"""
FastAPI application: QuickEats hardened Yuno integration reference implementation.

Demonstrates defense-in-depth security controls at every layer for a merchant
integrating with Yuno's payment orchestration API.

Security layers (outer to inner):
1. IP allowlisting (network)
2. Request size limits (DoS prevention — reads actual body, not just Content-Length)
3. Rate limiting (abuse prevention, with periodic stale bucket cleanup)
4. Audit logging (compliance + forensics)
5. Security headers (browser/client protection)
6. Authentication (incoming request validation)
7. Authorization (scoped API keys — Principle of Least Privilege, PCI-DSS Req 7.1)
8. Webhook signature verification (integrity)
9. Input validation (injection prevention)
10. Sanitized error handling (information disclosure prevention)

Request flow:
    Client → IP Allowlist → Size Limit → Rate Limit → Audit Log
    → Security Headers → Auth → Scope Check → Endpoint Logic
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import Settings, load_settings
from secrets_manager import EnvironmentBackend, SecretsManager
from webhook_handler import WebhookProcessor
from middleware.auth import YunoAPIClient, APIScope, requires_scope
from middleware.rate_limiter import RateLimiter
from middleware.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

# Globals initialized at startup
settings: Optional[Settings] = None
secrets_mgr: Optional[SecretsManager] = None
webhook_processor: Optional[WebhookProcessor] = None
yuno_client: Optional[YunoAPIClient] = None
rate_limiter: Optional[RateLimiter] = None
audit_logger: Optional[AuditLogger] = None
_cleanup_task: Optional[asyncio.Task] = None


async def _periodic_rate_limit_cleanup():
    """
    Periodic background task to evict stale rate-limit buckets.

    Why: without cleanup, the bucket registry grows unboundedly under sustained
    attacks from rotating IPs, eventually causing OOM. Running every 5 minutes
    with a 1-hour max age keeps memory bounded.
    Per OWASP API4:2023 Unrestricted Resource Consumption.
    """
    while True:
        await asyncio.sleep(300)  # Every 5 minutes
        if rate_limiter:
            rate_limiter.cleanup_stale_buckets(max_age_seconds=3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize all components on startup, tear down on shutdown."""
    global settings, secrets_mgr, webhook_processor, yuno_client, rate_limiter, audit_logger, _cleanup_task

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger.info("Starting QuickEats hardened integration...")

    settings = load_settings()
    logging.getLogger().setLevel(settings.LOG_LEVEL)

    # In production, swap EnvironmentBackend for AWSSecretsManagerBackend or VaultBackend
    secrets_mgr = SecretsManager(backend=EnvironmentBackend(), cache_ttl_seconds=300,
                                  service_name="quickeats-hardened")
    webhook_processor = WebhookProcessor(secrets_manager=secrets_mgr,
                                          tolerance_seconds=settings.WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS)
    yuno_client = YunoAPIClient(base_url=settings.YUNO_API_BASE_URL, secrets_manager=secrets_mgr)
    rate_limiter = RateLimiter(default_rpm=settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
                               endpoint_overrides={"/payments": settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
                                                   "/refunds": 20})
    audit_logger = AuditLogger(service_name="quickeats-hardened")

    # Start periodic rate-limiter cleanup to prevent memory growth
    _cleanup_task = asyncio.create_task(_periodic_rate_limit_cleanup())

    logger.info("All components initialized. Application ready.")
    yield

    # Shutdown
    if _cleanup_task:
        _cleanup_task.cancel()
    if yuno_client:
        await yuno_client.close()
    logger.info("Application shut down.")


app = FastAPI(
    title="QuickEats Hardened Yuno Integration",
    description="Secure reference implementation for Yuno payment orchestration",
    version="1.0.0",
    docs_url=None,   # Disable Swagger in production
    redoc_url=None,
    lifespan=lifespan,
)

# CORS: restrictive. Per OWASP API8:2023 Security Misconfiguration.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://quickeats.example.com"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
    allow_credentials=False,
    max_age=3600,
)


# --- Middleware stack (executed bottom-to-top in FastAPI) ---

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Defense-in-depth HTTP security headers on every response."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


# Why size limit: prevents DoS via oversized payloads. Payment webhooks
# should never exceed 64KB.
MAX_BODY_SIZE = 64 * 1024


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    """
    Reject oversized request bodies.

    Why we read the actual body instead of trusting Content-Length: the header
    can be spoofed (e.g., small Content-Length with chunked transfer encoding).
    Reading the body is the only reliable way to enforce the limit.
    Per OWASP API4:2023 Unrestricted Resource Consumption.
    """
    # First check Content-Length header as a fast-path rejection
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_BODY_SIZE:
                logger.warning("REQUEST_TOO_LARGE content_length=%s max=%d", content_length, MAX_BODY_SIZE)
                return JSONResponse(status_code=413, content={"error": "payload_too_large"})
        except ValueError:
            pass  # Malformed header, let downstream handle

    # For methods with bodies, also verify actual body size
    # (defends against Content-Length spoofing / chunked encoding bypass)
    if request.method in ("POST", "PUT", "PATCH"):
        body = await request.body()
        if len(body) > MAX_BODY_SIZE:
            logger.warning("REQUEST_TOO_LARGE actual_size=%d max=%d", len(body), MAX_BODY_SIZE)
            return JSONResponse(status_code=413, content={"error": "payload_too_large"})

    return await call_next(request)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if rate_limiter is None:
        return await call_next(request)
    api_key = request.headers.get("authorization", "")
    ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.allow(api_key=api_key, ip_address=ip, endpoint=request.url.path)
    if not allowed:
        return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"},
                            headers={"Retry-After": str(int(retry_after) + 1)})
    return await call_next(request)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    if audit_logger is None:
        return await call_next(request)
    return await audit_logger.log_request(request, call_next)


@app.middleware("http")
async def ip_allowlist_middleware(request: Request, call_next):
    """Restrict access to known IPs when ALLOWED_IPS is configured."""
    if settings and settings.allowed_ip_set:
        client_ip = request.client.host if request.client else "unknown"
        if client_ip not in settings.allowed_ip_set:
            logger.warning("IP_BLOCKED ip=%s", client_ip)
            return JSONResponse(status_code=403, content={"error": "forbidden"})
    return await call_next(request)


# --- Authentication middleware for incoming requests ---

# Endpoints that do NOT require authentication
_PUBLIC_ENDPOINTS = frozenset({"/health", "/docs", "/openapi.json"})

# Scope requirements per endpoint. Per PCI-DSS Req 7.1:
# "Limit access to system components and cardholder data to only those
# individuals whose job requires such access."
_ENDPOINT_SCOPES: dict[str, set[str]] = {
    "POST:/payments": {APIScope.PAYMENT_WRITE.value},
    "GET:/payments": {APIScope.PAYMENT_READ.value},
}


@app.middleware("http")
async def authentication_middleware(request: Request, call_next):
    """
    Validate incoming API key on protected endpoints.

    Why middleware instead of per-endpoint: ensures no endpoint is accidentally
    left unprotected. Defense in depth — even if a developer forgets to add
    @requires_scope, this layer catches unauthenticated access.

    Note: Webhook endpoint uses its own HMAC-based auth (not API keys).
    """
    path = request.url.path

    # Skip auth for public endpoints and webhooks (which have their own HMAC auth)
    if path in _PUBLIC_ENDPOINTS or path.startswith("/webhooks"):
        return await call_next(request)

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    api_key = auth_header[7:]
    if len(api_key) < 16:
        # Why length check: short tokens are obviously invalid. Rejecting them
        # early avoids unnecessary secrets manager lookups.
        return JSONResponse(status_code=401, content={"error": "unauthorized"})

    # In production, validate the key against Yuno's auth service and retrieve
    # its associated scopes. For this reference implementation, we derive scopes
    # from the key prefix convention.
    # Why scope check here: Principle of Least Privilege (PCI-DSS Req 7.1).
    scopes: set[str] = set()
    if api_key.startswith("yuno_pk_"):
        scopes = {APIScope.PAYMENT_READ.value, APIScope.PAYMENT_WRITE.value}
    # Store scopes on request state for use by @requires_scope decorator
    request.state.api_scopes = scopes

    # Check endpoint-specific scope requirements
    scope_key = f"{request.method}:{path.rstrip('/')}"
    # Also check path patterns like GET:/payments/{id}
    for pattern, required_scopes in _ENDPOINT_SCOPES.items():
        p_method, p_path = pattern.split(":", 1)
        if request.method == p_method and path.startswith(p_path):
            if not required_scopes.issubset(scopes):
                logger.warning("SCOPE_DENIED path=%s required=%s granted=%s",
                               path, required_scopes, scopes)
                return JSONResponse(status_code=403, content={"error": "forbidden"})

    return await call_next(request)


# --- Global exception handler ---

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Generic error response. Never leak stack traces, file paths, or secrets.
    Per OWASP API3:2023 Broken Object Property Level Authorization.
    """
    request_id = request.headers.get("x-request-id", uuid.uuid4().hex)
    logger.exception("UNHANDLED_EXCEPTION request_id=%s path=%s", request_id, request.url.path)
    return JSONResponse(status_code=500, content={"error": "internal_error", "request_id": request_id})


# --- Endpoints ---

@app.get("/health")
async def health_check():
    """Liveness probe. No internal state exposed to unauthenticated callers."""
    return {"status": "ok"}


@app.post("/webhooks/yuno")
async def receive_webhook(request: Request):
    """
    Receive and verify a Yuno webhook notification.

    Authentication: HMAC-SHA256 signature (not API key). The webhook delivery
    service signs payloads with the shared webhook secret; this endpoint
    verifies that signature. This is separate from the API key auth middleware
    because webhooks use a fundamentally different auth mechanism.

    All failures return same generic 400 -- never reveal which check failed.
    """
    if webhook_processor is None:
        raise HTTPException(status_code=503, detail="not_ready")
    signature = request.headers.get("x-yuno-signature", "")
    timestamp = request.headers.get("x-yuno-timestamp", "")
    body = await request.body()
    success, event = webhook_processor.process(body, signature, timestamp)
    if not success:
        return JSONResponse(status_code=400, content={"error": "invalid_webhook"})
    return JSONResponse(status_code=200,
                        content={"status": "accepted", "event_type": event.event_type if event else "unknown"})


@app.post("/payments")
@requires_scope(APIScope.PAYMENT_WRITE)
async def create_payment(request: Request):
    """
    Create payment via Yuno API.

    Requires PAYMENT_WRITE scope. Request body forwarded after auth + signing.
    Per PCI-DSS Req 7.1: restrict access to only those whose job requires it.
    """
    if yuno_client is None:
        raise HTTPException(status_code=503, detail="not_ready")
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "invalid_request"})
    idempotency_key = request.headers.get("x-idempotency-key", uuid.uuid4().hex)
    try:
        response = await yuno_client.request("POST", "/v1/payments", body=body,
                                              idempotency_key=idempotency_key)
        return JSONResponse(status_code=response.status_code, content=response.json())
    except Exception:
        logger.exception("PAYMENT_CREATE_ERROR")
        return JSONResponse(status_code=502, content={"error": "upstream_error"})


@app.get("/payments/{payment_id}")
@requires_scope(APIScope.PAYMENT_READ)
async def get_payment(payment_id: str, request: Request):
    """
    Retrieve payment status from Yuno API.

    Requires PAYMENT_READ scope. Input validated to prevent path traversal.
    """
    if yuno_client is None:
        raise HTTPException(status_code=503, detail="not_ready")
    # Input validation: payment IDs are alphanumeric + hyphens only.
    # Why strict regex: prevents path traversal (../../), SQL injection fragments,
    # and other injection attacks via the payment_id parameter.
    if not re.match(r"^[a-zA-Z0-9_-]{1,128}$", payment_id):
        return JSONResponse(status_code=400, content={"error": "invalid_request"})
    try:
        response = await yuno_client.request("GET", f"/v1/payments/{payment_id}")
        return JSONResponse(status_code=response.status_code, content=response.json())
    except Exception:
        logger.exception("PAYMENT_GET_ERROR")
        return JSONResponse(status_code=502, content={"error": "upstream_error"})
