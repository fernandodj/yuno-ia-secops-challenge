"""
API authentication middleware for outgoing requests to Yuno.

Security controls:
- Credentials from SecretsManager (never stored as long-lived attributes)
- Request signing via HMAC (integrity + authenticity)
- TLS verification (MITM prevention)
- Scoped API keys (Principle of Least Privilege, PCI-DSS Req 7.1)
- Safe retry logic (no retries on auth failures)

References:
- OWASP API2:2023 Broken Authentication
- PCI-DSS Req 7.1: Limit access to system components
- PCI-DSS Req 8.3: Secure authentication mechanisms
"""

from __future__ import annotations

import asyncio
import enum
import functools
import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from typing import Any, Callable, Optional

import httpx

from secrets_manager import SecretsManager

logger = logging.getLogger(__name__)


class APIScope(enum.Enum):
    """
    Granular permission scopes for Yuno API keys.

    Why scoped keys: Principle of Least Privilege (PCI-DSS Req 7.1).
    A read-only analytics integration should not be able to initiate refunds.
    If a scoped key leaks, blast radius is limited to its permissions.
    """
    PAYMENT_READ = "payment:read"
    PAYMENT_WRITE = "payment:write"
    REFUND_READ = "refund:read"
    REFUND_WRITE = "refund:write"
    MERCHANT_CONFIG_READ = "merchant_config:read"
    TRANSACTION_EXPORT = "transaction:export"


def requires_scope(*scopes: APIScope) -> Callable:
    """
    Decorator that validates the API key has required scope(s).

    Usage::
        @requires_scope(APIScope.PAYMENT_WRITE)
        async def create_payment(request): ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request = kwargs.get("request") or (args[0] if args else None)
            if request is None:
                raise PermissionError("No request context for scope check")
            granted: set[str] = getattr(request.state, "api_scopes", set())
            required = {s.value for s in scopes}
            if not required.issubset(granted):
                missing = required - granted
                logger.warning("SCOPE_DENIED endpoint=%s missing=%s",
                               getattr(request, "url", "unknown"), missing)
                raise PermissionError("Insufficient permissions")
            return await func(*args, **kwargs)
        return wrapper
    return decorator


class YunoAPIClient:
    """
    HTTP client for authenticated communication with the Yuno API.

    Security:
    - Credentials fetched just-in-time from SecretsManager
    - TLS certificate verification always enabled
    - Requests signed with HMAC-SHA256
    - Auth failures (401/403) fail immediately, no retries
    - Error responses sanitized before logging
    """

    def __init__(self, base_url: str, secrets_manager: SecretsManager,
                 timeout_seconds: float = 30.0, max_retries: int = 3) -> None:
        self._base_url = base_url.rstrip("/")
        self._secrets = secrets_manager
        self._max_retries = max_retries
        # Why verify=True: ensures TLS certificates are validated, preventing MITM.
        # In production, consider certificate pinning for the Yuno API domain to
        # guard against compromised CAs.
        self._client = httpx.AsyncClient(
            verify=True,
            timeout=httpx.Timeout(timeout_seconds),
        )

    async def request(self, method: str, path: str,
                      body: Optional[dict[str, Any]] = None,
                      idempotency_key: Optional[str] = None) -> httpx.Response:
        """Send a signed, authenticated request to the Yuno API."""
        url = f"{self._base_url}{path}"
        request_id = uuid.uuid4().hex

        # Fetch credentials just-in-time -- never cache on self
        api_key = self._secrets.get_secret("YUNO_API_KEY", requester=f"api_client:{request_id}")
        api_secret = self._secrets.get_secret("YUNO_API_SECRET", requester=f"api_client:{request_id}")
        if not api_key or not api_secret:
            raise RuntimeError("API credentials unavailable from secrets manager")

        timestamp = str(int(time.time()))
        body_bytes = b""
        if body is not None:
            body_bytes = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()

        # Request signing: method + path + timestamp + SHA-256(body)
        body_hash = hashlib.sha256(body_bytes).hexdigest()
        sign_payload = f"{method.upper()}\n{path}\n{timestamp}\n{body_hash}"
        signature = hmac.new(api_secret.encode(), sign_payload.encode(), hashlib.sha256).hexdigest()

        headers: dict[str, str] = {
            # Why header not query param: query params appear in server logs,
            # browser history, and proxy logs. Per OWASP API2:2023.
            "Authorization": f"Bearer {api_key}",
            "X-Timestamp": timestamp,
            "X-Signature": signature,
            "X-Request-Id": request_id,
            "Content-Type": "application/json",
        }
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                response = await self._client.request(
                    method=method.upper(), url=url,
                    content=body_bytes if body_bytes else None, headers=headers,
                )
                # Do NOT retry auth failures -- fail immediately
                if response.status_code in (401, 403):
                    logger.error("AUTH_FAILURE status=%d request_id=%s path=%s",
                                 response.status_code, request_id, path)
                    response.raise_for_status()

                if response.status_code >= 500:
                    logger.warning("SERVER_ERROR status=%d attempt=%d/%d",
                                   response.status_code, attempt, self._max_retries)
                    if attempt < self._max_retries:
                        await asyncio.sleep(2 ** (attempt - 1))
                        continue
                    response.raise_for_status()

                return response
            except httpx.TransportError as exc:
                last_exc = exc
                logger.warning("TRANSPORT_ERROR attempt=%d/%d error=%s",
                               attempt, self._max_retries, self._sanitize_error(str(exc)))
                if attempt < self._max_retries:
                    await asyncio.sleep(2 ** (attempt - 1))
                    continue

        raise RuntimeError(f"Request failed after {self._max_retries} attempts: "
                           f"{self._sanitize_error(str(last_exc))}")

    @staticmethod
    def _sanitize_error(msg: str) -> str:
        """Strip potential credentials echoed in error messages."""
        sanitized = re.sub(r"Bearer\s+\S+", "Bearer [REDACTED]", msg, flags=re.IGNORECASE)
        sanitized = re.sub(r"[A-Za-z0-9+/=_-]{32,}", "[REDACTED]", sanitized)
        return sanitized

    async def close(self) -> None:
        await self._client.aclose()
