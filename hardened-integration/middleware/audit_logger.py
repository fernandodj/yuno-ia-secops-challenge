"""
Structured audit logging middleware with PAN/credential sanitization.

Why sanitized logging: PCI-DSS Req 3.4 prohibits storing full PAN. Even in logs,
card data must be rendered unreadable. We mask to BIN (first 6) + last 4 for
troubleshooting while maintaining compliance.

What we NEVER log:
- Request/response bodies for payment endpoints (may contain card data)
- Full API keys or webhook secrets
- CVV/CVC values

Production note: logs should be shipped to SIEM (Datadog, Splunk) with retention
per PCI-DSS Req 10.7 (min 1 year, 3 months immediately accessible).
"""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

logger = logging.getLogger(__name__)

# --- Sanitization patterns ---

# Visa, MC, Amex, Discover patterns (13-19 digits)
_PAN_PATTERN = re.compile(r"\b([3-6]\d{5})\d{3,9}(\d{4})\b")

# CVV/CVC: 3-4 digit values near card-related field names
_CVV_PATTERN = re.compile(
    r'("(?:cvv|cvc|security_code|cvv2|cvc2)")\s*:\s*"?\d{3,4}"?',
    re.IGNORECASE,
)

# Long alphanumeric strings (API keys, tokens)
_API_KEY_PATTERN = re.compile(r"\b([A-Za-z0-9_-]{8})[A-Za-z0-9_-]{24,}\b")

# Email partial masking
_EMAIL_PATTERN = re.compile(
    r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)


def sanitize_pan(text: str) -> str:
    """Mask card numbers: BIN (first 6) + last 4. PCI-DSS Req 3.4."""
    return _PAN_PATTERN.sub(r"\1******\2", text)


def sanitize_cvv(text: str) -> str:
    """Replace CVV/CVC values entirely with '***'."""
    return _CVV_PATTERN.sub(r'\1: "***"', text)


def sanitize_api_key(text: str) -> str:
    """Show only first 8 chars of credential-like strings."""
    return _API_KEY_PATTERN.sub(r"\1...[REDACTED]", text)


def sanitize_email(text: str) -> str:
    """Partially mask email addresses."""
    return _EMAIL_PATTERN.sub(r"\1***@\2", text)


def sanitize(text: str) -> str:
    """Apply all sanitization rules."""
    text = sanitize_pan(text)
    text = sanitize_cvv(text)
    text = sanitize_api_key(text)
    text = sanitize_email(text)
    return text


@dataclass
class AuditLogEntry:
    """Structured audit log record for SIEM ingestion."""
    timestamp: str
    request_id: str
    merchant_id: str
    endpoint: str
    method: str
    source_ip: str
    user_agent: str
    response_status: int
    response_time_ms: float
    api_key_prefix: str = ""
    error: str = ""

    def to_json(self) -> str:
        raw = json.dumps(asdict(self), default=str)
        return sanitize(raw)


# Endpoints whose bodies must NEVER be logged
_SENSITIVE_ENDPOINTS = frozenset({
    "/payments", "/v1/payments", "/checkout/sessions",
    "/v1/checkout/sessions", "/refunds", "/v1/refunds",
})


class AuditLogger:
    """Middleware-compatible audit logger with structured JSON output."""

    def __init__(self, service_name: str = "hardened-integration") -> None:
        self._service_name = service_name

    async def log_request(self, request: Any, call_next: Any) -> Any:
        request_id = request.headers.get("x-request-id", uuid.uuid4().hex)
        start = time.monotonic()

        api_key = request.headers.get("authorization", "")
        api_key_prefix = ""
        if api_key.startswith("Bearer "):
            token = api_key[7:]
            api_key_prefix = token[:8] + "..." if len(token) > 8 else "***"

        merchant_id = request.headers.get("x-merchant-id", api_key_prefix)

        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000

        entry = AuditLogEntry(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            request_id=request_id,
            merchant_id=merchant_id,
            endpoint=str(request.url.path),
            method=request.method,
            source_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", ""),
            response_status=response.status_code,
            response_time_ms=round(elapsed_ms, 2),
            api_key_prefix=api_key_prefix,
        )

        log_line = entry.to_json()
        if response.status_code >= 500:
            logger.error(log_line)
        elif response.status_code >= 400:
            logger.warning(log_line)
        else:
            logger.info(log_line)

        response.headers["X-Request-Id"] = request_id
        return response

    @staticmethod
    def is_sensitive_endpoint(path: str) -> bool:
        return any(path.rstrip("/").endswith(ep) or ep in path for ep in _SENSITIVE_ENDPOINTS)
