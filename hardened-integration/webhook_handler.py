"""
Robust webhook signature verification and processing for Yuno webhooks.

Security controls:
1. HMAC-SHA256 signature verification (integrity + authenticity)
2. Timestamp validation (anti-replay, PCI-DSS Req 6.5.10)
3. Nonce/idempotency deduplication (complete replay protection)
4. Dual-key support (zero-downtime key rotation)
5. Generic error responses (prevent security-control enumeration)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional

from secrets_manager import SecretsManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WebhookEvent:
    """Parsed representation of a Yuno webhook event."""
    event_type: str
    payment_id: str
    status: str
    amount: str
    currency: str
    timestamp: str
    idempotency_key: str


class _NonceCache:
    """
    Thread-safe, bounded, in-memory nonce deduplication cache.

    Why nonce: timestamp alone allows replay within the tolerance window.
    Nonce + timestamp together provide complete replay protection.

    Why bounded: without a max size, sustained replay attacks within the TTL
    window could grow memory unboundedly. The max_size limit (default 100K)
    provides a hard cap; if exceeded, oldest entries are evicted first.

    Production note: replace with Redis SETNX + TTL for horizontal scalability.
    Cost: ~1KB/webhook, 50K webhooks/day = 50MB Redis — trivial.
    """

    def __init__(self, ttl_seconds: int = 600, max_size: int = 100_000) -> None:
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def is_duplicate(self, nonce: str) -> bool:
        now = time.time()
        with self._lock:
            # Lazy eviction of expired entries
            expired = [k for k, ts in self._seen.items() if now - ts > self._ttl]
            for k in expired:
                del self._seen[k]

            # Hard cap: if still over max_size, evict oldest entries
            if len(self._seen) >= self._max_size:
                sorted_keys = sorted(self._seen, key=self._seen.get)
                for k in sorted_keys[:len(self._seen) - self._max_size + 1]:
                    del self._seen[k]

            if nonce in self._seen:
                return True
            self._seen[nonce] = now
            return False


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    timestamp_header: str,
    secrets_manager: SecretsManager,
    tolerance_seconds: int = 300,
) -> bool:
    """
    Verify HMAC-SHA256 webhook signature with dual-key rotation support.

    The signed message format is: ``timestamp + "." + payload``

    Args:
        payload_bytes: Raw request body bytes.
        signature_header: The X-Yuno-Signature header value.
        timestamp_header: The X-Yuno-Timestamp header value (Unix epoch string).
        secrets_manager: Manager to retrieve webhook secrets.
        tolerance_seconds: Maximum acceptable age of the timestamp.

    Returns:
        True if signature is valid and timestamp within tolerance.
    """
    # --- Timestamp validation ---
    # Why: prevents replay attacks where an attacker captures a valid webhook
    # and re-sends it. 5-min window balances clock skew vs replay exposure.
    # Per PCI-DSS Req 6.5.10.
    try:
        ts = int(timestamp_header)
    except (ValueError, TypeError):
        logger.warning("WEBHOOK_VERIFY_FAIL reason=invalid_timestamp")
        return False

    age = abs(time.time() - ts)
    if age > tolerance_seconds:
        logger.warning("WEBHOOK_VERIFY_FAIL reason=timestamp_expired age=%.1f tolerance=%d",
                       age, tolerance_seconds)
        return False

    # Build signed message
    signed_message = f"{timestamp_header}.".encode() + payload_bytes

    # --- Dual-key verification for zero-downtime rotation ---
    # Why: during rotation, accept both old and new signatures. After merchant
    # confirms new key deployed, revoke old key.
    current_secret = secrets_manager.get_secret("WEBHOOK_SECRET", requester="webhook_verifier")
    previous_secret = secrets_manager.get_secret("WEBHOOK_SECRET_PREVIOUS", requester="webhook_verifier")

    for label, secret in [("current", current_secret), ("previous", previous_secret)]:
        if not secret:
            continue

        expected_sig = hmac.new(
            secret.encode(), signed_message, hashlib.sha256
        ).hexdigest()

        # Why hmac.compare_digest: constant-time comparison prevents timing
        # side-channel attacks where an attacker measures response-time differences
        # to determine the correct signature byte-by-byte.
        # Per OWASP Cryptographic Failures A02:2021.
        if hmac.compare_digest(expected_sig, signature_header):
            if label == "previous":
                logger.warning("WEBHOOK_VERIFY_OK key=previous -- sender should update to current secret")
            else:
                logger.info("WEBHOOK_VERIFY_OK key=current")
            return True

    logger.warning("WEBHOOK_VERIFY_FAIL reason=signature_mismatch")
    return False


def parse_webhook_event(payload: bytes) -> WebhookEvent:
    """Parse raw webhook payload into a structured WebhookEvent."""
    try:
        data: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("Malformed JSON payload") from exc

    return WebhookEvent(
        event_type=str(data.get("event_type", "")),
        payment_id=str(data.get("payment_id", "")),
        status=str(data.get("status", "")),
        amount=str(data.get("amount", "")),
        currency=str(data.get("currency", "")),
        timestamp=str(data.get("timestamp", "")),
        idempotency_key=str(data.get("idempotency_key", data.get("id", ""))),
    )


class WebhookProcessor:
    """
    Full webhook pipeline: verify -> deduplicate -> parse -> process -> ack.

    All error responses are intentionally generic ("invalid_webhook") to prevent
    attackers from enumerating which security control is failing.
    """

    def __init__(self, secrets_manager: SecretsManager, tolerance_seconds: int = 300,
                 on_event: Optional[Callable[[WebhookEvent], None]] = None) -> None:
        self._secrets_manager = secrets_manager
        self._tolerance = tolerance_seconds
        self._nonce_cache = _NonceCache(ttl_seconds=tolerance_seconds * 2)
        self._on_event = on_event or self._default_handler

    def process(self, payload_bytes: bytes, signature_header: str,
                timestamp_header: str) -> tuple[bool, Optional[WebhookEvent]]:
        """
        Run full verification and processing pipeline.

        Returns (success, event). On failure, event is None.
        Caller must return generic 400 for any failure.
        """
        # Step 1: Verify signature + timestamp
        if not verify_webhook_signature(
            payload_bytes, signature_header, timestamp_header,
            self._secrets_manager, self._tolerance,
        ):
            return False, None

        # Step 2: Parse
        try:
            event = parse_webhook_event(payload_bytes)
        except ValueError:
            logger.warning("WEBHOOK_PARSE_FAIL reason=malformed_payload")
            return False, None

        # Step 3: Deduplicate via nonce/idempotency key
        if not event.idempotency_key:
            logger.warning("WEBHOOK_DEDUP_FAIL reason=missing_idempotency_key")
            return False, None

        if self._nonce_cache.is_duplicate(event.idempotency_key):
            logger.info("WEBHOOK_DEDUP duplicate key=%s -- ack silently", event.idempotency_key)
            return True, event  # Ack to prevent sender retries

        # Step 4: Dispatch to business logic
        try:
            self._on_event(event)
        except Exception:
            logger.exception("WEBHOOK_HANDLER_ERROR event_type=%s", event.event_type)
            # Still ack to avoid infinite retries; push to dead-letter queue

        return True, event

    @staticmethod
    def _default_handler(event: WebhookEvent) -> None:
        logger.info("WEBHOOK_EVENT type=%s payment=%s status=%s",
                     event.event_type, event.payment_id, event.status)
