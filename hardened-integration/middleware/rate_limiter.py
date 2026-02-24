"""
Rate limiting middleware using the token bucket algorithm.

Why token bucket: allows bursts while maintaining average rate. Better for payment
APIs where merchants may batch-submit. Alternative sliding-window is simpler but
doesn't handle bursts. Leaky bucket smooths output but blocks legitimate spikes
(e.g., QuickEats lunch rush).

Rate limiting applied at three levels:
1. Per API key (per-merchant fairness)
2. Per IP address (defense against key sharing/credential stuffing)
3. Per endpoint (sensitive endpoints like /refunds get lower limits)

References:
- OWASP API4:2023 Unrestricted Resource Consumption
- PCI-DSS Req 6.5.10: Broken authentication and session management
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class _TokenBucket:
    """Thread-safe token bucket rate limiter."""
    capacity: float
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def consume(self, n: float = 1.0) -> bool:
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

    @property
    def retry_after_seconds(self) -> float:
        with self.lock:
            if self.tokens >= 1.0:
                return 0.0
            deficit = 1.0 - self.tokens
            return deficit / self.refill_rate if self.refill_rate > 0 else 60.0


class RateLimiter:
    """Multi-dimensional rate limiter: per-key, per-IP, per-endpoint."""

    def __init__(self, default_rpm: int = 100,
                 endpoint_overrides: Optional[dict[str, int]] = None) -> None:
        self._default_rpm = default_rpm
        self._endpoint_overrides = endpoint_overrides or {}
        self._buckets: dict[str, _TokenBucket] = {}
        self._registry_lock = threading.Lock()

    def allow(self, api_key: Optional[str] = None, ip_address: Optional[str] = None,
              endpoint: Optional[str] = None) -> tuple[bool, float]:
        """
        Check whether the request should be allowed.
        Returns (allowed, retry_after_seconds).
        """
        identifiers = []
        if api_key:
            identifiers.append(f"key:{api_key[:16]}")
        if ip_address:
            identifiers.append(f"ip:{ip_address}")
        if endpoint:
            identifiers.append(f"ep:{endpoint}")
            if api_key:
                identifiers.append(f"key:{api_key[:16]}:ep:{endpoint}")

        for ident in identifiers:
            bucket = self._get_or_create_bucket(ident, endpoint)
            if not bucket.consume():
                retry_after = bucket.retry_after_seconds
                logger.warning("RATE_LIMITED identifier=%s retry_after=%.1f", ident, retry_after)
                return False, retry_after

        return True, 0.0

    def _get_or_create_bucket(self, identifier: str, endpoint: Optional[str]) -> _TokenBucket:
        if identifier in self._buckets:
            return self._buckets[identifier]
        with self._registry_lock:
            if identifier in self._buckets:
                return self._buckets[identifier]
            rpm = self._default_rpm
            if endpoint and endpoint in self._endpoint_overrides:
                rpm = self._endpoint_overrides[endpoint]
            bucket = _TokenBucket(capacity=float(rpm), refill_rate=rpm / 60.0)
            self._buckets[identifier] = bucket
            return bucket

    def cleanup_stale_buckets(self, max_age_seconds: float = 3600.0) -> int:
        now = time.monotonic()
        removed = 0
        with self._registry_lock:
            stale = [k for k, b in self._buckets.items() if (now - b.last_refill) > max_age_seconds]
            for k in stale:
                del self._buckets[k]
                removed += 1
        if removed:
            logger.info("RATE_LIMITER_CLEANUP removed=%d buckets", removed)
        return removed
