"""
Secrets management abstraction supporting multiple backends.

Why an abstraction layer:
- Development uses plain environment variables
- Staging/production uses a real secrets manager (AWS SM, Vault)
- Application code never knows or cares which backend is active

Why caching: calling AWS SM or Vault on every request adds ~50-200ms latency
and counts against API rate limits. TTL-based cache provides a configurable
performance-vs-freshness tradeoff.

Why TTL refresh: if a secret is rotated in the backend, the cache picks up
the new value within TTL seconds, limiting the exposure window without restart.

Why audit logging: PCI-DSS Req 10.2.1 requires logging all access to the
cardholder data environment. We record who accessed which secret and when,
but NEVER the secret value itself.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


class SecretsBackend(ABC):
    """Abstract interface for secrets storage backends."""

    @abstractmethod
    def get_secret(self, key: str) -> Optional[str]:
        ...

    @abstractmethod
    def rotate_secret(self, key: str) -> Optional[str]:
        ...

    @abstractmethod
    def list_secrets(self) -> list[str]:
        ...


class EnvironmentBackend(SecretsBackend):
    """
    Reads secrets from OS environment variables.
    Simplest backend for local development.
    """

    def get_secret(self, key: str) -> Optional[str]:
        return os.environ.get(key)

    def rotate_secret(self, key: str) -> Optional[str]:
        logger.warning(
            "EnvironmentBackend does not support rotation. "
            "Restart the process with updated env vars for key=%s", key
        )
        return self.get_secret(key)

    def list_secrets(self) -> list[str]:
        known = ["YUNO_API_KEY", "YUNO_API_SECRET", "WEBHOOK_SECRET", "WEBHOOK_SECRET_PREVIOUS"]
        return [k for k in known if k in os.environ]


class AWSSecretsManagerBackend(SecretsBackend):
    """
    Simulated AWS Secrets Manager backend with TTL-based caching.

    In production, use boto3's secretsmanager client. The cache avoids
    hitting the AWS API on every request (latency ~50ms, rate limit 10K req/s).
    """

    def __init__(self, cache_ttl_seconds: int = 300) -> None:
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()

    def get_secret(self, key: str) -> Optional[str]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.expired:
                return entry.value
        value = self._fetch_from_aws(key)
        if value is not None:
            with self._lock:
                self._cache[key] = _CacheEntry(value=value, expires_at=time.monotonic() + self._cache_ttl)
        return value

    def rotate_secret(self, key: str) -> Optional[str]:
        logger.info("[AWS-SM] Rotation requested for key=%s", key)
        with self._lock:
            self._cache.pop(key, None)
        return self._fetch_from_aws(key)

    def list_secrets(self) -> list[str]:
        return ["YUNO_API_KEY", "YUNO_API_SECRET", "WEBHOOK_SECRET"]

    @staticmethod
    def _fetch_from_aws(key: str) -> Optional[str]:
        logger.debug("[AWS-SM] Fetching key=%s from AWS Secrets Manager", key)
        return os.environ.get(key)


class VaultBackend(SecretsBackend):
    """
    Simulated HashiCorp Vault KV v2 backend.
    In production, use the hvac library with AppRole or Kubernetes auth.
    """

    def __init__(self, vault_addr: str = "https://vault.internal:8200") -> None:
        self._vault_addr = vault_addr

    def get_secret(self, key: str) -> Optional[str]:
        logger.debug("[VAULT] GET %s/v1/secret/data/%s", self._vault_addr, key)
        return os.environ.get(key)

    def rotate_secret(self, key: str) -> Optional[str]:
        logger.info("[VAULT] Rotation requested for key=%s", key)
        return self.get_secret(key)

    def list_secrets(self) -> list[str]:
        return ["YUNO_API_KEY", "YUNO_API_SECRET", "WEBHOOK_SECRET"]


@dataclass
class _CacheEntry:
    value: str
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self.expires_at


class SecretsManager:
    """
    Thread-safe facade wrapping a SecretsBackend with:
    - TTL-based caching with automatic refresh
    - Audit logging of every secret access (PCI-DSS Req 10.2.1)
    - Thread-safe access via reentrant lock
    """

    def __init__(self, backend: SecretsBackend, cache_ttl_seconds: int = 300,
                 service_name: str = "hardened-integration") -> None:
        self._backend = backend
        self._cache_ttl = cache_ttl_seconds
        self._service_name = service_name
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.RLock()

    def get_secret(self, key: str, requester: str = "system") -> Optional[str]:
        """Retrieve a secret with caching and audit logging."""
        access_id = uuid.uuid4().hex[:12]
        # Audit: record access but NEVER the secret value
        logger.info("SECRET_ACCESS audit_id=%s requester=%s key=%s service=%s",
                     access_id, requester, key, self._service_name)

        with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.expired:
                return entry.value

        value = self._backend.get_secret(key)
        if value is not None:
            with self._lock:
                self._cache[key] = _CacheEntry(value=value, expires_at=time.monotonic() + self._cache_ttl)
        else:
            logger.warning("Secret key=%s not found in backend", key)
        return value

    def rotate_secret(self, key: str, requester: str = "system") -> Optional[str]:
        logger.info("SECRET_ROTATE requester=%s key=%s", requester, key)
        with self._lock:
            self._cache.pop(key, None)
        return self._backend.rotate_secret(key)

    def invalidate_cache(self, key: Optional[str] = None) -> None:
        with self._lock:
            if key:
                self._cache.pop(key, None)
            else:
                self._cache.clear()

    def list_secrets(self) -> list[str]:
        return self._backend.list_secrets()
