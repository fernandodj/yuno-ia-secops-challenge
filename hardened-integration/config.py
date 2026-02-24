"""
Configuration management for QuickEats hardened Yuno integration.

Why env vars instead of config files: env vars are not committed to VCS,
are process-scoped, and can be injected by secrets managers (Vault, AWS SM)
at runtime without code changes. Per OWASP API8:2023 Security Misconfiguration.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Settings:
    """
    Application settings loaded exclusively from environment variables.

    All secrets are sourced from the environment so they are never hardcoded
    in source files, never committed to version control, and can be rotated
    by infrastructure tooling without redeploying application code.
    """

    YUNO_API_KEY: str = ""
    YUNO_API_SECRET: str = ""
    WEBHOOK_SECRET: str = ""
    # Why WEBHOOK_SECRET_PREVIOUS: enables zero-downtime key rotation.
    # During the transition window both current and previous secrets are accepted.
    WEBHOOK_SECRET_PREVIOUS: str = ""
    # Why 300s: 5-minute window balances clock skew tolerance vs replay-attack
    # exposure. Per PCI-DSS Req 6.5.10.
    WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS: int = 300
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 100
    # Comma-separated IP allowlist; empty = allow all
    ALLOWED_IPS: str = ""
    LOG_LEVEL: str = "INFO"
    YUNO_API_BASE_URL: str = "https://api.yuno.co"

    @property
    def allowed_ip_set(self) -> set[str]:
        if not self.ALLOWED_IPS:
            return set()
        return {ip.strip() for ip in self.ALLOWED_IPS.split(",") if ip.strip()}


def load_settings() -> Settings:
    """
    Load settings from environment variables ONLY.

    Fails fast when required secrets are missing so the application never
    starts in an insecure state. Actual secret values are NEVER logged.
    """
    settings = Settings(
        YUNO_API_KEY=os.environ.get("YUNO_API_KEY", ""),
        YUNO_API_SECRET=os.environ.get("YUNO_API_SECRET", ""),
        WEBHOOK_SECRET=os.environ.get("WEBHOOK_SECRET", ""),
        WEBHOOK_SECRET_PREVIOUS=os.environ.get("WEBHOOK_SECRET_PREVIOUS", ""),
        WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS=int(
            os.environ.get("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS", "300")
        ),
        RATE_LIMIT_REQUESTS_PER_MINUTE=int(
            os.environ.get("RATE_LIMIT_REQUESTS_PER_MINUTE", "100")
        ),
        ALLOWED_IPS=os.environ.get("ALLOWED_IPS", ""),
        LOG_LEVEL=os.environ.get("LOG_LEVEL", "INFO"),
        YUNO_API_BASE_URL=os.environ.get("YUNO_API_BASE_URL", "https://api.yuno.co"),
    )

    # Fail-fast validation: check presence but NEVER log the actual value
    missing: list[str] = []
    if not settings.YUNO_API_KEY:
        missing.append("YUNO_API_KEY")
    if not settings.YUNO_API_SECRET:
        missing.append("YUNO_API_SECRET")
    if not settings.WEBHOOK_SECRET:
        missing.append("WEBHOOK_SECRET")

    if missing:
        # Why fail fast: running without credentials would silently disable
        # authentication, creating a false sense of security.
        msg = (
            f"Missing required environment variables: {', '.join(missing)}. "
            "Set them via your secrets manager or .env file (never commit .env)."
        )
        logger.critical(msg)
        raise SystemExit(msg)

    logger.info(
        "Settings loaded. API key prefix: %s..., webhook secret: [SET]",
        settings.YUNO_API_KEY[:8] if len(settings.YUNO_API_KEY) >= 8 else "***",
    )
    return settings
