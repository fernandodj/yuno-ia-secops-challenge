"""Shared test fixtures for security control tests."""

import json
import hashlib
import hmac
import os
import time
import pytest

# Ensure test secrets are set in environment before importing app modules
os.environ.setdefault("YUNO_API_KEY", "yuno_pk_test_abcdef1234567890abcdef1234567890")
os.environ.setdefault("YUNO_API_SECRET", "yuno_sk_test_1234567890abcdef1234567890abcdef")
os.environ.setdefault("WEBHOOK_SECRET", "whsec_test_current_secret_key_1234567890")
os.environ.setdefault("WEBHOOK_SECRET_PREVIOUS", "whsec_test_previous_secret_key_0987654321")

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secrets_manager import EnvironmentBackend, SecretsManager


@pytest.fixture
def webhook_secret() -> str:
    return "whsec_test_current_secret_key_1234567890"


@pytest.fixture
def webhook_secret_previous() -> str:
    return "whsec_test_previous_secret_key_0987654321"


@pytest.fixture
def mock_secrets_manager(webhook_secret, webhook_secret_previous) -> SecretsManager:
    """SecretsManager backed by environment variables with test secrets."""
    os.environ["WEBHOOK_SECRET"] = webhook_secret
    os.environ["WEBHOOK_SECRET_PREVIOUS"] = webhook_secret_previous
    return SecretsManager(
        backend=EnvironmentBackend(),
        cache_ttl_seconds=60,
        service_name="test",
    )


@pytest.fixture
def sample_webhook_payload() -> dict:
    return {
        "event_type": "payment.status_updated",
        "payment_id": "pay_abc123def456",
        "status": "approved",
        "amount": "49.99",
        "currency": "USD",
        "timestamp": "2024-01-15T12:00:00Z",
        "idempotency_key": "idem_unique_key_001",
    }


@pytest.fixture
def sample_payload_bytes(sample_webhook_payload) -> bytes:
    return json.dumps(sample_webhook_payload).encode()


@pytest.fixture
def valid_timestamp() -> str:
    return str(int(time.time()))


@pytest.fixture
def valid_signature(sample_payload_bytes, valid_timestamp, webhook_secret) -> str:
    """Generate a valid HMAC-SHA256 signature for the sample payload."""
    signed_message = f"{valid_timestamp}.".encode() + sample_payload_bytes
    return hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()


@pytest.fixture
def api_key() -> str:
    return "yuno_pk_test_abcdef1234567890abcdef1234567890"
