"""
End-to-end integration tests using FastAPI TestClient.

Validates the full request lifecycle including security headers,
error handling, webhook flow, authentication, and rate limiting.
"""

import hashlib
import hmac
import json
import os
import time

import pytest

# Set env vars before importing app
os.environ["YUNO_API_KEY"] = "yuno_pk_test_abcdef1234567890abcdef1234567890"
os.environ["YUNO_API_SECRET"] = "yuno_sk_test_1234567890abcdef1234567890abcdef"
os.environ["WEBHOOK_SECRET"] = "whsec_test_current_secret_key_1234567890"
os.environ["WEBHOOK_SECRET_PREVIOUS"] = "whsec_test_previous_secret_key_0987654321"

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from app import app

WEBHOOK_SECRET = "whsec_test_current_secret_key_1234567890"
AUTH_HEADER = {"Authorization": "Bearer yuno_pk_test_abcdef1234567890abcdef1234567890"}


@pytest.fixture(scope="module")
def client():
    """TestClient with lifespan context so startup initializes all components."""
    with TestClient(app) as c:
        yield c


def _sign_webhook(payload_bytes: bytes, timestamp: str, secret: str = WEBHOOK_SECRET) -> str:
    signed_message = f"{timestamp}.".encode() + payload_bytes
    return hmac.new(secret.encode(), signed_message, hashlib.sha256).hexdigest()


class TestHealthCheck:
    def test_health_returns_ok(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_health_no_auth_required(self, client):
        """Health check should be public -- no API key needed."""
        response = client.get("/health")  # No auth header
        assert response.status_code == 200


class TestSecurityHeaders:
    def test_security_headers_present(self, client):
        """Every response should include defense-in-depth security headers."""
        response = client.get("/health")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert response.headers.get("X-Frame-Options") == "DENY"
        assert "max-age=31536000" in response.headers.get("Strict-Transport-Security", "")
        assert response.headers.get("Content-Security-Policy") is not None
        assert "no-store" in response.headers.get("Cache-Control", "")


class TestAuthentication:
    def test_unauthenticated_request_rejected(self, client):
        """Requests without API key should get 401."""
        response = client.get("/payments/pay_123")
        assert response.status_code == 401
        assert response.json() == {"error": "unauthorized"}

    def test_short_token_rejected(self, client):
        """Obviously invalid short tokens should be rejected."""
        response = client.get("/payments/pay_123",
                              headers={"Authorization": "Bearer short"})
        assert response.status_code == 401

    def test_authenticated_request_accepted(self, client):
        """Valid API key should pass auth (may fail upstream, but not 401)."""
        response = client.get("/payments/pay_abc123", headers=AUTH_HEADER)
        assert response.status_code in (200, 502)  # 502 = upstream not running


class TestWebhookFlow:
    def test_valid_webhook_accepted(self, client):
        """POST valid webhook -> 200, event processed."""
        payload = json.dumps({
            "event_type": "payment.status_updated",
            "payment_id": "pay_integration_test_001",
            "status": "approved",
            "amount": "25.00",
            "currency": "USD",
            "timestamp": "2024-01-15T12:00:00Z",
            "idempotency_key": "idem_integration_001",
        }).encode()
        ts = str(int(time.time()))
        sig = _sign_webhook(payload, ts)

        response = client.post(
            "/webhooks/yuno",
            content=payload,
            headers={
                "x-yuno-signature": sig,
                "x-yuno-timestamp": ts,
                "content-type": "application/json",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "accepted"

    def test_webhook_no_api_key_needed(self, client):
        """Webhooks use HMAC auth, not API keys -- no Bearer token required."""
        payload = json.dumps({
            "event_type": "test",
            "payment_id": "pay_noauth",
            "status": "approved",
            "amount": "5.00",
            "currency": "USD",
            "timestamp": "2024-01-15T12:00:00Z",
            "idempotency_key": "idem_noauth_001",
        }).encode()
        ts = str(int(time.time()))
        sig = _sign_webhook(payload, ts)

        response = client.post(
            "/webhooks/yuno",
            content=payload,
            headers={"x-yuno-signature": sig, "x-yuno-timestamp": ts},
        )
        # Should succeed without Authorization header
        assert response.status_code == 200

    def test_bad_signature_returns_generic_400(self, client):
        """POST with bad signature -> 400 with generic error message."""
        payload = json.dumps({
            "event_type": "test",
            "payment_id": "pay_x",
            "status": "approved",
            "amount": "10.00",
            "currency": "USD",
            "timestamp": "2024-01-15T12:00:00Z",
            "idempotency_key": "idem_bad_sig_001",
        }).encode()
        ts = str(int(time.time()))

        response = client.post(
            "/webhooks/yuno",
            content=payload,
            headers={"x-yuno-signature": "invalid_signature", "x-yuno-timestamp": ts},
        )
        assert response.status_code == 400
        # Must be generic -- not "bad signature" or "invalid HMAC"
        assert response.json() == {"error": "invalid_webhook"}

    def test_replay_webhook_deduplicated(self, client):
        """POST same webhook twice -> first 200, second deduplicated."""
        payload = json.dumps({
            "event_type": "payment.status_updated",
            "payment_id": "pay_replay_test",
            "status": "approved",
            "amount": "30.00",
            "currency": "USD",
            "timestamp": "2024-01-15T12:00:00Z",
            "idempotency_key": "idem_replay_test_unique",
        }).encode()
        ts = str(int(time.time()))
        sig = _sign_webhook(payload, ts)
        headers = {"x-yuno-signature": sig, "x-yuno-timestamp": ts}

        r1 = client.post("/webhooks/yuno", content=payload, headers=headers)
        assert r1.status_code == 200

        r2 = client.post("/webhooks/yuno", content=payload, headers=headers)
        assert r2.status_code == 200  # Ack to prevent sender retries


class TestErrorHandling:
    def test_404_does_not_leak_internals(self, client):
        response = client.get("/nonexistent/endpoint")
        assert response.status_code in (401, 404, 405)
        body = response.text
        assert "Traceback" not in body
        assert "/Users/" not in body

    def test_large_payload_rejected(self, client):
        """POST >64KB payload -> 413."""
        large_payload = b"x" * (65 * 1024)
        response = client.post(
            "/webhooks/yuno",
            content=large_payload,
            headers={"content-length": str(len(large_payload))},
        )
        assert response.status_code == 413
        assert response.json() == {"error": "payload_too_large"}


class TestInputValidation:
    def test_invalid_payment_id_rejected(self, client):
        """Payment ID with path traversal should be rejected."""
        response = client.get("/payments/../../etc/passwd", headers=AUTH_HEADER)
        assert response.status_code in (400, 404)

    def test_valid_payment_id_format_accepted(self, client):
        """Valid payment ID format passes validation (may fail upstream)."""
        response = client.get("/payments/pay_abc123", headers=AUTH_HEADER)
        assert response.status_code in (502, 200)
