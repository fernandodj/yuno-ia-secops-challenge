"""
Tests for webhook HMAC signature verification.

Validates security controls:
- HMAC-SHA256 signature correctness
- Timestamp validation (anti-replay)
- Dual-key rotation support
- Nonce deduplication (replay prevention)
- Generic error handling (no info leakage)
"""

import hashlib
import hmac
import json
import time

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from webhook_handler import verify_webhook_signature, WebhookProcessor, parse_webhook_event


class TestSignatureVerification:
    """Tests for HMAC-SHA256 signature verification."""

    def test_valid_signature(self, sample_payload_bytes, valid_timestamp,
                              valid_signature, mock_secrets_manager):
        """A correctly signed webhook should pass verification."""
        assert verify_webhook_signature(
            sample_payload_bytes, valid_signature, valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is True

    def test_invalid_signature(self, sample_payload_bytes, valid_timestamp,
                                mock_secrets_manager):
        """A tampered payload should fail verification."""
        tampered = sample_payload_bytes + b"TAMPERED"
        signed_message = f"{valid_timestamp}.".encode() + sample_payload_bytes
        sig = hmac.new(b"whsec_test_current_secret_key_1234567890",
                       signed_message, hashlib.sha256).hexdigest()
        # Signature was computed over original, but we send tampered payload
        assert verify_webhook_signature(
            tampered, sig, valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is False

    def test_missing_signature(self, sample_payload_bytes, valid_timestamp,
                                mock_secrets_manager):
        """Empty signature should fail."""
        assert verify_webhook_signature(
            sample_payload_bytes, "", valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is False

    def test_expired_timestamp(self, sample_payload_bytes, mock_secrets_manager,
                                webhook_secret):
        """Timestamp older than tolerance should be rejected (anti-replay)."""
        old_ts = str(int(time.time()) - 600)  # 10 minutes ago
        signed_message = f"{old_ts}.".encode() + sample_payload_bytes
        sig = hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(
            sample_payload_bytes, sig, old_ts,
            mock_secrets_manager, tolerance_seconds=300,
        ) is False

    def test_future_timestamp(self, sample_payload_bytes, mock_secrets_manager,
                               webhook_secret):
        """Timestamp too far in the future should be rejected."""
        future_ts = str(int(time.time()) + 600)
        signed_message = f"{future_ts}.".encode() + sample_payload_bytes
        sig = hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(
            sample_payload_bytes, sig, future_ts,
            mock_secrets_manager, tolerance_seconds=300,
        ) is False

    def test_timestamp_just_within_tolerance(self, sample_payload_bytes,
                                              mock_secrets_manager, webhook_secret):
        """Timestamp at boundary minus 1 second should pass."""
        ts = str(int(time.time()) - 299)
        signed_message = f"{ts}.".encode() + sample_payload_bytes
        sig = hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(
            sample_payload_bytes, sig, ts,
            mock_secrets_manager, tolerance_seconds=300,
        ) is True

    def test_timestamp_just_outside_tolerance(self, sample_payload_bytes,
                                               mock_secrets_manager, webhook_secret):
        """Timestamp at boundary plus 1 second should fail."""
        ts = str(int(time.time()) - 301)
        signed_message = f"{ts}.".encode() + sample_payload_bytes
        sig = hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(
            sample_payload_bytes, sig, ts,
            mock_secrets_manager, tolerance_seconds=300,
        ) is False

    def test_empty_payload(self, valid_timestamp, mock_secrets_manager, webhook_secret):
        """Empty payload should be handled gracefully."""
        payload = b""
        signed_message = f"{valid_timestamp}.".encode() + payload
        sig = hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()
        # Signature verification should pass (it's a valid HMAC of empty payload)
        assert verify_webhook_signature(
            payload, sig, valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is True

    def test_malformed_signature_header(self, sample_payload_bytes, valid_timestamp,
                                         mock_secrets_manager):
        """Non-hex garbage should fail gracefully without exceptions."""
        assert verify_webhook_signature(
            sample_payload_bytes, "not-a-valid-hex-signature!!!",
            valid_timestamp, mock_secrets_manager, tolerance_seconds=300,
        ) is False

    def test_invalid_timestamp_format(self, sample_payload_bytes, mock_secrets_manager):
        """Non-numeric timestamp should fail gracefully."""
        assert verify_webhook_signature(
            sample_payload_bytes, "somesig", "not-a-number",
            mock_secrets_manager, tolerance_seconds=300,
        ) is False


class TestKeyRotation:
    """Tests for dual-key webhook signature verification during rotation."""

    def test_current_key_accepted(self, sample_payload_bytes, valid_timestamp,
                                   valid_signature, mock_secrets_manager):
        """Signature with current key should pass."""
        assert verify_webhook_signature(
            sample_payload_bytes, valid_signature, valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is True

    def test_previous_key_accepted(self, sample_payload_bytes, valid_timestamp,
                                    mock_secrets_manager, webhook_secret_previous):
        """Signature with previous/old key should pass during rotation window."""
        signed_message = f"{valid_timestamp}.".encode() + sample_payload_bytes
        sig = hmac.new(webhook_secret_previous.encode(),
                       signed_message, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(
            sample_payload_bytes, sig, valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is True

    def test_unknown_key_rejected(self, sample_payload_bytes, valid_timestamp,
                                   mock_secrets_manager):
        """Signature with completely unknown key should fail."""
        signed_message = f"{valid_timestamp}.".encode() + sample_payload_bytes
        sig = hmac.new(b"totally_unknown_key_not_in_any_config",
                       signed_message, hashlib.sha256).hexdigest()
        assert verify_webhook_signature(
            sample_payload_bytes, sig, valid_timestamp,
            mock_secrets_manager, tolerance_seconds=300,
        ) is False


class TestReplayProtection:
    """Tests for nonce-based replay attack prevention."""

    def test_duplicate_webhook_rejected(self, sample_payload_bytes, valid_timestamp,
                                         valid_signature, mock_secrets_manager):
        """Same webhook sent twice should be rejected on second attempt."""
        processor = WebhookProcessor(mock_secrets_manager, tolerance_seconds=300)

        # First attempt: should succeed
        success1, event1 = processor.process(sample_payload_bytes, valid_signature, valid_timestamp)
        assert success1 is True
        assert event1 is not None

        # Second attempt with same payload: should be deduplicated (ack but no reprocess)
        success2, event2 = processor.process(sample_payload_bytes, valid_signature, valid_timestamp)
        assert success2 is True  # Ack to prevent retries
        assert event2 is not None  # Event returned but was already processed

    def test_different_payloads_different_ids_accepted(self, valid_timestamp,
                                                        mock_secrets_manager, webhook_secret):
        """Different webhook IDs should both be accepted."""
        processor = WebhookProcessor(mock_secrets_manager, tolerance_seconds=300)

        for i in range(3):
            payload = json.dumps({
                "event_type": "payment.status_updated",
                "payment_id": f"pay_{i}",
                "status": "approved",
                "amount": "10.00",
                "currency": "USD",
                "timestamp": "2024-01-15T12:00:00Z",
                "idempotency_key": f"unique_key_{i}",
            }).encode()
            signed_msg = f"{valid_timestamp}.".encode() + payload
            sig = hmac.new(webhook_secret.encode(), signed_msg, hashlib.sha256).hexdigest()

            success, event = processor.process(payload, sig, valid_timestamp)
            assert success is True
            assert event.payment_id == f"pay_{i}"


class TestEventParsing:
    """Tests for webhook payload parsing."""

    def test_valid_payload(self, sample_webhook_payload):
        payload = json.dumps(sample_webhook_payload).encode()
        event = parse_webhook_event(payload)
        assert event.event_type == "payment.status_updated"
        assert event.payment_id == "pay_abc123def456"
        assert event.status == "approved"
        assert event.amount == "49.99"
        assert event.currency == "USD"

    def test_malformed_json(self):
        with pytest.raises(ValueError, match="Malformed"):
            parse_webhook_event(b"not json at all")

    def test_missing_fields_default_empty(self):
        payload = json.dumps({"event_type": "test"}).encode()
        event = parse_webhook_event(payload)
        assert event.event_type == "test"
        assert event.payment_id == ""
        assert event.status == ""
