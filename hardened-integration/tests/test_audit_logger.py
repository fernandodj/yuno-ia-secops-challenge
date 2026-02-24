"""
Tests for audit logging and PII/credential sanitization.

Validates PCI-DSS Req 3.4 (PAN masking), Req 10.2 (audit logging),
and defense against information disclosure via logs.
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from middleware.audit_logger import (
    sanitize_pan, sanitize_cvv, sanitize_api_key, sanitize_email,
    sanitize, AuditLogEntry, AuditLogger,
)


class TestPANMasking:
    """Card number sanitization per PCI-DSS Req 3.4."""

    def test_visa_card_masked(self):
        """Visa card should show BIN + last 4 only."""
        result = sanitize_pan("Card: 4111111111111111")
        assert "411111******1111" in result
        assert "4111111111111111" not in result

    def test_mastercard_masked(self):
        result = sanitize_pan("MC: 5500000000000004")
        assert "550000******0004" in result

    def test_amex_masked(self):
        result = sanitize_pan("Amex: 378282246310005")
        assert "378282" in result
        assert "0005" in result
        assert "378282246310005" not in result

    def test_no_card_unchanged(self):
        text = "Order total: $49.99, items: 3"
        assert sanitize_pan(text) == text


class TestCVVMasking:
    def test_cvv_fully_masked(self):
        result = sanitize_cvv('"cvv": "123"')
        assert "123" not in result
        assert '***' in result

    def test_cvc_fully_masked(self):
        result = sanitize_cvv('"cvc": "456"')
        assert "456" not in result

    def test_security_code_masked(self):
        result = sanitize_cvv('"security_code": "7890"')
        assert "7890" not in result


class TestAPIKeyMasking:
    def test_long_key_redacted(self):
        key = "yuno_pk_live_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c"
        result = sanitize_api_key(f"Key: {key}")
        assert key not in result
        assert "yuno_pk" in result  # Prefix visible
        assert "[REDACTED]" in result

    def test_short_string_unchanged(self):
        result = sanitize_api_key("hello world")
        assert result == "hello world"


class TestEmailMasking:
    def test_email_partially_masked(self):
        result = sanitize_email("user@example.com")
        assert "user@example.com" not in result
        assert "u***@example.com" in result

    def test_long_email_masked(self):
        result = sanitize_email("longusername@domain.co")
        assert "longusername@domain.co" not in result
        assert "@domain.co" in result


class TestFullSanitization:
    def test_combined_sanitization(self):
        """All sanitization rules applied together."""
        text = (
            'Card 4111111111111111 with "cvv": "123" '
            'key=yuno_pk_live_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c '
            'email user@example.com'
        )
        result = sanitize(text)
        assert "4111111111111111" not in result
        assert '"123"' not in result
        assert "8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c" not in result
        assert "user@example.com" not in result


class TestAuditLogEntry:
    def test_structured_json_format(self):
        entry = AuditLogEntry(
            timestamp="2024-01-15T12:00:00Z",
            request_id="req_abc123",
            merchant_id="quickeats",
            endpoint="/payments",
            method="POST",
            source_ip="198.51.100.10",
            user_agent="QuickEats/2.0",
            response_status=200,
            response_time_ms=150.5,
        )
        json_str = entry.to_json()
        import json
        parsed = json.loads(json_str)
        assert parsed["timestamp"] == "2024-01-15T12:00:00Z"
        assert parsed["request_id"] == "req_abc123"
        assert parsed["method"] == "POST"
        assert parsed["response_status"] == 200

    def test_entry_sanitizes_embedded_pan(self):
        """If a PAN somehow ends up in a field, it should be masked."""
        entry = AuditLogEntry(
            timestamp="2024-01-15T12:00:00Z",
            request_id="req_abc123",
            merchant_id="quickeats",
            endpoint="/payments",
            method="POST",
            source_ip="198.51.100.10",
            user_agent="QuickEats/2.0",
            response_status=200,
            response_time_ms=150.5,
            error="Card 4111111111111111 declined",
        )
        json_str = entry.to_json()
        assert "4111111111111111" not in json_str
        assert "411111" in json_str  # BIN visible
        assert "1111" in json_str   # Last 4 visible


class TestSensitiveEndpointDetection:
    def test_payment_endpoint_is_sensitive(self):
        assert AuditLogger.is_sensitive_endpoint("/v1/payments") is True

    def test_refund_endpoint_is_sensitive(self):
        assert AuditLogger.is_sensitive_endpoint("/v1/refunds") is True

    def test_health_endpoint_not_sensitive(self):
        assert AuditLogger.is_sensitive_endpoint("/health") is False
