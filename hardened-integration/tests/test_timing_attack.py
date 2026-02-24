"""
Tests to verify constant-time signature comparison.

Validates that hmac.compare_digest is used instead of == to prevent timing
side-channel attacks. Per OWASP A02:2021 Cryptographic Failures.

Note: The statistical timing test is probabilistic and may vary in CI due to
system load. The primary protection is code review ensuring compare_digest usage.
"""

import inspect
import time
import hashlib
import hmac
import statistics

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from webhook_handler import verify_webhook_signature


class TestConstantTimeComparison:
    """Verify that timing side-channels are mitigated."""

    def test_compare_digest_used_in_source(self):
        """
        Verify that hmac.compare_digest is used in the verification function.

        Why: == comparison short-circuits on first mismatch, leaking information
        about how many bytes of the signature are correct. compare_digest always
        takes the same time regardless of where the mismatch occurs.
        """
        source = inspect.getsource(verify_webhook_signature)
        assert "compare_digest" in source, (
            "webhook signature verification must use hmac.compare_digest, "
            "not == operator, to prevent timing attacks"
        )
        # Also verify == is not used for signature comparison
        # (it's OK for other comparisons like label == "previous")
        lines = source.split("\n")
        for line in lines:
            stripped = line.strip()
            if "expected_sig" in stripped and "==" in stripped:
                pytest.fail(
                    f"Found direct == comparison with expected_sig: {stripped}. "
                    "Must use hmac.compare_digest for constant-time comparison."
                )

    def test_timing_resistance(self, mock_secrets_manager, webhook_secret):
        """
        Statistical test: verification time should not correlate with signature correctness.

        We compare timing for a completely wrong signature vs a partially correct one.
        If the implementation uses ==, the partially correct one would take slightly
        longer (short-circuit later). With compare_digest, timing should be similar.

        Note: This is a probabilistic test. In noisy CI environments, it may not
        detect subtle timing differences. The source code inspection test above
        is the primary control.
        """
        payload = b'{"test": "timing"}'
        ts = str(int(time.time()))
        signed_message = f"{ts}.".encode() + payload
        correct_sig = hmac.new(webhook_secret.encode(), signed_message, hashlib.sha256).hexdigest()

        # Completely wrong signature
        wrong_sig = "0" * 64

        # Partially correct signature (first half matches)
        partial_sig = correct_sig[:32] + "0" * 32

        iterations = 50
        wrong_times = []
        partial_times = []

        for _ in range(iterations):
            start = time.perf_counter_ns()
            verify_webhook_signature(payload, wrong_sig, ts, mock_secrets_manager, 300)
            wrong_times.append(time.perf_counter_ns() - start)

            start = time.perf_counter_ns()
            verify_webhook_signature(payload, partial_sig, ts, mock_secrets_manager, 300)
            partial_times.append(time.perf_counter_ns() - start)

        wrong_mean = statistics.mean(wrong_times)
        partial_mean = statistics.mean(partial_times)

        # The ratio should be close to 1.0 (same time for both).
        # Allow generous 50% tolerance for system noise.
        ratio = partial_mean / wrong_mean if wrong_mean > 0 else 1.0
        assert 0.5 < ratio < 1.5, (
            f"Timing ratio {ratio:.2f} suggests non-constant-time comparison. "
            f"Wrong sig avg: {wrong_mean:.0f}ns, Partial sig avg: {partial_mean:.0f}ns"
        )
