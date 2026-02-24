#!/usr/bin/env python3
"""
Automated Credential Rotation for Leaked Merchant Credentials.

Orchestrates the full credential rotation lifecycle: revoke compromised keys,
generate new credentials, verify deployment, and produce an audit trail.

Usage:
    python rotate_credentials.py --merchant-id merchant_quickeats_prod_001 --environment production --dry-run
    python rotate_credentials.py --merchant-id merchant_quickeats_prod_001 --environment production --force

References:
    - NIST SP 800-57: Key Management Recommendations
    - PCI-DSS Req 3.6: Key management procedures for cryptographic keys
"""

import argparse
import json
import secrets
import sys
import uuid
from datetime import datetime, timezone
from typing import Any


class AuditTrail:
    """Append-only audit trail for credential rotation actions."""

    def __init__(self):
        self.entries: list[dict[str, Any]] = []

    def log(self, action: str, status: str, details: str, **kwargs):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "status": status,
            "details": details,
            **kwargs,
        }
        self.entries.append(entry)
        marker = {"SUCCESS": "+", "FAILED": "!", "SKIPPED": "~", "INFO": " "}
        print(f"  [{marker.get(status, '?')}] {action}: {details}")

    def to_dict(self) -> list[dict]:
        return self.entries


class MockYunoAdminAPI:
    """
    Simulated Yuno Admin API for credential management.

    In production, replace with actual HTTP calls to Yuno's internal admin API.
    The mock exercises the full rotation logic including error handling and rollback.
    """

    def __init__(self):
        self._credentials = {
            "merchant_quickeats_prod_001": {
                "production": {
                    "api_key": "yuno_pk_live_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c",
                    "api_secret": "yuno_sk_live_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
                    "webhook_secret": "whsec_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
                    "status": "active",
                    "created_at": "2023-06-15T10:00:00Z",
                    "scopes": ["payment:read", "payment:write", "refund:write"],
                },
                "test": {
                    "api_key": "yuno_pk_test_2b7c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
                    "api_secret": "yuno_sk_test_7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c",
                    "webhook_secret": "whsec_test_x1y2z3a4b5c6d7e8f9g0h1i2j3k4l5m",
                    "status": "active",
                    "created_at": "2023-06-15T10:00:00Z",
                    "scopes": ["payment:read", "payment:write"],
                },
            }
        }

    def get_credentials(self, merchant_id: str, environment: str) -> dict | None:
        merchant = self._credentials.get(merchant_id)
        if not merchant:
            return None
        return merchant.get(environment)

    def revoke_credentials(self, merchant_id: str, environment: str, api_key: str) -> bool:
        """
        Revoke a specific API key immediately.

        Why immediate revocation: during an active credential leak, any delay
        extends the attacker's access window. Per NIST SP 800-57 Section 5.3.6.
        """
        merchant = self._credentials.get(merchant_id, {})
        env_creds = merchant.get(environment)
        if not env_creds or env_creds.get("api_key") != api_key:
            return False
        env_creds["status"] = "revoked"
        env_creds["revoked_at"] = datetime.now(timezone.utc).isoformat()
        return True

    def generate_new_credentials(self, merchant_id: str, environment: str,
                                  scopes: list[str]) -> dict:
        """
        Generate new API credentials with specified scopes.

        Why scoped generation: new credentials should follow least privilege.
        If old key had overly broad scopes, restrict them. Per PCI-DSS Req 7.1.
        """
        prefix = "live" if environment == "production" else "test"
        new_creds = {
            "api_key": f"yuno_pk_{prefix}_{secrets.token_hex(16)}",
            "api_secret": f"yuno_sk_{prefix}_{secrets.token_hex(16)}",
            "webhook_secret": f"whsec_{secrets.token_hex(16)}",
            "status": "active",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "scopes": scopes,
        }
        if merchant_id not in self._credentials:
            self._credentials[merchant_id] = {}
        self._credentials[merchant_id][environment] = new_creds
        return new_creds

    def verify_credentials(self, api_key: str) -> bool:
        for merchant in self._credentials.values():
            for env in merchant.values():
                if env.get("api_key") == api_key and env.get("status") == "active":
                    return True
        return False

    def verify_old_revoked(self, api_key: str) -> bool:
        for merchant in self._credentials.values():
            for env in merchant.values():
                if env.get("api_key") == api_key:
                    return env.get("status") == "revoked"
        return True


def rotate_credentials(merchant_id: str, environment: str,
                       dry_run: bool = False, force: bool = False) -> dict[str, Any]:
    """
    Execute the full credential rotation workflow.

    Steps:
        1. Fetch current active credentials
        2. Validate rotation prerequisites
        3. Generate new credentials
        4. Revoke old credentials
        5. Verify new credentials work
        6. Verify old credentials are revoked
        7. Generate rotation report
    """
    api = MockYunoAdminAPI()
    audit = AuditTrail()
    rotation_id = uuid.uuid4().hex[:12]

    print(f"\n{'='*60}")
    print(f"  CREDENTIAL ROTATION {'(DRY RUN)' if dry_run else ''}")
    print(f"{'='*60}")
    print(f"  Rotation ID:  {rotation_id}")
    print(f"  Merchant:     {merchant_id}")
    print(f"  Environment:  {environment}")
    print(f"  Mode:         {'DRY RUN' if dry_run else 'LIVE'}")
    print(f"{'='*60}\n")

    audit.log("ROTATION_START", "INFO",
              f"Rotation {rotation_id} initiated for {merchant_id}/{environment}",
              rotation_id=rotation_id, dry_run=dry_run)

    # Step 1: Fetch current credentials
    current = api.get_credentials(merchant_id, environment)
    if not current:
        audit.log("FETCH_CREDENTIALS", "FAILED",
                  f"No credentials found for {merchant_id}/{environment}")
        return {"status": "failed", "reason": "credentials_not_found", "audit": audit.to_dict()}

    old_key = current["api_key"]
    old_key_prefix = old_key[:16] + "..."
    audit.log("FETCH_CREDENTIALS", "SUCCESS",
              f"Found active credentials: key_prefix={old_key_prefix}, "
              f"scopes={current.get('scopes', [])}")

    # Step 2: Production safety check
    if environment == "production" and not force and not dry_run:
        audit.log("SAFETY_CHECK", "INFO",
                  "Production rotation requires --force or --dry-run")
        print("\n  WARNING: PRODUCTION ENVIRONMENT - Will immediately revoke live credentials.")
        print("     Use --force to proceed or --dry-run to preview.\n")
        return {"status": "aborted", "reason": "production_safety_check", "audit": audit.to_dict()}

    scopes = current.get("scopes", ["payment:read", "payment:write"])

    # Step 3: Generate new credentials
    if dry_run:
        audit.log("GENERATE_NEW", "SKIPPED",
                  f"[DRY RUN] Would generate new credentials with scopes={scopes}")
        new_creds = {"api_key": "[DRY_RUN]", "webhook_secret": "[DRY_RUN]"}
    else:
        try:
            new_creds = api.generate_new_credentials(merchant_id, environment, scopes)
            audit.log("GENERATE_NEW", "SUCCESS",
                      f"New credentials generated: key_prefix={new_creds['api_key'][:16]}...")
        except Exception as e:
            audit.log("GENERATE_NEW", "FAILED", f"Generation failed: {type(e).__name__}")
            return {"status": "failed", "reason": "generation_failed", "audit": audit.to_dict()}

    # Step 4: Revoke old credentials
    if dry_run:
        audit.log("REVOKE_OLD", "SKIPPED", f"[DRY RUN] Would revoke: {old_key_prefix}")
    else:
        try:
            if api.revoke_credentials(merchant_id, environment, old_key):
                audit.log("REVOKE_OLD", "SUCCESS", f"Old key revoked: {old_key_prefix}")
            else:
                audit.log("REVOKE_OLD", "FAILED", f"Revocation failed: {old_key_prefix}")
                audit.log("ROLLBACK", "INFO", "Both old and new keys may be active - escalate")
                return {"status": "failed", "reason": "revocation_failed",
                        "action_required": "Manual review needed", "audit": audit.to_dict()}
        except Exception as e:
            audit.log("REVOKE_OLD", "FAILED", f"Exception: {type(e).__name__}")
            return {"status": "failed", "reason": "revocation_error", "audit": audit.to_dict()}

    # Step 5: Verify new credentials
    if dry_run:
        audit.log("VERIFY_NEW", "SKIPPED", "[DRY RUN] Would verify new credentials")
    else:
        if api.verify_credentials(new_creds["api_key"]):
            audit.log("VERIFY_NEW", "SUCCESS", "New credentials verified active")
        else:
            audit.log("VERIFY_NEW", "FAILED", "New credentials verification failed!")
            return {"status": "failed", "reason": "verification_failed", "audit": audit.to_dict()}

    # Step 6: Verify old revoked
    if dry_run:
        audit.log("VERIFY_REVOCATION", "SKIPPED", "[DRY RUN] Would verify old key revoked")
    else:
        if api.verify_old_revoked(old_key):
            audit.log("VERIFY_REVOCATION", "SUCCESS", "Old credentials confirmed revoked")
        else:
            audit.log("VERIFY_REVOCATION", "FAILED", "Old key may still be active!")
            return {"status": "partial", "reason": "old_key_still_active", "audit": audit.to_dict()}

    audit.log("ROTATION_COMPLETE", "SUCCESS", f"Rotation {rotation_id} completed")

    result = {
        "status": "success",
        "rotation_id": rotation_id,
        "merchant_id": merchant_id,
        "environment": environment,
        "dry_run": dry_run,
        "old_key_prefix": old_key_prefix,
        "new_key_prefix": new_creds["api_key"][:16] + "..." if not dry_run else "[DRY_RUN]",
        "scopes": scopes,
        "next_steps": [
            "Deliver new credentials via encrypted channel (NOT email/Slack)",
            "Verify merchant has deployed new credentials",
            "Run test transaction to confirm integration works",
            "Monitor API logs for 72 hours post-rotation",
        ],
        "audit": audit.to_dict(),
    }

    print(f"\n{'='*60}")
    print(f"  ROTATION {'PREVIEW' if dry_run else 'COMPLETE'}")
    print(f"{'='*60}")
    print(f"  Status: {result['status']}")
    print(f"  Old key: {result['old_key_prefix']}")
    print(f"  New key: {result['new_key_prefix']}")
    print(f"\n  Next steps:")
    for i, step in enumerate(result["next_steps"], 1):
        print(f"    {i}. {step}")
    print()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Automated credential rotation for leaked merchant credentials")
    parser.add_argument("--merchant-id", required=True, help="Merchant identifier")
    parser.add_argument("--environment", required=True, choices=["production", "test"])
    parser.add_argument("--dry-run", action="store_true", help="Preview without executing")
    parser.add_argument("--force", action="store_true", help="Skip production safety check")
    parser.add_argument("--output-json", help="Write report to JSON file")
    args = parser.parse_args()

    result = rotate_credentials(args.merchant_id, args.environment, args.dry_run, args.force)

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Report written to: {args.output_json}")

    sys.exit(0 if result["status"] == "success" else 1)


if __name__ == "__main__":
    main()
