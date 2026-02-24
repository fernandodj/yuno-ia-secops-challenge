# Yuno SecOps Challenge: QuickEats Credential Leak Response

Comprehensive security incident response and remediation for a leaked merchant credential scenario at Yuno, a payment orchestration platform.

## Scenario

QuickEats (food delivery, $2.5M/day, 50K+ txns) had API credentials committed to a public GitHub repository for 18 hours. Leaked credentials include production API keys, webhook secrets, database connection strings, and payment routing configuration.

## Repository Structure

```
.
├── README.md                              # This file
├── Makefile                               # Demo runner (make demo-all)
├── docs/
│   ├── 01-incident-response-playbook.md   # SOC playbook with decision trees
│   └── 02-threat-model-and-design.md      # STRIDE analysis + design rationale
├── incident-response/
│   ├── analyze_api_logs.py                # Anomaly detection in API access logs
│   ├── rotate_credentials.py             # Automated credential rotation
│   ├── generate_report.py                # Incident report generator
│   └── sample_data/
│       └── generate_sample_logs.py       # Generate realistic test data
├── hardened-integration/
│   ├── app.py                            # FastAPI merchant backend
│   ├── webhook_handler.py                # HMAC verification + replay protection
│   ├── secrets_manager.py                # Multi-backend secrets management
│   ├── config.py                         # Env-based configuration
│   ├── middleware/
│   │   ├── auth.py                       # API auth + scoped permissions
│   │   ├── rate_limiter.py               # Token bucket rate limiting
│   │   └── audit_logger.py              # PAN-sanitized structured logging
│   ├── tests/                            # Security control tests
│   │   ├── test_webhook_verification.py  # HMAC, replay, rotation tests
│   │   ├── test_timing_attack.py         # Constant-time comparison verification
│   │   ├── test_audit_logger.py          # PAN masking, CVV redaction tests
│   │   ├── test_rate_limiter.py          # Token bucket behavior tests
│   │   └── test_integration.py           # E2E FastAPI tests
│   └── requirements.txt
└── secrets-scanning/
    ├── gitleaks.toml                     # Custom rules for Yuno key formats
    ├── .pre-commit-config.yaml           # Git pre-commit hook config
    ├── .github/workflows/secrets-scan.yml # CI/CD GitHub Action
    └── test-samples/
        └── fake_secrets.py               # Intentional secrets for demo
```

## Quick Start

```bash
# Install dependencies
make setup

# Run the full demo (log analysis → rotation → report → tests)
make demo-all

# Or run individual components:
make demo-analyze    # Analyze sample logs for post-leak anomalies
make demo-rotate     # Preview credential rotation (dry run)
make demo-report     # Generate incident report
make test            # Run all security control tests
make scan-secrets    # Run Gitleaks against test samples
```

## What Was Built

### 1. Incident Response Playbook & Automation (Required)

**Playbook** (`docs/01-incident-response-playbook.md`): Complete 6-phase playbook covering Detection → Blast Radius → Containment → Investigation → Remediation → Post-Incident. Includes severity classification (P1/P2/P3), decision trees for active exploitation scenarios, forensic evidence preservation procedures, and stakeholder communication templates.

**Automation scripts:**
- `analyze_api_logs.py` — Detects 7 types of anomalies: new IPs, geographic outliers, volume spikes, sensitive endpoint access, enumeration patterns, unusual user agents, temporal anomalies. Outputs structured findings with severity classification.
- `rotate_credentials.py` — Full rotation lifecycle with dry-run mode, production safety checks, rollback logic, and audit trail.
- `generate_report.py` — Produces markdown incident reports with timeline, blast radius assessment, quantified impact, and compliance considerations.

### 2. Hardened Merchant Integration (Required)

Production-quality FastAPI reference implementation with 9 layers of defense in depth:

| Layer | Control | Implementation |
|-------|---------|---------------|
| Network | IP allowlisting | Middleware rejects unknown IPs when configured |
| DoS Prevention | Request size limits | 64KB max payload |
| Abuse Prevention | Token bucket rate limiting | Per-key, per-IP, per-endpoint dimensions |
| Compliance | Audit logging | Structured JSON, PAN/CVV/key sanitization |
| Browser Security | Security headers | HSTS, CSP, X-Frame-Options, no-cache |
| Identity | API authentication | Bearer tokens in headers, request signing |
| Integrity | Webhook verification | HMAC-SHA256, timestamp validation, nonce dedup |
| Authorization | Scoped permissions | `@requires_scope` decorator with 6 granular scopes |
| Info Disclosure | Error sanitization | Generic errors externally, detailed logs internally |

**Key security features:**
- **Dual-key webhook verification**: Accepts signatures from both current and previous keys during rotation, enabling zero-downtime key rotation
- **Constant-time HMAC comparison**: Uses `hmac.compare_digest` to prevent timing side-channel attacks
- **Nonce-based replay protection**: Timestamp (5-min window) + idempotency key deduplication
- **Secrets Manager abstraction**: Pluggable backends (env vars → AWS SM → Vault) with TTL-cached, audit-logged access

### 3. Threat Analysis & Design Decisions (Required)

**STRIDE threat model** (`docs/02-threat-model-and-design.md`):
- 10 identified threats mapped across 4 trust boundaries
- 3 threat actor profiles (opportunistic scraper, targeted attacker, malicious insider)
- 2 attack trees (data exfiltration, financial damage) as Mermaid diagrams
- Quantified impact ($2.5M daily exposure, $18.7K estimated loss per incident)
- Design rationale with alternatives considered and rejected (HMAC vs JWT vs RSA, token bucket vs sliding window vs leaky bucket)
- PCI-DSS and OWASP API Security Top 10 compliance mapping
- Residual risk register with prioritized remediation roadmap

### 4. Secrets Scanning (Stretch)

- **Gitleaks configuration**: 12 regex rules for Yuno-specific and common credential formats, plus entropy-based detection for unknown secret types
- **Pre-commit hook**: Catches secrets before they reach the repository
- **GitHub Action**: CI/CD pipeline that fails the build on detected secrets
- **Test samples**: Intentional fake secrets demonstrating scanner detection

## Security Design Reasoning

**Why HMAC-SHA256 for webhooks**: Simpler than JWT (fewer failure modes, no `alg:none` vulnerability), faster than RSA (0.01ms vs 0.5ms per verification). Shared secret risk mitigated by dual-key rotation support. Recommended future migration to Ed25519 asymmetric signatures.

**Why token bucket rate limiting**: Allows legitimate burst traffic (food delivery lunch/dinner rush) while enforcing average rate. Fixed-window allows 2x burst at boundaries; leaky bucket blocks legitimate spikes.

**Why generic error responses**: Differentiated error messages ("bad signature" vs "expired timestamp") allow attackers to isolate and bypass individual controls. Generic `{"error": "invalid_webhook"}` forces attackers to solve all problems simultaneously.

**Why secrets manager abstraction**: Merchant teams range from 8 developers (QuickEats) to enterprise. Abstraction lets each choose appropriate backend while the security contract remains consistent.

## Tests

```bash
make test
```

Test coverage includes:
- HMAC signature verification (valid, invalid, empty, malformed)
- Timestamp boundary testing (within/outside 5-min tolerance)
- Key rotation (current key, previous key, unknown key)
- Replay attack prevention (duplicate nonce rejection)
- Constant-time comparison verification (source code inspection + statistical timing test)
- PAN/CVV/API key sanitization in logs
- Rate limiter behavior (burst, per-merchant isolation, endpoint overrides)
- Integration tests (full webhook flow, security headers, error handling, input validation)
