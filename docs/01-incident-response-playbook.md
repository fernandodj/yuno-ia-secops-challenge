# Incident Response Playbook: Leaked Merchant Credentials

| Field | Value |
|-------|-------|
| **Playbook ID** | IR-PLAY-001 |
| **Version** | 1.0 |
| **Owner** | Yuno Security Operations Center (SOC) |
| **Last Updated** | 2024-01-15 |
| **Classification** | Internal — Restricted |

---

## Severity Classification

| Level | Criteria | Response Window | Escalation |
|-------|----------|----------------|------------|
| **P1 — CRITICAL** | Production API keys or webhook secrets leaked; active exploitation detected | 15 minutes | VP Engineering + CISO + PCI QSA |
| **P2 — HIGH** | Test environment keys + configuration/routing logic exposed | 4 hours | Engineering Lead + Security Lead |
| **P3 — MEDIUM** | Test keys only, no configuration exposure | 24 hours | Security Team |

---

## Phase 1: Detection & Assessment (0–15 minutes)

### 1.1 How Was the Leak Detected?

| Source | Action |
|--------|--------|
| GitHub Secret Scanning | Automated alert triggered on Yuno credential pattern |
| Third-party report (HackerOne, email) | Validate reporter, confirm finding |
| Internal audit / developer self-report | Log discovery context |
| Yuno automated monitoring | Check alert details in SIEM |

### 1.2 Confirm What Was Leaked

Enumerate each credential found in the exposed repository:

- [ ] Yuno API keys (note: test vs production, key prefix `yuno_pk_live_` vs `yuno_pk_test_`)
- [ ] Yuno API secrets
- [ ] Webhook signing secrets (`whsec_*`)
- [ ] Database connection strings (check for embedded passwords)
- [ ] Service-to-service authentication tokens
- [ ] Payment routing configuration / processor credentials
- [ ] Other secrets (AWS keys, third-party API keys)

### 1.3 Determine Exposure Window

```
Commit timestamp:     _____________ (when credentials were committed)
Repo became public:   _____________ (if private repo was made public)
Detection timestamp:  _____________
Exposure duration:    _____________ hours
```

### 1.4 Severity Decision Tree

```
Production keys leaked?
├── YES ──→ Active exploitation detected in logs?
│           ├── YES ──→ P1 CRITICAL: Immediate containment + halt merchant API access
│           └── NO  ──→ P1 CRITICAL: Immediate credential rotation
└── NO  ──→ Configuration/routing data leaked?
            ├── YES ──→ P2 HIGH: Expedited rotation within 4 hours
            └── NO  ──→ Test keys only?
                        ├── YES ──→ P3 MEDIUM: Standard rotation within 24 hours
                        └── NO  ──→ Assess further, consult security lead
```

---

## Phase 2: Blast Radius Analysis (15–30 minutes)

### 2.1 Environment Assessment

| Environment | Keys Found? | Scopes | Data Access Risk |
|-------------|-------------|--------|-----------------|
| Production | [ ] Yes / [ ] No | List scopes | Describe risk |
| Test/Sandbox | [ ] Yes / [ ] No | List scopes | Describe risk |

### 2.2 Quantified Impact Assessment

```
Daily transactions:           _______ (e.g., 50,000)
Average transaction value:    $_______ (e.g., $50)
Daily transaction volume:     $_______ (e.g., $2,500,000)
Exposure window:              _______ hours (e.g., 18)
Transactions in window:       _______ (daily × hours/24)
Worst-case financial exposure: $_______
```

**QuickEats Example:**
- 50K txns/day × $50 avg = $2.5M daily exposure
- 18h window → ~37,500 transactions potentially visible
- If attacker redirected 1% of payments: ~$18.7K direct loss
- Additional: PCI compliance violations ($5K–$100K fines), reputational damage

### 2.3 Data Access Assessment

| Data Type | Accessible via Leaked Creds? | PCI Impact |
|-----------|------------------------------|------------|
| Transaction history | Yes (via API) | Req 7.1 violation |
| Tokenized card data | Tokens only (PANs tokenized by Yuno) | Limited if tokens non-reversible |
| Merchant configuration | Yes (routing rules, processor setup) | Business intelligence leak |
| Cardholder PII | Only if DB creds leaked AND network accessible | Req 3.4, breach notification required |

---

## Phase 3: Containment (30–60 minutes)

### 3.1 Immediate Actions (within 15 min of P1 classification)

```
Priority  Action                                              Status
──────────────────────────────────────────────────────────────────────
[P1]  1.  Revoke all leaked API keys via Yuno Admin API       [ ]
[P1]  2.  Rotate webhook signing secrets                      [ ]
[P1]  3.  Block suspicious IPs at API gateway/WAF             [ ]
[P1]  4.  Enable IP allowlisting for affected merchant        [ ]
[P1]  5.  Activate enhanced rate limiting (10 req/min temp)   [ ]
[P1]  6.  Change DB passwords, restrict to app IPs only       [ ]
[P2]  7.  Disable test environment API keys                   [ ]
[P2]  8.  Rotate service-to-service tokens                    [ ]
[P2]  9.  Invalidate processor credential sessions            [ ]
```

### 3.2 Active Exploitation Decision Tree

```
Evidence of credential usage post-leak?
├── YES ──→ Unauthorized transactions detected?
│           ├── YES ──→ NUCLEAR: Halt all API access for merchant
│           │          Notify merchant engineering lead IMMEDIATELY
│           │          Engage Yuno fraud team for transaction review
│           │          Consider freezing merchant's payment processing
│           └── NO  ──→ Data exfiltration only
│                      Proceed with rotation
│                      Enhanced monitoring for 72 hours
│                      Preserve all access logs for forensics
└── NO  ──→ Proceed with standard rotation
            Monitor API logs closely for 72 hours
            Alert on any usage of revoked credentials
```

### 3.3 Automation

```bash
# Run credential rotation (dry run first)
python incident-response/rotate_credentials.py \
    --merchant-id merchant_quickeats_prod_001 \
    --environment production \
    --dry-run

# Execute rotation
python incident-response/rotate_credentials.py \
    --merchant-id merchant_quickeats_prod_001 \
    --environment production \
    --force \
    --output-json rotation_report.json
```

---

## Phase 4: Investigation (1–4 hours)

### 4.1 Log Analysis

Run the automated anomaly detection tool:

```bash
# Generate sample logs for testing (if needed)
python incident-response/sample_data/generate_sample_logs.py

# Analyze API access logs
python incident-response/analyze_api_logs.py \
    --log-file /path/to/api_access_logs.jsonl \
    --leak-timestamp 2024-01-15T03:47:00+00:00 \
    --merchant-id merchant_quickeats_prod_001 \
    --output-json analysis_report.json
```

### 4.2 Investigation Checklist

- [ ] **New IPs**: Any IP addresses not seen before the leak?
- [ ] **Geographic anomalies**: Requests from unexpected countries?
- [ ] **Volume spikes**: Unusual traffic patterns post-leak?
- [ ] **Sensitive endpoints**: Access to /merchants/config, /transactions/export, /api-keys?
- [ ] **Enumeration**: Sequential scanning of resources?
- [ ] **Webhook interception**: Were any webhooks replayed or forged?
- [ ] **Refund anomalies**: Unusual refund patterns or amounts?
- [ ] **Credential creation**: Were new API keys created via leaked admin creds?

### 4.3 Forensic Evidence Preservation

**CRITICAL: Preserve evidence BEFORE credential rotation, as post-rotation you lose visibility into attempts with old keys.**

| Evidence | How to Preserve | Retention |
|----------|----------------|-----------|
| API access logs (exposure window + 48h) | Export from SIEM to secure archive | 1 year (PCI-DSS Req 10.7) |
| Credential state and permissions | Snapshot via Admin API | Until incident closure |
| Leaked repository content | Screenshots + `git clone` + SHA hash | Until incident closure |
| Network flow logs | Export from cloud provider | 90 days |
| Database audit logs | Export from DB audit system | 1 year |

**Chain of Custody:**
```
Analyst: _______________
Timestamp: _______________
Evidence hash (SHA-256): _______________
Storage location: _______________
```

---

## Phase 5: Remediation (2–8 hours)

### 5.1 Credential Rotation

1. Generate new credentials via Yuno Admin API
2. Deliver to merchant via **encrypted channel** (NOT email, NOT Slack)
   - Use: PGP-encrypted file, secure vault share link, or in-person
3. Merchant deploys new credentials
4. Verify integration works: run test transaction
5. Confirm old credentials fully revoked: attempt use, verify rejection

### 5.2 Integration Hardening

Recommend merchant adopt the hardened integration reference:

- Secrets management (Vault, AWS SM, or at minimum secure env vars)
- Pre-commit secrets scanning hooks
- Webhook signature verification with replay protection
- Scoped API keys (least privilege)
- See: `hardened-integration/` in this repository

---

## Phase 6: Post-Incident (24–72 hours)

### 6.1 Incident Report

```bash
python incident-response/generate_report.py \
    --merchant-id merchant_quickeats_prod_001 \
    --leak-timestamp 2024-01-15T03:47:00+00:00 \
    --analyst-name "Your Name" \
    --findings-file analysis_report.json \
    --output incident_report.md
```

### 6.2 Lessons Learned

- [ ] Conduct retrospective with SOC + merchant engineering
- [ ] Update credential patterns in GitHub Secret Scanning
- [ ] Evaluate: should Yuno mandate secrets scanning for all merchants?
- [ ] Update this playbook with any new findings

### 6.3 Compliance Notifications

| Condition | Required Notification | Timeline |
|-----------|----------------------|----------|
| Cardholder data possibly exposed | PCI QSA | 72 hours |
| EU cardholder data accessed | Data Protection Authority (GDPR) | 72 hours |
| > 10K cardholders affected | Card brands (Visa, MC) | Per brand rules |

---

## Stakeholder Communication Templates

### Template 1: Internal Notification

```
Subject: [P1] Credential Leak - Merchant: {merchant_name} - {date}

SEVERITY: {P1/P2/P3}
STATUS: {Active Investigation / Contained / Resolved}

SUMMARY:
At {time} UTC, {detection_method} identified that API credentials for
{merchant_name} ({merchant_id}) were exposed in a public GitHub repository.

IMPACT:
- Environment: {production/test/both}
- Exposure window: {hours} hours
- Credentials leaked: {list}
- Blast radius: {description}

ACTIONS TAKEN:
1. {action_1}
2. {action_2}
3. {action_3}

NEXT STEPS:
- {next_step_1}
- {next_step_2}

INCIDENT LEAD: {name}
ESCALATION: {contact}
```

### Template 2: Merchant Notification

```
Subject: Security Incident - Immediate Action Required

Dear {merchant_contact},

At {time} UTC on {date}, our security monitoring detected that API credentials
for your {environment} environment were exposed in a public code repository.

WHAT HAPPENED:
Your API credentials were found in a public GitHub repository. We have taken
immediate action to protect your account.

WHAT WE DID:
- Revoked all affected API credentials
- Generated new credentials (delivered separately via secure channel)
- Analyzed API access logs for unauthorized activity during the exposure window
- Enabled enhanced monitoring on your account

WHAT YOU NEED TO DO:
1. Deploy the new credentials we provided via {secure_channel}
2. Verify your integration is functioning with a test transaction
3. Review your codebase for any other hardcoded credentials
4. Implement a secrets management solution (see our guide: {link})
5. Set up pre-commit hooks for secrets scanning

FINDINGS:
{summary_of_any_unauthorized_access_detected}

If you have questions, contact your Yuno account manager or our security
team at security@yuno.co.

Yuno Security Team
```

---

## Appendix: Merchant-Wide Applicability

This playbook is parameterized by `merchant_id` and applies to all 1,000+
Yuno merchant integrations. For programmatic execution:

```bash
# Can be triggered automatically by GitHub Secret Scanning webhooks
python incident-response/rotate_credentials.py \
    --merchant-id $MERCHANT_ID \
    --environment $ENVIRONMENT \
    --force
```

**Recommendation:** Implement automated playbook execution triggered by
GitHub secret scanning alerts via webhook → SOC automation pipeline.
