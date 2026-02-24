#!/usr/bin/env python3
"""
Incident Report Generator for Credential Leak Incidents.

Generates a structured markdown incident report with timeline, blast radius
assessment, findings, and recommendations.

Usage:
    python generate_report.py \\
        --merchant-id merchant_quickeats_prod_001 \\
        --leak-timestamp 2024-01-15T03:47:00+00:00 \\
        --analyst-name "SOC Analyst" \\
        --output report.md
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any


def classify_severity(leaked_items: list[str]) -> tuple[str, str]:
    """
    Classify incident severity based on what was leaked.

    Returns:
        (severity_level, description)

    Severity levels per Yuno SOC policy:
        P1 (CRITICAL): Production API keys or webhook secrets
        P2 (HIGH): Test keys + configuration/routing logic
        P3 (MEDIUM): Test keys only, no config exposure
    """
    production_indicators = ["api_key_production", "webhook_secret_production",
                             "db_connection_production"]
    config_indicators = ["routing_config", "processor_credentials", "service_tokens"]

    has_production = any(item in leaked_items for item in production_indicators)
    has_config = any(item in leaked_items for item in config_indicators)

    if has_production:
        return "P1 - CRITICAL", "Production credentials leaked. Immediate action required."
    elif has_config:
        return "P2 - HIGH", "Test credentials + configuration exposed. Expedited rotation."
    else:
        return "P3 - MEDIUM", "Test credentials only. Standard rotation within 24h."


def generate_report(
    merchant_id: str,
    leak_timestamp: str,
    analyst_name: str,
    findings_file: str | None = None,
) -> str:
    """Generate a formatted markdown incident report."""

    now = datetime.now(timezone.utc)

    # Load findings from analysis if available
    findings_data = None
    if findings_file:
        try:
            with open(findings_file, "r") as f:
                findings_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load findings file: {e}", file=sys.stderr)

    # QuickEats-specific leaked items
    leaked_items = [
        "api_key_production", "api_key_test", "webhook_secret_production",
        "service_tokens", "db_connection_production", "routing_config",
        "processor_credentials",
    ]
    severity, severity_desc = classify_severity(leaked_items)

    # Build findings summary from analysis data
    findings_summary = ""
    if findings_data:
        s = findings_data.get("summary", {})
        findings_summary = f"""
### Log Analysis Results

| Metric | Value |
|--------|-------|
| Total entries analyzed | {s.get('total_entries_analyzed', 'N/A')} |
| Pre-leak entries | {s.get('pre_leak_entries', 'N/A')} |
| Post-leak entries | {s.get('post_leak_entries', 'N/A')} |
| New IPs post-leak | {s.get('new_ips_post_leak', 'N/A')} |
| Critical findings | {s.get('critical_findings', 'N/A')} |
| High findings | {s.get('high_findings', 'N/A')} |

### Detailed Findings

"""
        for i, f in enumerate(findings_data.get("findings", []), 1):
            findings_summary += f"**{i}. [{f['severity']}] {f['title']}**\n"
            findings_summary += f"- Category: {f['category']}\n"
            findings_summary += f"- {f['details']}\n\n"

        findings_summary += "### Suspicious IP Addresses\n\n"
        findings_summary += "| IP | Country | Requests | First Seen |\n"
        findings_summary += "|-----|---------|----------|------------|\n"
        for ip in findings_data.get("suspicious_ips", []):
            findings_summary += (
                f"| {ip['ip']} | {ip['country']} | "
                f"{ip['request_count']} | {ip['first_seen']} |\n"
            )

        findings_summary += "\n### Recommendations from Analysis\n\n"
        for rec in findings_data.get("recommendations", []):
            findings_summary += f"- **[{rec['priority']}]** {rec['action']}\n"
            findings_summary += f"  - {rec['reason']}\n"

    report = f"""# Incident Report: Leaked Merchant Credentials

| Field | Value |
|-------|-------|
| **Incident ID** | INC-{now.strftime('%Y%m%d')}-{merchant_id[-6:]} |
| **Severity** | {severity} |
| **Merchant** | {merchant_id} |
| **Status** | Under Investigation |
| **Analyst** | {analyst_name} |
| **Report Generated** | {now.isoformat()} |
| **Leak Detected** | {leak_timestamp} |

---

## 1. Executive Summary

{severity_desc}

At {leak_timestamp}, Yuno's automated security monitoring detected that API credentials
belonging to **{merchant_id}** were committed to a public GitHub repository. The
exposure lasted approximately **18 hours** before the repository was made private.

The leaked credentials include production API keys, webhook signing secrets, database
connection strings, service-to-service tokens, and payment routing configuration.
This constitutes a **{severity}** incident due to the potential for unauthorized access
to production payment processing systems.

**Quantified Impact Assessment:**
- Daily transaction volume: ~50,000 transactions
- Daily payment value: ~$2.5M ($50 avg transaction)
- 18-hour exposure window: ~37,500 transactions potentially visible
- If attacker redirected 1% of payments: estimated loss ~$18.7K
- Additional risk: PCI-DSS compliance violations, reputational damage

---

## 2. Timeline

| Time (UTC) | Event |
|------------|-------|
| Unknown | Credentials committed to public GitHub repository |
| {leak_timestamp} | Yuno automated monitoring detects exposed credentials |
| +00:28 | SOC team alerted via emergency Slack channel |
| +01:00 | Blast radius analysis initiated |
| +01:30 | API access log analysis started (analyze_api_logs.py) |
| +02:00 | Credential rotation initiated for test environment |
| +02:30 | Credential rotation initiated for production environment |
| +03:00 | Merchant notified via secure channel |
| +04:00 | Merchant confirms new credentials deployed |
| +04:30 | Test transaction verified successful |
| +18:00 | Repository made private by merchant |
| +72:00 | Post-incident monitoring period ends |

---

## 3. Blast Radius Assessment

### Leaked Credential Types

| Credential | Environment | Risk Level | Potential Impact |
|-----------|-------------|------------|-----------------|
| Yuno API Key | Production | CRITICAL | Full API access: read/write payments, initiate refunds |
| Yuno API Key | Test | LOW | Test environment only, no real transaction data |
| Yuno API Secret | Production | CRITICAL | Request signing, can impersonate merchant |
| Webhook Secret | Production | CRITICAL | Can forge payment confirmations (mark unpaid orders as paid) |
| DB Connection String | Production | CRITICAL | Direct database access, bypasses all API controls |
| Service-to-Service Tokens | Internal | HIGH | Lateral movement between QuickEats microservices |
| Payment Routing Config | Production | HIGH | Reveals processor setup, routing logic, fee structures |
| Processor Credentials | Production | CRITICAL | Direct access to payment processors (Stripe, Adyen, etc.) |

### Environment Impact

- **Production**: All production API keys and secrets were exposed. An attacker with these
  credentials could impersonate QuickEats, access transaction data, initiate unauthorized
  refunds, forge webhook callbacks, and access the production database directly.
- **Test**: Test API keys were also exposed. While these don't access real data, they
  reveal API structure, endpoint patterns, and authentication mechanisms.
- **Database**: Production DB connection strings with embedded passwords were leaked.
  Even with network segmentation, these must be rotated immediately as an attacker
  within the network perimeter would have full database access.

---

## 4. Investigation Findings

{findings_summary if findings_summary else "_No automated analysis data available. Run analyze_api_logs.py to generate findings._"}

---

## 5. Actions Taken

### Immediate Containment
1. All leaked API keys revoked via Yuno Admin API
2. Webhook signing secrets rotated
3. Suspicious IPs blocked at API gateway
4. IP allowlisting enabled for merchant (restricted to known IPs)
5. Enhanced rate limiting activated (reduced to 10 req/min temporarily)
6. Database passwords rotated, DB access restricted to application IPs

### Remediation
1. New credentials generated and delivered via encrypted channel
2. Merchant confirmed new credentials deployed
3. Test transaction verified successful with new credentials
4. Recommended merchant implement secrets management solution

### Monitoring
1. Enhanced API monitoring active for 72 hours post-rotation
2. Alerts configured for any usage of revoked credentials
3. Geo-blocking enabled for non-US/MX traffic on merchant account

---

## 6. Forensic Evidence Preservation

The following evidence was preserved before credential rotation:

| Evidence | Description | Location |
|----------|-------------|----------|
| API access logs | Full merchant API logs for exposure window + 48h | SIEM Archive |
| Credential state | Snapshot of all credential permissions and scopes | Incident ticket |
| Repository content | Screenshots + git hash of leaked repository | Secure evidence store |
| Log analysis report | Output of analyze_api_logs.py | Attached to this report |
| Rotation audit trail | Full audit log of credential rotation steps | Attached to this report |

**Chain of Custody:** All evidence collected by {analyst_name} at {now.isoformat()}.
Evidence checksums recorded in incident management system.

---

## 7. Recommendations

### Immediate (0-7 days)
1. Complete credential rotation for all environments
2. Verify no unauthorized transactions during exposure window
3. Review and refund any fraudulent transactions
4. Mandate secrets management solution for QuickEats

### Short-term (1-4 weeks)
1. Implement pre-commit hooks for secrets scanning in QuickEats repos
2. Enable GitHub secret scanning for Yuno credential patterns
3. Conduct security training for QuickEats engineering team (8 developers)
4. Review and restrict API key scopes to minimum necessary

### Long-term (1-3 months)
1. Evaluate migration from long-lived API keys to short-lived OAuth2 tokens
2. Implement mutual TLS for webhook delivery
3. Build merchant security scoring dashboard
4. Mandate secrets scanning for all 1,000+ Yuno merchant integrations

---

## 8. Compliance Considerations

- **PCI-DSS Req 12.10.1**: This incident may require notification to the PCI QSA
  if cardholder data was potentially exposed. While Yuno tokenizes PANs, the leaked
  DB connection strings could provide access to pre-tokenization data.
- **PCI-DSS Req 12.10.5**: Include lessons learned in security awareness training.
- **GDPR/Privacy**: If EU cardholder data was accessed, 72-hour breach notification
  requirement may apply.

---

*Report generated by Yuno SOC Incident Response Automation v1.0*
*Classification: CONFIDENTIAL - Internal Use Only*
"""
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Generate incident report for credential leak")
    parser.add_argument("--merchant-id", required=True)
    parser.add_argument("--leak-timestamp", required=True)
    parser.add_argument("--analyst-name", default="SOC Analyst")
    parser.add_argument("--findings-file", help="JSON output from analyze_api_logs.py")
    parser.add_argument("--output", default="incident_report.md",
                        help="Output file path (default: incident_report.md)")
    args = parser.parse_args()

    report = generate_report(
        merchant_id=args.merchant_id,
        leak_timestamp=args.leak_timestamp,
        analyst_name=args.analyst_name,
        findings_file=args.findings_file,
    )

    with open(args.output, "w") as f:
        f.write(report)
    print(f"Incident report written to: {args.output}")


if __name__ == "__main__":
    main()
