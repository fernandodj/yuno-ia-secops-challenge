#!/usr/bin/env python3
"""
API Access Log Anomaly Detector for Credential Leak Incidents.

Analyzes API access logs to detect suspicious activity following a credential
leak. Identifies new IPs, geographic anomalies, volume spikes, sensitive
endpoint access, and enumeration patterns.

This is a core component of Yuno's incident response automation, designed
to be run by the SOC team immediately after a credential leak is detected.

Usage:
    python analyze_api_logs.py \\
        --log-file sample_data/sample_api_logs.jsonl \\
        --leak-timestamp 2024-01-15T03:47:00+00:00 \\
        --merchant-id merchant_quickeats_prod_001

References:
    - NIST SP 800-61r2: Computer Security Incident Handling Guide
    - PCI-DSS Req 10.6: Review logs to identify anomalies or suspicious activity
    - OWASP API Security Top 10 - API4:2023 Unrestricted Resource Consumption
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


# --- Severity Levels ---
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Endpoints that should raise alarms when accessed post-leak.
# Why: These endpoints expose configuration, credentials, or bulk data
# that an attacker would target first after obtaining API keys.
SENSITIVE_ENDPOINTS = {
    "/v1/merchants/config": CRITICAL,
    "/v1/api-keys": CRITICAL,
    "/v1/webhooks/secrets": CRITICAL,
    "/v1/transactions/export": CRITICAL,
    "/v1/payments/{id}/card-details": HIGH,
}

# Countries where QuickEats normally operates.
# Traffic from outside these countries post-leak is a strong signal.
EXPECTED_COUNTRIES = {"US", "MX"}

# User agents that are suspicious in a merchant API context.
# Why: Legitimate merchant backends use consistent, identifiable user agents.
# Generic tools suggest manual exploration or automated scanning.
SUSPICIOUS_UA_PATTERNS = [
    "curl/",
    "PostmanRuntime/",
    "python-requests/",
    "Googlebot",
    "",  # Empty user agent
]


class Finding:
    """Represents a single anomaly finding."""

    def __init__(self, severity: str, category: str, title: str, details: str,
                 evidence: list[dict] | None = None):
        self.severity = severity
        self.category = category
        self.title = title
        self.details = details
        self.evidence = evidence or []
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "details": self.details,
            "evidence_count": len(self.evidence),
            "evidence_sample": self.evidence[:5],  # Limit evidence in output
        }


class LogAnalyzer:
    """
    Analyzes API access logs for post-credential-leak anomalies.

    Detection strategies:
    1. New IP addresses not seen before the leak (behavioral baseline)
    2. Geographic anomalies (requests from unexpected countries)
    3. Volume spikes (hourly rate comparison pre vs post leak)
    4. Sensitive endpoint access (config, keys, export endpoints)
    5. Enumeration patterns (sequential IDs, pagination scanning)
    6. Unusual user agents (generic tools instead of merchant SDK)
    7. Temporal anomalies (requests during merchant's off-hours)
    """

    def __init__(self, leak_timestamp: datetime, merchant_id: str):
        self.leak_timestamp = leak_timestamp
        self.merchant_id = merchant_id
        self.pre_leak_entries: list[dict] = []
        self.post_leak_entries: list[dict] = []
        self.findings: list[Finding] = []

    def load_logs(self, log_file: str) -> int:
        """Load and partition log entries by leak timestamp."""
        total = 0
        errors = 0
        with open(log_file, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    errors += 1
                    continue

                # Filter by merchant if specified
                if entry.get("merchant_id") != self.merchant_id:
                    continue

                ts_str = entry.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    errors += 1
                    continue

                if ts < self.leak_timestamp:
                    self.pre_leak_entries.append(entry)
                else:
                    self.post_leak_entries.append(entry)
                total += 1

        if errors > 0:
            print(f"  Warning: {errors} malformed log entries skipped", file=sys.stderr)
        return total

    def analyze(self) -> list[Finding]:
        """Run all anomaly detection checks."""
        self.findings = []
        self._detect_new_ips()
        self._detect_geo_anomalies()
        self._detect_volume_spikes()
        self._detect_sensitive_endpoint_access()
        self._detect_enumeration_patterns()
        self._detect_unusual_user_agents()
        self._detect_temporal_anomalies()
        # Sort findings by severity
        severity_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 99))
        return self.findings

    def _detect_new_ips(self):
        """
        Detect IP addresses that appear post-leak but were never seen pre-leak.

        Why: A legitimate merchant's backend servers have consistent IP addresses.
        New IPs post-leak strongly suggest the leaked credentials are being used
        from unauthorized locations. This is the highest-confidence signal.
        Per NIST SP 800-61r2 Section 3.2.4: Identify indicators of compromise.
        """
        pre_ips = {e["ip_address"] for e in self.pre_leak_entries}
        post_ips = {e["ip_address"] for e in self.post_leak_entries}
        new_ips = post_ips - pre_ips

        if new_ips:
            # Gather details for each new IP
            evidence = []
            for ip in new_ips:
                ip_entries = [e for e in self.post_leak_entries if e["ip_address"] == ip]
                first_seen = min(e["timestamp"] for e in ip_entries)
                endpoints = list(set(e["endpoint"] for e in ip_entries))
                geo = ip_entries[0].get("geo_location", {})

                evidence.append({
                    "ip": ip,
                    "country": geo.get("country", "Unknown"),
                    "city": geo.get("city", "Unknown"),
                    "first_seen": first_seen,
                    "request_count": len(ip_entries),
                    "endpoints_accessed": endpoints[:10],
                })

            self.findings.append(Finding(
                severity=CRITICAL,
                category="New IP Addresses",
                title=f"{len(new_ips)} new IP(s) detected post-leak",
                details=(
                    f"IP addresses not seen in pre-leak baseline appeared after the "
                    f"credential leak. This strongly suggests unauthorized use of "
                    f"the leaked API keys from attacker infrastructure."
                ),
                evidence=evidence,
            ))

    def _detect_geo_anomalies(self):
        """
        Detect requests from countries outside the merchant's normal operating region.

        Why: QuickEats operates in US and MX. API requests from RU, CN, or NG
        are a strong indicator of credential abuse, as food delivery services
        have geographically bounded operations.
        """
        anomalous = []
        for entry in self.post_leak_entries:
            country = entry.get("geo_location", {}).get("country", "")
            if country and country not in EXPECTED_COUNTRIES:
                anomalous.append(entry)

        if anomalous:
            country_counts = Counter(
                e.get("geo_location", {}).get("country", "Unknown")
                for e in anomalous
            )
            evidence = [
                {"country": country, "request_count": count}
                for country, count in country_counts.most_common(10)
            ]

            self.findings.append(Finding(
                severity=CRITICAL,
                category="Geographic Anomaly",
                title=f"{len(anomalous)} requests from unexpected countries",
                details=(
                    f"Requests detected from countries outside QuickEats' normal "
                    f"operating region ({', '.join(EXPECTED_COUNTRIES)}). "
                    f"Countries: {dict(country_counts)}. "
                    f"This is a strong indicator of credential abuse."
                ),
                evidence=evidence,
            ))

    def _detect_volume_spikes(self):
        """
        Compare hourly request rates pre and post leak.

        Why: A sudden increase in API traffic post-leak indicates automated
        scanning or data exfiltration. We compare against the pre-leak baseline
        to account for normal traffic patterns.
        Per PCI-DSS Req 10.6.1: Review audit logs for anomalous activity.
        """
        def hourly_rates(entries: list[dict]) -> dict[str, int]:
            rates: dict[str, int] = defaultdict(int)
            for e in entries:
                try:
                    ts = datetime.fromisoformat(e["timestamp"])
                    hour_key = ts.strftime("%Y-%m-%dT%H:00")
                    rates[hour_key] += 1
                except (ValueError, KeyError):
                    continue
            return dict(rates)

        pre_rates = hourly_rates(self.pre_leak_entries)
        post_rates = hourly_rates(self.post_leak_entries)

        if not pre_rates:
            return

        avg_pre = sum(pre_rates.values()) / max(len(pre_rates), 1)
        # Flag hours where post-leak rate exceeds 3x the pre-leak average
        spike_threshold = avg_pre * 3
        spikes = {
            hour: count
            for hour, count in post_rates.items()
            if count > spike_threshold
        }

        if spikes:
            evidence = [
                {"hour": hour, "requests": count, "baseline_avg": round(avg_pre, 1)}
                for hour, count in sorted(spikes.items())
            ]
            self.findings.append(Finding(
                severity=HIGH,
                category="Volume Spike",
                title=f"{len(spikes)} hours with traffic >3x baseline",
                details=(
                    f"Pre-leak average: {avg_pre:.1f} requests/hour. "
                    f"Post-leak spikes detected up to "
                    f"{max(spikes.values())} requests/hour. "
                    f"This may indicate automated scanning or data exfiltration."
                ),
                evidence=evidence,
            ))

    def _detect_sensitive_endpoint_access(self):
        """
        Detect access to sensitive endpoints post-leak.

        Why: An attacker with leaked API keys will first attempt to:
        1. Read merchant configuration (/merchants/config) to understand the target
        2. Export transaction data (/transactions/export) for financial fraud
        3. Access API key management (/api-keys) to create persistent backdoor access
        4. Read webhook secrets (/webhooks/secrets) to forge payment confirmations
        These endpoints are rarely accessed in normal operations.
        """
        for entry in self.post_leak_entries:
            endpoint = entry.get("endpoint", "")
            for sensitive_path, severity in SENSITIVE_ENDPOINTS.items():
                # Match both exact and parameterized endpoints
                pattern = sensitive_path.replace("{id}", "")
                if pattern in endpoint:
                    self.findings.append(Finding(
                        severity=severity,
                        category="Sensitive Endpoint Access",
                        title=f"Access to {sensitive_path}",
                        details=(
                            f"IP {entry.get('ip_address')} accessed sensitive endpoint "
                            f"{endpoint} at {entry.get('timestamp')}. "
                            f"Status: {entry.get('status_code')}. "
                            f"This endpoint exposes {self._endpoint_risk(sensitive_path)}."
                        ),
                        evidence=[{
                            "ip": entry.get("ip_address"),
                            "timestamp": entry.get("timestamp"),
                            "endpoint": endpoint,
                            "status_code": entry.get("status_code"),
                            "user_agent": entry.get("user_agent"),
                        }],
                    ))

    def _endpoint_risk(self, endpoint: str) -> str:
        """Return human-readable risk description for sensitive endpoints."""
        risks = {
            "/v1/merchants/config": "merchant configuration and payment routing logic",
            "/v1/api-keys": "API key management (attacker could create backdoor keys)",
            "/v1/webhooks/secrets": "webhook signing secrets (enables webhook forgery)",
            "/v1/transactions/export": "bulk transaction data (financial and PII exposure)",
            "/v1/payments/{id}/card-details": "tokenized card details (aids fraud)",
        }
        return risks.get(endpoint, "sensitive merchant data")

    def _detect_enumeration_patterns(self):
        """
        Detect sequential or paginated scanning of resources.

        Why: Attackers enumerate resources by iterating through sequential IDs
        or paginating through list endpoints. Normal merchant traffic accesses
        specific known resource IDs; scanning accesses many resources rapidly.
        Per OWASP API4:2023 - Unrestricted Resource Consumption.
        """
        # Detect pagination scanning (page=1, page=2, ...)
        pagination_entries = [
            e for e in self.post_leak_entries
            if "page=" in e.get("endpoint", "")
        ]

        if len(pagination_entries) > 3:
            ips = list(set(e["ip_address"] for e in pagination_entries))
            self.findings.append(Finding(
                severity=HIGH,
                category="Enumeration Pattern",
                title=f"Pagination scanning detected ({len(pagination_entries)} requests)",
                details=(
                    f"Sequential pagination detected across {len(pagination_entries)} "
                    f"requests from IPs: {ips}. This pattern indicates systematic "
                    f"data exfiltration or resource enumeration."
                ),
                evidence=[{
                    "ip": e["ip_address"],
                    "endpoint": e["endpoint"],
                    "timestamp": e["timestamp"],
                } for e in pagination_entries[:10]],
            ))

        # Detect rapid successive requests to same endpoint pattern from same IP
        ip_endpoint_times: dict[str, list[str]] = defaultdict(list)
        for e in self.post_leak_entries:
            key = f"{e['ip_address']}:{e['endpoint'].split('?')[0].rsplit('/', 1)[0]}"
            ip_endpoint_times[key].append(e["timestamp"])

        for key, timestamps in ip_endpoint_times.items():
            if len(timestamps) > 15:  # More than 15 requests to same endpoint pattern
                ip = key.split(":")[0]
                endpoint_pattern = key.split(":", 1)[1]
                # Only flag IPs not seen in the pre-leak baseline (dynamic, not hardcoded)
                pre_ips = {e["ip_address"] for e in self.pre_leak_entries}
                if ip not in pre_ips:
                    self.findings.append(Finding(
                        severity=MEDIUM,
                        category="Enumeration Pattern",
                        title=f"Rapid endpoint scanning from {ip}",
                        details=(
                            f"IP {ip} made {len(timestamps)} requests to "
                            f"{endpoint_pattern}/* pattern. This exceeds normal "
                            f"merchant access patterns and suggests automated scanning."
                        ),
                    ))

    def _detect_unusual_user_agents(self):
        """
        Detect requests with suspicious user agent strings.

        Why: QuickEats' legitimate backend uses consistent, identifiable user
        agents (e.g., "QuickEats-Backend/2.1.4"). Requests from generic tools
        like curl, Postman, or python-requests suggest manual exploration by
        an attacker who obtained the credentials but doesn't have the merchant's
        actual codebase. Empty user agents are also suspicious.
        """
        suspicious = []
        for entry in self.post_leak_entries:
            ua = entry.get("user_agent", "")
            for pattern in SUSPICIOUS_UA_PATTERNS:
                if pattern == "" and ua == "":
                    suspicious.append(entry)
                    break
                elif pattern and pattern in ua:
                    suspicious.append(entry)
                    break

        if suspicious:
            ua_counts = Counter(e.get("user_agent", "(empty)") or "(empty)" for e in suspicious)
            evidence = [
                {"user_agent": ua, "count": count}
                for ua, count in ua_counts.most_common(10)
            ]

            self.findings.append(Finding(
                severity=MEDIUM,
                category="Unusual User Agent",
                title=f"{len(suspicious)} requests with suspicious user agents",
                details=(
                    f"Requests detected using generic tools instead of QuickEats' "
                    f"expected SDK. User agents: {dict(ua_counts)}. "
                    f"This suggests manual API exploration or automated scanning tools."
                ),
                evidence=evidence,
            ))

    def _detect_temporal_anomalies(self):
        """
        Detect requests during unusual hours for the merchant.

        Why: QuickEats is a food delivery service with predictable traffic
        patterns (lunch/dinner peaks). Significant API activity during
        off-hours (e.g., 4-10 AM UTC / 8PM-2AM PST) from new IPs is
        suspicious, especially if combined with other indicators.
        """
        pre_ips = {e["ip_address"] for e in self.pre_leak_entries}
        off_hours_new_ip = []

        for entry in self.post_leak_entries:
            if entry["ip_address"] in pre_ips:
                continue  # Known IP, skip
            try:
                ts = datetime.fromisoformat(entry["timestamp"])
                # QuickEats low-traffic hours: 4-10 UTC (8PM-2AM PST)
                if 4 <= ts.hour <= 10:
                    off_hours_new_ip.append(entry)
            except (ValueError, KeyError):
                continue

        if off_hours_new_ip:
            self.findings.append(Finding(
                severity=MEDIUM,
                category="Temporal Anomaly",
                title=f"{len(off_hours_new_ip)} off-hours requests from new IPs",
                details=(
                    f"Requests from previously unseen IPs during QuickEats' "
                    f"typical low-traffic hours (04:00-10:00 UTC). Combined with "
                    f"new IP addresses, this strengthens the case for unauthorized access."
                ),
                evidence=[{
                    "ip": e["ip_address"],
                    "timestamp": e["timestamp"],
                    "endpoint": e["endpoint"],
                } for e in off_hours_new_ip[:10]],
            ))

    def generate_report(self) -> dict[str, Any]:
        """Generate a structured analysis report."""
        # Suspicious IPs summary
        pre_ips = {e["ip_address"] for e in self.pre_leak_entries}
        suspicious_ips: dict[str, dict] = {}
        for entry in self.post_leak_entries:
            ip = entry["ip_address"]
            if ip not in pre_ips:
                if ip not in suspicious_ips:
                    geo = entry.get("geo_location", {})
                    suspicious_ips[ip] = {
                        "ip": ip,
                        "country": geo.get("country", "Unknown"),
                        "city": geo.get("city", "Unknown"),
                        "first_seen": entry["timestamp"],
                        "last_seen": entry["timestamp"],
                        "request_count": 0,
                        "endpoints": set(),
                        "status_codes": [],
                    }
                suspicious_ips[ip]["last_seen"] = entry["timestamp"]
                suspicious_ips[ip]["request_count"] += 1
                suspicious_ips[ip]["endpoints"].add(entry.get("endpoint", ""))
                suspicious_ips[ip]["status_codes"].append(entry.get("status_code"))

        # Convert sets to lists for JSON serialization
        for ip_data in suspicious_ips.values():
            ip_data["endpoints"] = list(ip_data["endpoints"])
            ip_data["status_codes"] = dict(Counter(ip_data["status_codes"]))

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "analyzer_version": "1.0.0",
                "merchant_id": self.merchant_id,
                "leak_timestamp": self.leak_timestamp.isoformat(),
            },
            "summary": {
                "total_entries_analyzed": len(self.pre_leak_entries) + len(self.post_leak_entries),
                "pre_leak_entries": len(self.pre_leak_entries),
                "post_leak_entries": len(self.post_leak_entries),
                "pre_leak_unique_ips": len({e["ip_address"] for e in self.pre_leak_entries}),
                "post_leak_unique_ips": len({e["ip_address"] for e in self.post_leak_entries}),
                "new_ips_post_leak": len(suspicious_ips),
                "total_findings": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f.severity == CRITICAL),
                "high_findings": sum(1 for f in self.findings if f.severity == HIGH),
                "medium_findings": sum(1 for f in self.findings if f.severity == MEDIUM),
                "low_findings": sum(1 for f in self.findings if f.severity == LOW),
            },
            "findings": [f.to_dict() for f in self.findings],
            "suspicious_ips": list(suspicious_ips.values()),
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> list[dict[str, str]]:
        """Generate actionable recommendations based on findings."""
        recs = []

        critical_count = sum(1 for f in self.findings if f.severity == CRITICAL)
        if critical_count > 0:
            recs.append({
                "priority": "IMMEDIATE",
                "action": "Revoke all leaked API keys and webhook secrets",
                "reason": f"{critical_count} critical findings detected. Credentials are actively being abused.",
            })
            recs.append({
                "priority": "IMMEDIATE",
                "action": "Enable IP allowlisting for this merchant",
                "reason": "Restrict API access to known merchant IPs only.",
            })

        new_ips = [f for f in self.findings if f.category == "New IP Addresses"]
        if new_ips:
            recs.append({
                "priority": "IMMEDIATE",
                "action": "Block suspicious IPs at WAF/API gateway level",
                "reason": "New IPs detected post-leak indicate unauthorized access.",
            })

        geo = [f for f in self.findings if f.category == "Geographic Anomaly"]
        if geo:
            recs.append({
                "priority": "HIGH",
                "action": "Implement geo-blocking for merchant API access",
                "reason": "Requests from unexpected countries detected.",
            })

        sensitive = [f for f in self.findings if f.category == "Sensitive Endpoint Access"]
        if sensitive:
            recs.append({
                "priority": "HIGH",
                "action": "Audit all data accessed via sensitive endpoints during exposure window",
                "reason": "Attacker may have exfiltrated merchant configuration or transaction data.",
            })
            recs.append({
                "priority": "HIGH",
                "action": "Review transaction data for unauthorized refunds or modifications",
                "reason": "Sensitive endpoint access may indicate financial fraud attempts.",
            })

        # Always recommend these post-incident
        recs.append({
            "priority": "MEDIUM",
            "action": "Rotate database connection strings and restrict to application IPs",
            "reason": "DB credentials were part of the leak. Even if not used, they must be rotated.",
        })
        recs.append({
            "priority": "MEDIUM",
            "action": "Mandate secrets management solution for the merchant",
            "reason": "Prevent future credential leaks by eliminating hardcoded secrets.",
        })
        recs.append({
            "priority": "LOW",
            "action": "Monitor merchant API activity for 72 hours post-remediation",
            "reason": "Attacker may have created persistent access or backdoor credentials.",
        })

        return recs


def format_report_text(report: dict) -> str:
    """Format the analysis report for human-readable console output."""
    lines = []
    lines.append("=" * 72)
    lines.append("  YUNO SOC — API ACCESS LOG ANOMALY ANALYSIS REPORT")
    lines.append("=" * 72)
    lines.append("")

    meta = report["report_metadata"]
    lines.append(f"  Generated:    {meta['generated_at']}")
    lines.append(f"  Merchant:     {meta['merchant_id']}")
    lines.append(f"  Leak Time:    {meta['leak_timestamp']}")
    lines.append("")

    # Summary
    s = report["summary"]
    lines.append("─" * 72)
    lines.append("  SUMMARY")
    lines.append("─" * 72)
    lines.append(f"  Total entries analyzed:  {s['total_entries_analyzed']}")
    lines.append(f"  Pre-leak entries:        {s['pre_leak_entries']}")
    lines.append(f"  Post-leak entries:       {s['post_leak_entries']}")
    lines.append(f"  Pre-leak unique IPs:     {s['pre_leak_unique_ips']}")
    lines.append(f"  Post-leak unique IPs:    {s['post_leak_unique_ips']}")
    lines.append(f"  NEW IPs post-leak:       {s['new_ips_post_leak']}")
    lines.append("")
    lines.append(f"  Findings:  {s['critical_findings']} CRITICAL | "
                 f"{s['high_findings']} HIGH | {s['medium_findings']} MEDIUM | "
                 f"{s['low_findings']} LOW")
    lines.append("")

    # Findings
    lines.append("─" * 72)
    lines.append("  FINDINGS")
    lines.append("─" * 72)
    for i, finding in enumerate(report["findings"], 1):
        sev = finding["severity"]
        marker = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "."}
        lines.append(f"\n  [{marker.get(sev, '?')}] #{i} [{sev}] {finding['title']}")
        lines.append(f"      Category: {finding['category']}")
        lines.append(f"      {finding['details']}")
        if finding.get("evidence_sample"):
            lines.append(f"      Evidence ({finding['evidence_count']} items):")
            for ev in finding["evidence_sample"]:
                lines.append(f"        - {json.dumps(ev, default=str)}")
    lines.append("")

    # Suspicious IPs
    lines.append("─" * 72)
    lines.append("  SUSPICIOUS IP ADDRESSES")
    lines.append("─" * 72)
    for ip_data in report.get("suspicious_ips", []):
        lines.append(f"\n  IP: {ip_data['ip']} ({ip_data['country']}/{ip_data['city']})")
        lines.append(f"    First seen:    {ip_data['first_seen']}")
        lines.append(f"    Last seen:     {ip_data['last_seen']}")
        lines.append(f"    Requests:      {ip_data['request_count']}")
        lines.append(f"    Endpoints:     {', '.join(ip_data['endpoints'][:5])}")
        lines.append(f"    Status codes:  {ip_data['status_codes']}")
    lines.append("")

    # Recommendations
    lines.append("─" * 72)
    lines.append("  RECOMMENDATIONS")
    lines.append("─" * 72)
    for rec in report.get("recommendations", []):
        lines.append(f"\n  [{rec['priority']}] {rec['action']}")
        lines.append(f"    Reason: {rec['reason']}")
    lines.append("")
    lines.append("=" * 72)
    lines.append("  END OF REPORT")
    lines.append("=" * 72)

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze API access logs for anomalies following a credential leak",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-file logs.jsonl --leak-timestamp 2024-01-15T03:47:00+00:00 --merchant-id merchant_quickeats_prod_001
  %(prog)s --log-file logs.jsonl --leak-timestamp 2024-01-15T03:47:00+00:00 --merchant-id merchant_quickeats_prod_001 --output-json report.json
        """,
    )
    parser.add_argument(
        "--log-file", required=True,
        help="Path to JSONL log file",
    )
    parser.add_argument(
        "--leak-timestamp", required=True,
        help="ISO 8601 timestamp of the credential leak (e.g., 2024-01-15T03:47:00+00:00)",
    )
    parser.add_argument(
        "--merchant-id", required=True,
        help="Merchant ID to analyze",
    )
    parser.add_argument(
        "--output-json",
        help="Optional: write JSON report to file",
    )
    args = parser.parse_args()

    # Parse leak timestamp
    try:
        leak_ts = datetime.fromisoformat(args.leak_timestamp)
        if leak_ts.tzinfo is None:
            leak_ts = leak_ts.replace(tzinfo=timezone.utc)
    except ValueError:
        print(f"Error: Invalid timestamp format: {args.leak_timestamp}", file=sys.stderr)
        sys.exit(1)

    # Initialize and run analysis
    analyzer = LogAnalyzer(leak_ts, args.merchant_id)

    print(f"\nLoading logs from {args.log_file}...")
    total = analyzer.load_logs(args.log_file)
    print(f"  Loaded {total} entries for merchant {args.merchant_id}")
    print(f"  Pre-leak: {len(analyzer.pre_leak_entries)} | Post-leak: {len(analyzer.post_leak_entries)}")

    print("\nRunning anomaly detection...")
    findings = analyzer.analyze()
    print(f"  Detected {len(findings)} findings\n")

    # Generate and output report
    report = analyzer.generate_report()
    print(format_report_text(report))

    # Optionally write JSON report
    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\nJSON report written to: {args.output_json}")

    # Exit code based on severity
    if report["summary"]["critical_findings"] > 0:
        sys.exit(2)  # Critical findings
    elif report["summary"]["high_findings"] > 0:
        sys.exit(1)  # High findings
    sys.exit(0)


if __name__ == "__main__":
    main()
