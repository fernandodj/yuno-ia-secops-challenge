#!/usr/bin/env python3
"""
Generate Sample API Access Logs for Incident Response Testing.

Produces realistic API access logs simulating both normal merchant traffic
and malicious post-leak activity for QuickEats (food delivery platform).

Usage:
    python generate_sample_logs.py --output sample_api_logs.jsonl
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timedelta, timezone

# --- Constants ---
LEAK_TIMESTAMP = datetime(2024, 1, 15, 3, 47, 0, tzinfo=timezone.utc)
MERCHANT_ID = "merchant_quickeats_prod_001"
API_KEY_PREFIX_PROD = "yuno_pk_live_8f3a"
API_KEY_PREFIX_TEST = "yuno_pk_test_2b7c"

# Normal QuickEats traffic patterns
NORMAL_IPS = [
    ("198.51.100.10", "US", "San Francisco"),
    ("198.51.100.11", "US", "San Francisco"),
    ("198.51.100.20", "US", "New York"),
    ("203.0.113.50", "MX", "Mexico City"),
    ("203.0.113.51", "MX", "Mexico City"),
]

NORMAL_ENDPOINTS = [
    ("POST", "/v1/payments", 60),        # Most common: create payment
    ("GET", "/v1/payments/{id}", 25),     # Check payment status
    ("POST", "/v1/refunds", 8),           # Occasional refunds
    ("GET", "/v1/refunds/{id}", 5),       # Check refund status
    ("GET", "/v1/health", 2),             # Health checks
]

NORMAL_USER_AGENTS = [
    "QuickEats-Backend/2.1.4 (Python/3.11; httpx/0.25.0)",
    "QuickEats-Backend/2.1.4 (Python/3.11; httpx/0.25.0)",
    "QuickEats-Worker/1.0.2 (Python/3.11; requests/2.31.0)",
]

# Malicious post-leak traffic patterns
MALICIOUS_IPS = [
    ("45.227.255.100", "RU", "Moscow"),
    ("103.152.220.44", "CN", "Shanghai"),
    ("41.190.3.22", "NG", "Lagos"),
    ("185.220.101.33", "DE", "Frankfurt"),  # Known Tor exit node pattern
    ("23.129.64.15", "US", "Unknown"),      # Tor exit node
]

SENSITIVE_ENDPOINTS = [
    ("GET", "/v1/merchants/config", 15),
    ("GET", "/v1/transactions/export", 20),
    ("GET", "/v1/api-keys", 10),
    ("GET", "/v1/webhooks/secrets", 10),
    ("GET", "/v1/payments/{id}/card-details", 15),
    ("POST", "/v1/refunds", 10),            # Unauthorized refund attempts
    ("GET", "/v1/payments", 20),             # Bulk enumeration
]

MALICIOUS_USER_AGENTS = [
    "python-requests/2.28.0",
    "curl/7.88.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",  # Disguised as bot
    "PostmanRuntime/7.32.3",
    "",  # Empty user agent
]


def generate_normal_entry(timestamp: datetime) -> dict:
    """Generate a single normal API access log entry."""
    ip, country, city = random.choice(NORMAL_IPS)
    method, endpoint, _ = random.choices(
        NORMAL_ENDPOINTS, weights=[e[2] for e in NORMAL_ENDPOINTS]
    )[0]

    # Replace {id} with realistic payment/refund IDs
    if "{id}" in endpoint:
        endpoint = endpoint.replace("{id}", f"pay_{uuid.uuid4().hex[:16]}")

    status = random.choices([200, 201, 400, 404, 500], weights=[70, 15, 8, 5, 2])[0]
    if method == "POST" and status == 200:
        status = 201

    return {
        "timestamp": timestamp.isoformat(),
        "merchant_id": MERCHANT_ID,
        "api_key_prefix": API_KEY_PREFIX_PROD,
        "ip_address": ip,
        "geo_location": {"country": country, "city": city},
        "endpoint": endpoint,
        "method": method,
        "status_code": status,
        "response_time_ms": random.randint(50, 350),
        "user_agent": random.choice(NORMAL_USER_AGENTS),
        "request_id": f"req_{uuid.uuid4().hex[:24]}",
    }


def generate_malicious_entry(timestamp: datetime) -> dict:
    """Generate a single malicious/suspicious API access log entry."""
    ip, country, city = random.choice(MALICIOUS_IPS)
    method, endpoint, _ = random.choices(
        SENSITIVE_ENDPOINTS, weights=[e[2] for e in SENSITIVE_ENDPOINTS]
    )[0]

    if "{id}" in endpoint:
        # Sequential enumeration pattern: predictable IDs
        endpoint = endpoint.replace("{id}", f"pay_{random.randint(1000, 9999):04d}")

    # Attackers often hit valid endpoints but with unusual patterns
    status = random.choices([200, 401, 403, 404, 429], weights=[40, 20, 15, 15, 10])[0]

    return {
        "timestamp": timestamp.isoformat(),
        "merchant_id": MERCHANT_ID,
        "api_key_prefix": random.choice([API_KEY_PREFIX_PROD, API_KEY_PREFIX_TEST]),
        "ip_address": ip,
        "geo_location": {"country": country, "city": city},
        "endpoint": endpoint,
        "method": method,
        "status_code": status,
        "response_time_ms": random.randint(20, 800),
        "user_agent": random.choice(MALICIOUS_USER_AGENTS),
        "request_id": f"req_{uuid.uuid4().hex[:24]}",
    }


def generate_logs(num_entries: int = 500) -> list[dict]:
    """
    Generate a mix of normal and malicious API access logs.

    Normal traffic: 24 hours before the leak, following business-hour patterns.
    Post-leak traffic: 18 hours after the leak, with interspersed malicious requests.
    """
    entries = []
    random.seed(42)  # Reproducible output for demo

    # --- Pre-leak normal traffic (24h before leak) ---
    pre_leak_start = LEAK_TIMESTAMP - timedelta(hours=24)
    pre_leak_count = int(num_entries * 0.45)

    for i in range(pre_leak_count):
        # Higher traffic during business hours (14:00-02:00 UTC = 6AM-6PM PST)
        offset_hours = random.uniform(0, 24)
        ts = pre_leak_start + timedelta(hours=offset_hours)
        hour = ts.hour

        # Simulate business-hour weighting (food delivery peaks at lunch/dinner)
        if 17 <= hour <= 23 or 0 <= hour <= 3:  # Peak: lunch/dinner US time
            if random.random() > 0.3:
                entries.append(generate_normal_entry(ts))
        elif 14 <= hour <= 17:  # Moderate
            if random.random() > 0.5:
                entries.append(generate_normal_entry(ts))
        else:  # Low traffic
            if random.random() > 0.8:
                entries.append(generate_normal_entry(ts))

    # Pad to target count if needed
    while len(entries) < pre_leak_count:
        offset = random.uniform(0, 24)
        ts = pre_leak_start + timedelta(hours=offset)
        entries.append(generate_normal_entry(ts))

    # --- Post-leak traffic (18h after leak) ---
    post_leak_count = num_entries - pre_leak_count
    normal_post = int(post_leak_count * 0.55)  # Normal traffic continues
    malicious_post = post_leak_count - normal_post  # ~45% malicious

    # Normal post-leak traffic
    for _ in range(normal_post):
        offset = random.uniform(0, 18)
        ts = LEAK_TIMESTAMP + timedelta(hours=offset)
        entries.append(generate_normal_entry(ts))

    # Malicious post-leak traffic (starts ~2h after leak as attacker discovers creds)
    for i in range(malicious_post):
        # Malicious traffic ramps up over time
        min_offset = 1.5  # First malicious activity ~1.5h after leak
        offset = min_offset + random.uniform(0, 16.5)
        ts = LEAK_TIMESTAMP + timedelta(hours=offset)

        entry = generate_malicious_entry(ts)

        # Add enumeration pattern: some attackers scan sequentially
        if i % 8 == 0 and i > 0:
            entry["endpoint"] = f"/v1/payments?page={i // 8}&limit=100"
            entry["method"] = "GET"

        entries.append(entry)

    # Sort by timestamp
    entries.sort(key=lambda x: x["timestamp"])
    return entries


def main():
    parser = argparse.ArgumentParser(
        description="Generate sample API access logs for incident response testing"
    )
    parser.add_argument(
        "--output",
        default="incident-response/sample_data/sample_api_logs.jsonl",
        help="Output file path (default: sample_api_logs.jsonl)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=500,
        help="Number of log entries to generate (default: 500)",
    )
    args = parser.parse_args()

    entries = generate_logs(args.count)

    with open(args.output, "w") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")

    # Summary
    pre_leak = sum(1 for e in entries if e["timestamp"] < LEAK_TIMESTAMP.isoformat())
    post_leak = len(entries) - pre_leak
    print(f"Generated {len(entries)} log entries → {args.output}")
    print(f"  Pre-leak:  {pre_leak} entries (normal traffic)")
    print(f"  Post-leak: {post_leak} entries (normal + malicious)")
    print(f"  Leak timestamp: {LEAK_TIMESTAMP.isoformat()}")


if __name__ == "__main__":
    main()
