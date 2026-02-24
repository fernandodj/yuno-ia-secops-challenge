# Secrets Scanning Configuration

Automated secrets detection to prevent credential leaks before they reach public repositories.

## Components

| Component | Purpose | When it runs |
|-----------|---------|-------------|
| **Gitleaks** (gitleaks.toml) | Regex + entropy-based secret detection | Pre-commit + CI/CD |
| **Pre-commit hook** (.pre-commit-config.yaml) | Scans staged files before commit | Every `git commit` |
| **GitHub Action** (.github/workflows/secrets-scan.yml) | Scans all commits on push/PR | Every push to main/develop |

## Setup

```bash
# Install pre-commit
pip install pre-commit

# Install hooks (from repo root)
pre-commit install

# Test: run against all files
pre-commit run --all-files
```

## Demo: Scanning Test Samples

```bash
# Run Gitleaks directly against the test samples
gitleaks detect --source test-samples/ --config gitleaks.toml --verbose

# Expected output: 8+ findings across Yuno keys, DB strings, AWS creds, etc.
```

## Detection Coverage

| Secret Type | Detection Method | Example Pattern |
|-------------|-----------------|-----------------|
| Yuno API keys (prod/test) | Regex | `yuno_pk_live_*`, `yuno_sk_live_*` |
| Yuno webhook secrets | Regex | `whsec_*` |
| Database connection strings | Regex | `postgres://user:pass@host` |
| AWS credentials | Regex | `AKIA*`, `aws_secret_access_key` |
| Private keys | Regex | `-----BEGIN * PRIVATE KEY-----` |
| JWT tokens | Regex | `eyJ*.*.*` |
| Unknown high-entropy secrets | Entropy analysis | Any 32+ char hex/base64 string with Shannon entropy > 4.5 |

## False Positive Management

The `[allowlist]` section in `gitleaks.toml` excludes:
- Test files and samples
- Known placeholder patterns (`EXAMPLE_*`, `changeme`, etc.)
- The gitleaks config file itself
