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

## Sample Scanner Output

```
$ gitleaks detect --source test-samples/ --config gitleaks.toml --verbose --no-git

Finding:     YUNO_API_KEY = "yuno_pk_live_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c"
Secret:      yuno_pk_live_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c
RuleID:      yuno-api-key-live
File:        test-samples/fake_secrets.py:14
Tags:        [yuno, api-key, production, critical]

Finding:     YUNO_API_SECRET = "yuno_sk_live_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
Secret:      yuno_sk_live_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
RuleID:      yuno-api-secret-live
File:        test-samples/fake_secrets.py:17
Tags:        [yuno, api-secret, production, critical]

Finding:     WEBHOOK_SECRET = "whsec_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
Secret:      whsec_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
RuleID:      yuno-webhook-secret
File:        test-samples/fake_secrets.py:23
Tags:        [yuno, webhook, critical]

Finding:     DATABASE_URL = "postgres://quickeats_admin:SuperSecretP@ssw0rd123!@..."
RuleID:      database-connection-string
File:        test-samples/fake_secrets.py:27
Tags:        [database, credential, critical]

Finding:     AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
RuleID:      aws-access-key
File:        test-samples/fake_secrets.py:33
Tags:        [aws, access-key]

...

12 findings detected. 5 CRITICAL, 4 HIGH, 3 MEDIUM.
```

## False Positive Management

The `[allowlist]` section in `gitleaks.toml` excludes:
- Test files and samples
- Known placeholder patterns (`EXAMPLE_*`, `changeme`, etc.)
- The gitleaks config file itself
