"""
INTENTIONALLY INSECURE FILE FOR SECRETS SCANNER TESTING.

This file contains deliberately embedded fake secrets to demonstrate
that the Gitleaks scanner detects them. All credentials are fictional
and do not grant access to any real system.

Expected scanner output: 8+ findings across multiple secret types.
"""

# --- Yuno-specific credentials (should be caught by custom rules) ---

# Yuno production API key (CRITICAL - fake)
YUNO_API_KEY = "yuno_pk_live_8f3a9b2c4d5e6f7a8b9c0d1e2f3a4b5c"

# Yuno production API secret (CRITICAL - fake)
YUNO_API_SECRET = "yuno_sk_live_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"

# Yuno test API key
YUNO_TEST_KEY = "yuno_pk_test_2b7c3d4e5f6a7b8c9d0e1f2a3b4c5d6e"

# Yuno webhook secret (CRITICAL - fake)
WEBHOOK_SECRET = "whsec_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

# --- Database connection strings (should be caught) ---

DATABASE_URL = "postgres://quickeats_admin:SuperSecretP@ssw0rd123!@db.quickeats.internal:5432/payments"
REDIS_URL = "redis://:MyRedisPassword456@cache.quickeats.internal:6379/0"
MONGO_URI = "mongodb://admin:MongoDBSecret789@mongo.quickeats.internal:27017/orders"

# --- AWS credentials (should be caught) ---

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# --- Private key (should be caught) ---

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLGFYOX1234567890abcdefghijklmnopqrs
tuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=EXAMPLE
-----END RSA PRIVATE KEY-----"""

# --- JWT token (should be caught) ---

AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# --- Generic password assignments (should be caught) ---

config = {
    "api_key": "fake_processor_key_a1b2c3d4e5f6a7b8c9d0e1f2",
    "password": "QuickEats2024!SuperSecret",
    "secret": "d4f8a3b2c1e0f9a8b7c6d5e4f3a2b1c0",
}

# --- Processor-like key (should be caught by generic pattern) ---
PROCESSOR_KEY = "fake_processor_live_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"

# --- Password in URL (should be caught) ---
SERVICE_URL = "https://api_user:MyApiPassword123@api.internal.quickeats.com/v2"


def main():
    """This function exists only to make the file importable for testing."""
    print("WARNING: This file contains intentional fake secrets for scanner testing!")
    print(f"Found {12} embedded secrets that should be detected by Gitleaks.")


if __name__ == "__main__":
    main()
