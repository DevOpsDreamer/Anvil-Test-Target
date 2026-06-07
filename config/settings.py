"""
Application configuration.
VULNERABLE: Hardcoded credentials (CWE-798)
"""

# VULNERABLE: Hardcoded database credentials
DATABASE_URL = "postgresql://admin:super_secret_db_password_123@localhost:5432/appdb"

# VULNERABLE: Hardcoded API keys
STRIPE_SECRET_KEY = "sk_live_hardcoded_stripe_key_abc123def456"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# VULNERABLE: Hardcoded JWT secret
JWT_SECRET = "my_super_secret_jwt_key_never_change_this"

# VULNERABLE: Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin_password_never_change"

# VULNERABLE: Hardcoded encryption key
ENCRYPTION_KEY = "hardcoded_aes_key_256bit_value_here"

# These look like secrets but are not real (safe — for comparison)
PLACEHOLDER_KEY = "your-api-key-here"
EXAMPLE_SECRET = "change-me-in-production"
