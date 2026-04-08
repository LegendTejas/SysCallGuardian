"""
auth_rbac/password_utils.py
Password hashing and verification using bcrypt.
"""

import bcrypt


def hash_password(plain: str) -> str:
    """Hash a plaintext password. Returns UTF-8 decoded bcrypt hash string."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def is_strong_password(password: str) -> tuple[bool, str]:
    """
    Basic password strength check.
    Returns (is_valid, error_message).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, ""
