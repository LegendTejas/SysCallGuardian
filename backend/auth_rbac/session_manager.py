"""
auth_rbac/session_manager.py
Tejas — JWT generation, verification, and DB session lifecycle.
"""

import jwt
import uuid
from datetime import datetime, timedelta, timezone

from database.db import get_connection
from config import JWT_SECRET, JWT_ALGORITHM, TOKEN_EXPIRY_H


# ── JWT ───────────────────────────────────────────────────────────────────────

def generate_token(user_id: int, username: str, role: str) -> str:
    """Generate a signed JWT with user identity, expiry, and unique jti."""
    expiry = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_H)
    payload = {
        "user_id":  user_id,
        "username": username,
        "role":     role,
        "exp":      expiry,
        "iat":      datetime.now(timezone.utc),
        "jti":      str(uuid.uuid4()),   # unique token ID — prevents replay attacks
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict | None:
    """
    Decode and verify a JWT signature and expiry.
    Returns payload dict or None on any failure.
    """
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ── Session DB ────────────────────────────────────────────────────────────────

def store_session(token: str, user_id: int):
    """Persist session token in DB with expiry timestamp."""
    expires_at = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRY_H)
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (token, user_id, expires_at.isoformat())
        )
        conn.commit()
    finally:
        conn.close()


def validate_session(token: str) -> dict:
    """
    Full session validation:
      1. Verify JWT signature + expiry
      2. Check session exists in DB (not logged out)
      3. Check DB expiry hasn't passed

    Returns: { valid, user_id, username, role } or { valid: False, error }
    """
    payload = decode_token(token)
    if not payload:
        return {"valid": False, "error": "Invalid or expired token."}

    conn = get_connection()
    try:
        session = conn.execute(
            "SELECT * FROM sessions WHERE token = ?", (token,)
        ).fetchone()

        if not session:
            return {"valid": False, "error": "Session not found. Please log in again."}

        expires_at = datetime.fromisoformat(session["expires_at"])
        if datetime.now(timezone.utc) > expires_at.replace(tzinfo=timezone.utc):
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            return {"valid": False, "error": "Session expired. Please log in again."}

        return {
            "valid":    True,
            "user_id":  payload["user_id"],
            "username": payload["username"],
            "role":     payload["role"],
        }
    finally:
        conn.close()


def delete_session(token: str):
    """Remove session from DB on logout."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
    finally:
        conn.close()