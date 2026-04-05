"""
auth_rbac/auth_controller.py
Tejas — User registration, login, logout, and user info.
"""

from database.db import get_connection
from auth_rbac.password_utils import hash_password, verify_password, is_strong_password
from auth_rbac.session_manager import generate_token, store_session, delete_session
from config import RISK_INCREMENT_PER_FAIL, MAX_RISK_SCORE, MAX_FAILED_LOGINS_BEFORE_FLAG


def register_user(username: str, password: str, role: str = "guest", email: str = "") -> dict:
    """
    Register a new user.
    Returns: { success, message } or { success: False, error }
    """
    if role not in ("admin", "developer", "guest"):
        return {"success": False, "error": "Invalid role. Must be admin, developer, or guest."}

    valid, msg = is_strong_password(password)
    if not valid:
        return {"success": False, "error": msg}

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, email)
        )
        conn.commit()
        return {"success": True, "message": f"User '{username}' registered with role '{role}'."}
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return {"success": False, "error": "Username already exists."}
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


def login_user(username: str, password: str) -> dict:
    """
    Authenticate user.
    - Wrong password → increments risk_score, flags user after threshold
    - Correct password → generates JWT, stores session in DB
    Returns: { success, token, role, username, message }
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (username.lower(), username.lower())
        ).fetchone()

        if not row:
            return {"success": False, "error": "Invalid credentials."}

        if not verify_password(password, row["password_hash"]):
            # Track failed attempts via risk_score
            new_risk   = min(row["risk_score"] + RISK_INCREMENT_PER_FAIL, MAX_RISK_SCORE)
            is_flagged = 1 if new_risk >= MAX_FAILED_LOGINS_BEFORE_FLAG * RISK_INCREMENT_PER_FAIL \
                           else row["is_flagged"]
            conn.execute(
                "UPDATE users SET risk_score = ?, is_flagged = ? WHERE id = ?",
                (new_risk, is_flagged, row["id"])
            )
            conn.commit()
            return {"success": False, "error": "Invalid credentials."}

        token = generate_token(row["id"], row["username"], row["role"])
        store_session(token, row["id"])

        return {
            "success":  True,
            "message":  "Login successful",
            "token":    token,
            "role":     row["role"],
            "username": row["username"],
        }
    finally:
        conn.close()


def logout_user(token: str) -> dict:
    """Invalidate the session token."""
    delete_session(token)
    return {"success": True, "message": "Logged out successfully."}


def get_user_by_id(user_id: int) -> dict | None:
    """Fetch user record by ID."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id, username, role, is_flagged, risk_score FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
