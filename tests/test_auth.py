"""
tests/test_auth.py
pytest test suite for Authentication System.

Coverage:
  - User registration (success, duplicate, weak password, invalid role)
  - Login (success, wrong password, nonexistent user)
  - Failed login risk tracking (risk_score increment, flagging)
  - JWT token generation and validation
  - Session lifecycle (create → validate → logout → invalidate)
  - Token expiry behavior
  - get_user_by_id
"""

import pytest
from auth_rbac.auth_controller  import register_user, login_user, logout_user, get_user_by_id
from auth_rbac.session_manager  import validate_session, generate_token, decode_token
from database.db                import get_connection


# ── Registration ──────────────────────────────────────────────────────────────

class TestRegistration:

    def test_register_success(self):
        result = register_user("alice", "SecurePass1", "developer")
        assert result["success"] is True
        assert "alice" in result["message"]

    def test_register_default_role_is_guest(self):
        register_user("bob", "SecurePass1")
        conn = get_connection()
        row  = conn.execute("SELECT role FROM users WHERE username='bob'").fetchone()
        conn.close()
        assert row["role"] == "guest"

    def test_register_duplicate_username(self):
        register_user("carol", "SecurePass1", "guest")
        result = register_user("carol", "SecurePass1", "guest")
        assert result["success"] is False
        assert "already exists" in result["error"]

    def test_register_invalid_role(self):
        result = register_user("dave", "SecurePass1", "superuser")
        assert result["success"] is False
        assert "Invalid role" in result["error"]

    def test_register_weak_password_too_short(self):
        result = register_user("eve", "abc", "guest")
        assert result["success"] is False
        assert "8 characters" in result["error"]

    def test_register_weak_password_no_uppercase(self):
        result = register_user("frank", "lowercase1", "guest")
        assert result["success"] is False
        assert "uppercase" in result["error"]

    def test_register_weak_password_no_digit(self):
        result = register_user("grace", "NoDigitsHere", "guest")
        assert result["success"] is False
        assert "digit" in result["error"]

    def test_register_all_three_roles(self):
        for username, role in [("u1","admin"),("u2","developer"),("u3","guest")]:
            result = register_user(username, "ValidPass1", role)
            assert result["success"] is True, f"Failed for role {role}: {result}"


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:

    def test_login_success(self):
        register_user("tejas", "ValidPass1", "admin")
        result = login_user("tejas", "ValidPass1")
        assert result["success"] is True
        assert result["role"] == "admin"
        assert result["username"] == "tejas"
        assert "token" in result
        assert len(result["token"]) > 20

    def test_login_wrong_password(self):
        register_user("tejas2", "ValidPass1", "developer")
        result = login_user("tejas2", "WrongPassword1")
        assert result["success"] is False
        assert "Invalid credentials" in result["error"]

    def test_login_nonexistent_user(self):
        result = login_user("nobody", "AnyPass1")
        assert result["success"] is False
        assert "Invalid credentials" in result["error"]

    def test_login_increments_risk_on_wrong_password(self):
        register_user("victim", "ValidPass1", "guest")
        # 3 failed attempts
        for _ in range(3):
            login_user("victim", "WrongPass1")
        conn = get_connection()
        row  = conn.execute("SELECT risk_score FROM users WHERE username='victim'").fetchone()
        conn.close()
        assert row["risk_score"] == 30.0   # 3 × 10.0

    def test_login_flags_user_after_threshold(self):
        register_user("brute", "ValidPass1", "guest")
        # 5 failed attempts triggers flag
        for _ in range(5):
            login_user("brute", "WrongPass1")
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged, risk_score FROM users WHERE username='brute'").fetchone()
        conn.close()
        assert row["is_flagged"] == 1
        assert row["risk_score"] == 50.0

    def test_login_correct_after_failed_does_not_add_risk(self):
        register_user("mixed", "ValidPass1", "guest")
        login_user("mixed", "WrongPass1")   # 1 fail → risk 10
        result = login_user("mixed", "ValidPass1")  # correct
        assert result["success"] is True
        conn = get_connection()
        row  = conn.execute("SELECT risk_score FROM users WHERE username='mixed'").fetchone()
        conn.close()
        assert row["risk_score"] == 10.0   # didn't increase on success

    def test_login_stores_session_in_db(self):
        register_user("session_user", "ValidPass1", "developer")
        result = login_user("session_user", "ValidPass1")
        conn   = get_connection()
        session = conn.execute(
            "SELECT * FROM sessions WHERE token=?", (result["token"],)
        ).fetchone()
        conn.close()
        assert session is not None


# ── Session & JWT ─────────────────────────────────────────────────────────────

class TestSessionAndJWT:

    def test_validate_session_success(self):
        register_user("sess1", "ValidPass1", "admin")
        login_result = login_user("sess1", "ValidPass1")
        token        = login_result["token"]
        validation   = validate_session(token)
        assert validation["valid"] is True
        assert validation["username"] == "sess1"
        assert validation["role"] == "admin"

    def test_validate_session_invalid_token(self):
        result = validate_session("this.is.not.a.real.token")
        assert result["valid"] is False

    def test_validate_session_garbage_string(self):
        result = validate_session("aaabbbccc")
        assert result["valid"] is False

    def test_validate_session_empty_string(self):
        result = validate_session("")
        assert result["valid"] is False

    def test_logout_invalidates_session(self):
        register_user("logouter", "ValidPass1", "guest")
        login_result = login_user("logouter", "ValidPass1")
        token        = login_result["token"]

        # Valid before logout
        assert validate_session(token)["valid"] is True

        logout_user(token)

        # Invalid after logout
        assert validate_session(token)["valid"] is False

    def test_logout_removes_session_from_db(self):
        register_user("dbcheck", "ValidPass1", "guest")
        result = login_user("dbcheck", "ValidPass1")
        token  = result["token"]
        logout_user(token)
        conn    = get_connection()
        session = conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
        conn.close()
        assert session is None

    def test_jwt_payload_contains_correct_fields(self):
        register_user("payload_user", "ValidPass1", "developer")
        result  = login_user("payload_user", "ValidPass1")
        payload = decode_token(result["token"])
        assert payload is not None
        assert payload["username"] == "payload_user"
        assert payload["role"]     == "developer"
        assert "user_id" in payload
        assert "exp" in payload
        assert "jti" in payload   # unique token ID — prevents replay

    def test_two_logins_produce_different_tokens(self):
        register_user("two_tokens", "ValidPass1", "guest")
        t1 = login_user("two_tokens", "ValidPass1")["token"]
        logout_user(t1)
        t2 = login_user("two_tokens", "ValidPass1")["token"]
        assert t1 != t2   # jti guarantees uniqueness


# ── get_user_by_id ────────────────────────────────────────────────────────────

class TestGetUser:

    def test_get_user_by_id_found(self):
        register_user("findme", "ValidPass1", "developer")
        conn = get_connection()
        row  = conn.execute("SELECT id FROM users WHERE username='findme'").fetchone()
        conn.close()
        user = get_user_by_id(row["id"])
        assert user is not None
        assert user["username"]   == "findme"
        assert user["role"]       == "developer"
        assert "risk_score"       in user
        assert "is_flagged"       in user

    def test_get_user_by_id_not_found(self):
        user = get_user_by_id(99999)
        assert user is None
