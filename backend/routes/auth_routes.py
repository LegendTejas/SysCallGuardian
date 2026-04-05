"""
routes/auth_routes.py
Tejas — Flask routes for auth, user info, and policy management.
"""

from flask import Blueprint, request, jsonify, g

from auth_rbac.auth_controller    import register_user, login_user, logout_user, get_user_by_id
from auth_rbac.permission_middleware import require_auth, require_role
from auth_rbac.roles              import get_all_roles, load_permissions
from policy_engine.policy_loader  import (
    get_all_policies_from_db, create_policy, update_policy, reload_policies, bulk_import_policies
)
from database.db import get_connection

auth_bp   = Blueprint("auth",   __name__)
user_bp   = Blueprint("user",   __name__)
policy_bp = Blueprint("policy", __name__)


# ── Auth ──────────────────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/register", methods=["POST"])
@require_auth
@require_role("developer")
def api_register():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "guest")

    # Security: Hierarchy check
    # Admins can create anyone; Developers can ONLY create guests.
    creator_role = g.user.get("role", "guest")
    if creator_role == "developer" and role != "guest":
        return jsonify({
            "error": "Forbidden.",
            "detail": "Developers can only create Guest accounts. Admins are required for higher roles."
        }), 403

    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400

    result = register_user(username, password, role, email)
    if not result["success"]:
        return jsonify({"error": result["error"]}), 409
    return jsonify({"message": result["message"]}), 201


@auth_bp.route("/api/auth/login", methods=["POST"])
def api_login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400

    result = login_user(username, password)
    if not result["success"]:
        return jsonify({"error": result["error"]}), 401

    return jsonify({
        "message":  result["message"],
        "token":    result["token"],
        "role":     result["role"],
        "username": result["username"],
    }), 200


@auth_bp.route("/api/auth/logout", methods=["POST"])
@require_auth
def api_logout():
    result = logout_user(g.token)
    return jsonify({"message": result["message"]}), 200

@auth_bp.route("/api/auth/recover-info", methods=["POST"])
def api_recover_info():
    data = request.get_json(silent=True) or {}
    identity = data.get("identity", "").strip().lower()
    if not identity:
        return jsonify({"error": "Identity required"}), 400
    
    from database.db import get_connection
    conn = get_connection()
    try:
        row = conn.execute("SELECT role FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (identity.lower(), identity.lower())).fetchone()
        if not row:
            # Prevent user enumeration by masking missing users as guests or generic
            return jsonify({"role": "guest"}), 200
        return jsonify({"role": row["role"]}), 200
    finally:
        conn.close()

@auth_bp.route("/api/auth/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    identity = data.get("identity", "").strip()
    # The email they entered or the identity itself if it's an email format
    
    if not identity:
        return jsonify({"error": "Identity required"}), 400

    from database.db import get_connection
    from auth_rbac.notification_service import send_admin_alert, send_developer_secure_link, send_guest_otp
    import uuid
    import random

    conn = get_connection()
    try:
        row = conn.execute("SELECT id, username, email, role FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", 
                           (identity.lower(), identity.lower())).fetchone()
        
        # Always return generic success to prevent enumeration
        generic_response = (jsonify({"message": "If an account matching those details exists, recovery instructions have been sent."}), 200)
        
        if not row:
            # If they typed an email address that doesn't exist in the DB,
            # send a guest OTP to it for testing/dynamic guest usage.
            if "@" in identity:
                otp = f"{random.randint(100000, 999999)}"
                # Save into OTPs table
                conn.execute(
                    "INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, datetime('now', '+15 minutes'))",
                    (identity.lower(), otp)
                )
                conn.commit()
                send_guest_otp(identity.lower(), otp)
            return generic_response
            
        role = row["role"]
        db_email = row["email"]
        username = row["username"]
        
        if role == "admin":
            if db_email != "testingacctejax@gmail.com":
                return generic_response
            send_admin_alert(db_email, username)
            
        elif role == "developer":
            if db_email != "cvanshika995@gmail.com":
                return generic_response
            token = str(uuid.uuid4())
            send_developer_secure_link(db_email, token)
            
        else:
            # Guest logic fallback for registered user
            target_email = db_email
            if not target_email and "@" in identity:
                target_email = identity.lower()
                
            if not target_email:
                return generic_response
                
            otp = f"{random.randint(100000, 999999)}"
            conn.execute(
                "INSERT INTO otps (email, otp_code, expires_at) VALUES (?, ?, datetime('now', '+15 minutes'))",
                (target_email, otp)
            )
            conn.commit()
            send_guest_otp(target_email, otp)

        return generic_response
    finally:
        conn.close()

@auth_bp.route("/api/auth/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json(silent=True) or {}
    identity = data.get("identity", "").strip().lower()
    otp = data.get("otp", "").strip()
    new_password = data.get("new_password", "")
    
    if not identity or not otp or not new_password:
        return jsonify({"error": "Missing parameters."}), 400
        
    from auth_rbac.auth_controller import is_strong_password, hash_password
    valid, msg = is_strong_password(new_password)
    if not valid:
        return jsonify({"error": msg}), 400
        
    from database.db import get_connection
    conn = get_connection()
    try:
        # Check OTP validity
        target_email = identity
        
        # If username was used, we need their actual DB email
        user_row = conn.execute("SELECT email FROM users WHERE LOWER(username) = ?", (identity,)).fetchone()
        if user_row and user_row["email"]:
            target_email = user_row["email"]
            
        otp_row = conn.execute(
            "SELECT id FROM otps WHERE LOWER(email) = ? AND otp_code = ? AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1",
            (target_email, otp)
        ).fetchone()
        
        if not otp_row:
            return jsonify({"error": "Invalid or expired verification code."}), 400
            
        # Delete used OTP
        conn.execute("DELETE FROM otps WHERE id = ?", (otp_row["id"],))
        
        # Update user's password if they exist
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE LOWER(username) = ? OR LOWER(email) = ?",
            (hash_password(new_password), identity, target_email)
        )
        conn.commit()
        return jsonify({"message": "Password successfully reset."}), 200
    finally:
        conn.close()



# ── User ──────────────────────────────────────────────────────────────────────

@user_bp.route("/api/user/me", methods=["GET"])
@require_auth
def api_me():
    user = get_user_by_id(g.user["user_id"])
    if not user:
        return jsonify({"error": "User not found."}), 404
    return jsonify({
        "username":   user["username"],
        "role":       user["role"],
        "is_flagged": bool(user["is_flagged"]),
        "risk_score": user["risk_score"],
    }), 200


@user_bp.route("/api/user/roles", methods=["GET"])
@require_auth
@require_role("developer")
def api_roles():
    return jsonify(get_all_roles()), 200


# ── Policies ──────────────────────────────────────────────────────────────────

@policy_bp.route("/api/policies", methods=["GET"])
@require_auth
@require_role("developer")
def api_get_policies():
    return jsonify(get_all_policies_from_db()), 200


@policy_bp.route("/api/policies/preview", methods=["GET"])
@require_auth
@require_role("developer")
def api_get_policies_preview():
    """Read-only preview of active policies for Developers.
    Shows policy name and active status only — no rule JSON internals."""
    all_policies = get_all_policies_from_db()
    preview = [
        {"id": p["id"], "name": p["name"], "is_active": p["is_active"]}
        for p in all_policies if p.get("is_active", True)
    ]
    return jsonify(preview), 200


@policy_bp.route("/api/policies", methods=["POST"])
@require_auth
@require_role("admin")
def api_create_policy():
    data      = request.get_json(silent=True) or {}
    name      = data.get("name", "").strip()
    rule_json = data.get("rule_json")

    if not name or not rule_json:
        return jsonify({"error": "name and rule_json are required."}), 400

    try:
        result = create_policy(name, rule_json)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not result["success"]:
        return jsonify({"error": result["error"]}), 409

    load_permissions()
    return jsonify({"message": "Policy created successfully.", "id": result["id"]}), 201


@policy_bp.route("/api/policies/<int:policy_id>", methods=["PUT"])
@require_auth
@require_role("admin")
def api_update_policy(policy_id: int):
    data      = request.get_json(silent=True) or {}
    rule_json = data.get("rule_json")
    is_active = data.get("is_active")

    if rule_json is None and is_active is None:
        return jsonify({"error": "Provide at least one of: rule_json, is_active."}), 400

    try:
        result = update_policy(policy_id, rule=rule_json, is_active=is_active)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not result["success"]:
        return jsonify({"error": result["error"]}), 404

    reload_policies()
    load_permissions()
    return jsonify({"message": result["message"]}), 200


@policy_bp.route("/api/policies/export", methods=["GET"])
@require_auth
@require_role("admin")
def api_export_rule_set():
    """GET /api/policies/export — Download all policies as a JSON rule-set."""
    policies = get_all_policies_from_db()
    return jsonify(policies), 200


@policy_bp.route("/api/policies/import", methods=["POST"])
@require_auth
@require_role("admin")
def api_import_rule_set():
    """POST /api/policies/import — Upload a JSON rule-set to update policies."""
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "Expected a JSON list of policies."}), 400
    
    result = bulk_import_policies(data)
    if not result["success"]:
        return jsonify({"error": result["error"]}), 500
        
    return jsonify({"message": f"Successfully imported {result['imported']} security policies."}), 200


@policy_bp.route("/api/policies/<int:policy_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def api_delete_policy(policy_id: int):
    """DELETE /api/policies/:id — Remove a policy permanently."""
    conn = get_connection()
    try:
        conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
        conn.commit()
        reload_policies()
        return jsonify({"success": True, "message": "Policy deleted."}), 200
    finally:
        conn.close()


# ── User Management Routes (Phase 4) ──────────────────────────────────────────

@user_bp.route("/api/users", methods=["GET"])
@require_auth
@require_role("developer")
def api_get_all_users():
    """
    GET /api/users
    Returns all users with their real syscall stats.
    Admin only.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT
                u.id,
                u.username,
                u.role,
                u.is_flagged,
                u.risk_score,
                u.created_at,
                COUNT(l.id)                                          AS total_calls,
                SUM(CASE WHEN l.status = 'blocked' THEN 1 ELSE 0 END) AS blocked_calls
            FROM users u
            LEFT JOIN syscall_logs l ON l.user_id = u.id
            GROUP BY u.id
            ORDER BY total_calls DESC
        """).fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


@user_bp.route("/api/users/<int:user_id>/revoke", methods=["POST"])
@require_auth
@require_role("developer")
def api_revoke_user_session(user_id: int):
    """
    POST /api/users/:id/revoke
    Delete all active sessions for a user — forces re-login.
    Admin only.
    """
    conn = get_connection()
    try:
        deleted = conn.execute(
            "DELETE FROM sessions WHERE user_id = ?", (user_id,)
        ).rowcount
        conn.commit()
        return jsonify({
            "message":          f"Revoked {deleted} session(s).",
            "sessions_revoked": deleted,
        }), 200
    finally:
        conn.close()


@user_bp.route("/api/users/<int:user_id>/unflag", methods=["POST"])
@require_auth
@require_role("developer")
def api_unflag_user(user_id: int):
    """
    POST /api/users/:id/unflag
    Reset is_flagged = 0 and risk_score = 0.0 for a user.
    Admin only.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if not row:
            return jsonify({"error": f"User ID {user_id} not found."}), 404
        conn.execute(
            "UPDATE users SET is_flagged = 0, risk_score = 0.0 WHERE id = ?",
            (user_id,)
        )
        conn.commit()
        return jsonify({
            "message":  f"User '{row['username']}' cleared — flag and risk score reset.",
            "user_id":  user_id,
        }), 200
    finally:
        conn.close()


@user_bp.route("/api/users/<int:user_id>/role", methods=["PUT"])
@require_auth
@require_role("developer")
def api_change_user_role(user_id: int):
    """
    PUT /api/users/:id/role
    Body: { "role": "developer" }
    Change a user's role. Admin cannot change their own role.
    """
    data = request.get_json(silent=True) or {}
    role = data.get("role", "").strip()

    if role not in ("admin", "developer", "guest"):
        return jsonify({"error": "Invalid role. Must be admin, developer, or guest."}), 400

    if user_id == g.user["user_id"]:
        return jsonify({"error": "You cannot change your own role."}), 400

    creator_role = g.user.get("role", "guest")
    if creator_role == "developer" and role != "guest":
        return jsonify({"error": "Forbidden", "detail": "Developers can only assign Guest roles."}), 403

    conn = get_connection()
    try:
        current_data = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not current_data:
            return jsonify({"error": f"User ID {user_id} not found."}), 404
        
        # Security: Developer cannot change an Admin's role
        if creator_role == "developer" and current_data["role"] == "admin":
            return jsonify({"error": "Forbidden", "detail": "Developers cannot modify Administrator accounts."}), 403
        conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (role, user_id)
        )
        conn.commit()
        return jsonify({
            "message":  f"Role updated to '{role}' for user '{row['username']}'.",
            "user_id":  user_id,
            "new_role": role,
        }), 200
    finally:
        conn.close()
