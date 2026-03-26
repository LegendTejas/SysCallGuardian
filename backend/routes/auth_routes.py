"""
routes/auth_routes.py
Tejas — Flask routes for auth, user info, and policy management.
"""

from flask import Blueprint, request, jsonify, g

from auth_rbac.auth_controller    import register_user, login_user, logout_user, get_user_by_id
from auth_rbac.permission_middleware import require_auth, require_role
from auth_rbac.roles              import get_all_roles, load_permissions
from policy_engine.policy_loader  import (
    get_all_policies_from_db, create_policy, update_policy, reload_policies
)

auth_bp   = Blueprint("auth",   __name__)
user_bp   = Blueprint("user",   __name__)
policy_bp = Blueprint("policy", __name__)


# ── Auth ──────────────────────────────────────────────────────────────────────

@auth_bp.route("/api/auth/register", methods=["POST"])
def api_register():
    data     = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "guest")

    if not username or not password:
        return jsonify({"error": "username and password are required."}), 400

    result = register_user(username, password, role)
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
@require_role("admin")
def api_roles():
    return jsonify(get_all_roles()), 200


# ── Policies ──────────────────────────────────────────────────────────────────

@policy_bp.route("/api/policies", methods=["GET"])
@require_auth
@require_role("admin")
def api_get_policies():
    return jsonify(get_all_policies_from_db()), 200


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