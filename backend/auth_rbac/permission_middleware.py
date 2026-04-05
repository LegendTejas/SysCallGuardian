"""
auth_rbac/permission_middleware.py
Tejas — Flask decorators for route-level auth and permission enforcement.
"""

from functools import wraps
from flask import request, jsonify, g

from auth_rbac.session_manager import validate_session
from auth_rbac.roles import can_perform, has_minimum_role


def require_auth(f):
    """
    Decorator: validates JWT from Authorization header.
    Injects g.user = { user_id, username, role } and g.token into Flask context.

    Usage:
        @app.route("/api/logs")
        @require_auth
        def get_logs():
            print(g.user["role"])
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header."}), 401

        token   = auth_header.split(" ", 1)[1]
        session = validate_session(token)

        if not session["valid"]:
            return jsonify({"error": session.get("error", "Unauthorized.")}), 401

        g.user  = session
        g.token = token
        return f(*args, **kwargs)
    return decorated


def require_role(required_role: str):
    """
    Decorator factory: enforces minimum role level.
    Must stack AFTER @require_auth.

    Usage:
        @require_auth
        @require_role("admin")
        def create_policy(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = g.user.get("role", "guest")
            if not has_minimum_role(user_role, required_role):
                return jsonify({
                    "error":  "Forbidden.",
                    "detail": f"Requires '{required_role}' or higher. Your role: '{user_role}'."
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permission(permission: str):
    """
    Decorator factory: enforces a specific permission string.
    Must stack AFTER @require_auth.

    Usage:
        @require_auth
        @require_permission("exec_process")
        def execute(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role = g.user.get("role", "guest")
            if not can_perform(user_role, permission):
                return jsonify({
                    "error":      "Forbidden.",
                    "detail":     f"Role '{user_role}' lacks permission: '{permission}'.",
                    "permission": permission,
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
