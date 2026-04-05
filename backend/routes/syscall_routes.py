"""
routes/syscall_routes.py
Vanshika — Flask routes for all syscall endpoints.
"""

from flask import Blueprint, request, jsonify, g

from auth_rbac.permission_middleware import require_auth
from syscall_layer.syscall_controller import handle_syscall

syscall_bp = Blueprint("syscall", __name__)


def _get_user_with_risk(g_user: dict) -> dict:
    """Enrich g.user with current risk_score from DB."""
    from auth_rbac.auth_controller import get_user_by_id
    full = get_user_by_id(g_user["user_id"])
    return {**g_user, "risk_score": full["risk_score"] if full else 0.0}


@syscall_bp.route("/api/syscall/read", methods=["POST"])
@require_auth
def api_file_read():
    data = request.get_json(silent=True) or {}
    if not data.get("file_path"):
        return jsonify({"error": "file_path is required."}), 400
    result = handle_syscall("file_read", _get_user_with_risk(g.user), data)
    code = 200 if result["status"] == "allowed" else 403
    return jsonify(result), code


@syscall_bp.route("/api/syscall/write", methods=["POST"])
@require_auth
def api_file_write():
    data = request.get_json(silent=True) or {}
    if not data.get("file_path"):
        return jsonify({"error": "file_path is required."}), 400
    result = handle_syscall("file_write", _get_user_with_risk(g.user), data)
    code = 200 if result["status"] == "allowed" else 403
    return jsonify(result), code


@syscall_bp.route("/api/syscall/delete", methods=["POST"])
@require_auth
def api_file_delete():
    data = request.get_json(silent=True) or {}
    if not data.get("file_path"):
        return jsonify({"error": "file_path is required."}), 400
    result = handle_syscall("file_delete", _get_user_with_risk(g.user), data)
    code = 200 if result["status"] == "allowed" else 403
    return jsonify(result), code


@syscall_bp.route("/api/syscall/dir_list", methods=["POST"])
@require_auth
def api_dir_list():
    data = request.get_json(silent=True) or {}
    if not data.get("file_path"):
        return jsonify({"error": "file_path is required."}), 400
    result = handle_syscall("dir_list", _get_user_with_risk(g.user), data)
    code = 200 if result["status"] == "allowed" else 403
    return jsonify(result), code


@syscall_bp.route("/api/syscall/execute", methods=["POST"])
@require_auth
def api_exec_process():
    data = request.get_json(silent=True) or {}
    if not data.get("command"):
        return jsonify({"error": "command is required."}), 400
    result = handle_syscall("exec_process", _get_user_with_risk(g.user), data)
    code = 200 if result["status"] == "allowed" else 403
    return jsonify(result), code


@syscall_bp.route("/api/syscall/system_info", methods=["GET", "POST"])
@require_auth
def api_system_info():
    """Safe system information syscall."""
    result = handle_syscall("system_info", _get_user_with_risk(g.user), {})
    code = 200 if result["status"] == "allowed" else 403
    return jsonify(result), code
