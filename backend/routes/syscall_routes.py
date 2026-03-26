"""
routes/syscall_routes.py
Vanshika — Flask routes for all secure system call operations.

Endpoints:
    POST /api/syscall/read      → read a file
    POST /api/syscall/write     → write to a file
    POST /api/syscall/delete    → delete a file
    POST /api/syscall/execute   → execute a safe command

Every endpoint:
    1. Requires authentication (Tejas's @require_auth)
    2. Requires the correct permission (Tejas's @require_permission)
    3. Evaluates against active policies (Tejas's policy engine)
    4. Passes through syscall wrapper (Vanshika's path sanitization)
    5. Logs the result (Vanshika's logger)
    6. Runs threat analysis (Vanshika's threat engine)
"""

from flask import Blueprint, request, jsonify, g

# Tejas's decorators — used as-is, no changes to his files
from auth_rbac.permission_middleware import require_auth, require_permission
from auth_rbac.auth_controller import get_user_by_id
from policy_engine.policy_evaluator import evaluate

# Vanshika's modules
from syscall_layer.syscall_wrapper import do_file_read, do_file_write, do_file_delete, do_execute
from syscall_layer.logger import write_log, update_user_risk
from syscall_layer.threat_engine import analyze_threat, check_restricted_path

syscall_bp = Blueprint("syscall", __name__)


# ── Helper: map HTTP action to call_type string ───────────────────────────────

ACTION_MAP = {
    "read":    "file_read",
    "write":   "file_write",
    "delete":  "file_delete",
    "execute": "exec_process",
}


# ── POST /api/syscall/read ────────────────────────────────────────────────────

@syscall_bp.route("/api/syscall/read", methods=["POST"])
@require_auth
@require_permission("file_read")
def api_syscall_read():
    """
    Read a file securely.

    Request body:
        { "path": "myfile.txt" }

    Response (allowed):
        { "status": "allowed", "content": "file contents here" }

    Response (blocked):
        { "status": "blocked", "reason": "why it was blocked" }
    """
    data    = request.get_json(silent=True) or {}
    path    = data.get("path", "").strip()
    user_id = g.user["user_id"]
    role    = g.user["role"]

    # Get user's current risk score for policy evaluation
    user    = get_user_by_id(user_id)
    context = {"risk_score": user["risk_score"] if user else 0.0}

    # Check restricted path BEFORE policy (immediate flag)
    path_threat = check_restricted_path(path)
    if path_threat["triggered"]:
        update_user_risk(user_id, path_threat["risk_added"])
        write_log(user_id, "file_read", path, "blocked", path_threat["reason"], path_threat["risk_added"])
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": path_threat["reason"]}), 403

    # Evaluate against active policies
    policy_result = evaluate("file_read", role, context)
    if not policy_result["allowed"]:
        write_log(user_id, "file_read", path, "blocked", policy_result["reason"], 3.0)
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": policy_result["reason"]}), 403

    # Execute through secure wrapper
    result = do_file_read(path)

    if not result["success"]:
        write_log(user_id, "file_read", path, "blocked", result["reason"], 3.0)
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": result["reason"]}), 400

    # Log success
    write_log(user_id, "file_read", path, "allowed", None, 0.0)
    analyze_threat(user_id, path, was_blocked=False)
    return jsonify({"status": "allowed", "content": result["content"]}), 200


# ── POST /api/syscall/write ───────────────────────────────────────────────────

@syscall_bp.route("/api/syscall/write", methods=["POST"])
@require_auth
@require_permission("file_write")
def api_syscall_write():
    """
    Write content to a file securely.

    Request body:
        { "path": "myfile.txt", "content": "hello world" }

    Response:
        { "status": "allowed", "message": "File written successfully." }
        { "status": "blocked", "reason": "..." }
    """
    data    = request.get_json(silent=True) or {}
    path    = data.get("path", "").strip()
    content = data.get("content", "")
    user_id = g.user["user_id"]
    role    = g.user["role"]

    user    = get_user_by_id(user_id)
    context = {"risk_score": user["risk_score"] if user else 0.0}

    # Restricted path check
    path_threat = check_restricted_path(path)
    if path_threat["triggered"]:
        update_user_risk(user_id, path_threat["risk_added"])
        write_log(user_id, "file_write", path, "blocked", path_threat["reason"], path_threat["risk_added"])
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": path_threat["reason"]}), 403

    # Policy check
    policy_result = evaluate("file_write", role, context)
    if not policy_result["allowed"]:
        write_log(user_id, "file_write", path, "blocked", policy_result["reason"], 3.0)
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": policy_result["reason"]}), 403

    # Execute through secure wrapper
    result = do_file_write(path, content)

    if not result["success"]:
        write_log(user_id, "file_write", path, "blocked", result["reason"], 3.0)
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": result["reason"]}), 400

    write_log(user_id, "file_write", path, "allowed", None, 0.0)
    analyze_threat(user_id, path, was_blocked=False)
    return jsonify({"status": "allowed", "message": result["message"]}), 200


# ── POST /api/syscall/delete ──────────────────────────────────────────────────

@syscall_bp.route("/api/syscall/delete", methods=["POST"])
@require_auth
@require_permission("file_delete")
def api_syscall_delete():
    """
    Delete a file securely.

    Request body:
        { "path": "myfile.txt" }

    Response:
        { "status": "allowed", "message": "Deleted successfully." }
        { "status": "blocked", "reason": "..." }
    """
    data    = request.get_json(silent=True) or {}
    path    = data.get("path", "").strip()
    user_id = g.user["user_id"]
    role    = g.user["role"]

    user    = get_user_by_id(user_id)
    context = {"risk_score": user["risk_score"] if user else 0.0}

    # Restricted path check
    path_threat = check_restricted_path(path)
    if path_threat["triggered"]:
        update_user_risk(user_id, path_threat["risk_added"])
        write_log(user_id, "file_delete", path, "blocked", path_threat["reason"], path_threat["risk_added"])
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": path_threat["reason"]}), 403

    # Policy check
    policy_result = evaluate("file_delete", role, context)
    if not policy_result["allowed"]:
        write_log(user_id, "file_delete", path, "blocked", policy_result["reason"], 3.0)
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": policy_result["reason"]}), 403

    # Execute through secure wrapper
    result = do_file_delete(path)

    if not result["success"]:
        write_log(user_id, "file_delete", path, "blocked", result["reason"], 3.0)
        analyze_threat(user_id, path, was_blocked=True)
        return jsonify({"status": "blocked", "reason": result["reason"]}), 400

    write_log(user_id, "file_delete", path, "allowed", None, 0.0)
    analyze_threat(user_id, path, was_blocked=False)
    return jsonify({"status": "allowed", "message": result["message"]}), 200


# ── POST /api/syscall/execute ─────────────────────────────────────────────────

@syscall_bp.route("/api/syscall/execute", methods=["POST"])
@require_auth
@require_permission("exec_process")
def api_syscall_execute():
    """
    Execute a whitelisted shell command securely.

    Request body:
        { "command": "ls" }

    Response:
        { "status": "allowed", "output": "file1.txt\nfile2.txt\n" }
        { "status": "blocked", "reason": "..." }
    """
    data    = request.get_json(silent=True) or {}
    command = data.get("command", "").strip()
    user_id = g.user["user_id"]
    role    = g.user["role"]

    user    = get_user_by_id(user_id)
    context = {"risk_score": user["risk_score"] if user else 0.0}

    # Policy check
    policy_result = evaluate("exec_process", role, context)
    if not policy_result["allowed"]:
        write_log(user_id, "exec_process", command, "blocked", policy_result["reason"], 3.0)
        analyze_threat(user_id, command, was_blocked=True)
        return jsonify({"status": "blocked", "reason": policy_result["reason"]}), 403

    # Execute through secure wrapper
    result = do_execute(command)

    if not result["success"]:
        write_log(user_id, "exec_process", command, "blocked", result["reason"], 3.0)
        analyze_threat(user_id, command, was_blocked=True)
        return jsonify({"status": "blocked", "reason": result["reason"]}), 400

    write_log(user_id, "exec_process", command, "allowed", None, 0.0)
    analyze_threat(user_id, command, was_blocked=False)
    return jsonify({
        "status": "allowed",
        "output": result["output"],
        "stderr": result.get("stderr", ""),
    }), 200
