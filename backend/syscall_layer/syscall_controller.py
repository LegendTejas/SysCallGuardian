"""
syscall_layer/syscall_controller.py
Vanshika — Central syscall orchestrator.

Flow for every call:
  1. Validate input
  2. Evaluate RBAC permission (from Tejas)
  3. Evaluate policy engine (from Tejas)
  4. Execute wrapped syscall
  5. Log the result with risk delta
  6. Run threat detection
  7. Return response
"""

from auth_rbac.roles              import can_perform
from policy_engine.policy_evaluator import evaluate
from syscall_layer.file_operations  import safe_file_read, safe_file_write, safe_file_delete, safe_dir_list
from syscall_layer.process_operations import safe_exec_process
from logging_detection.audit_logger import log_syscall
from logging_detection.threat_detection import analyze_event
from logging_detection.risk_scoring import compute_risk_delta

# Maps call_type to the required permission string (from Tejas's permission map)
PERMISSION_MAP = {
    "file_read":   "file_read",
    "file_write":  "file_write",
    "file_delete": "file_delete",
    "dir_list":    "dir_list",
    "exec_process":"exec_process",
    "system_info": "system_info",
}


def handle_syscall(call_type: str, user: dict, payload: dict) -> dict:
    """
    Central handler for all syscall requests.

    Args:
        call_type : one of file_read, file_write, file_delete, dir_list, exec_process
        user      : validated session dict { user_id, username, role, risk_score }
        payload   : request body e.g. { file_path, data, command }

    Returns:
        { status: allowed|blocked, result/output/content, reason }
    """
    permission = PERMISSION_MAP.get(call_type)
    if not permission:
        return {"status": "blocked", "reason": f"Unknown call type: '{call_type}'."}

    # ── Step 1: RBAC check ────────────────────────────────
    if not can_perform(user["role"], permission):
        _log_and_score(call_type, user, payload, "blocked",
                       f"RBAC: role '{user['role']}' lacks permission '{permission}'.")
        return {
            "status": "blocked",
            "reason": f"Your role '{user['role']}' does not have permission to perform '{call_type}'.",
        }

    # ── Step 2: Policy check ──────────────────────────────
    policy_result = evaluate(call_type, user["role"], {"risk_score": user.get("risk_score", 0.0)})
    if not policy_result["allowed"]:
        _log_and_score(call_type, user, payload, "blocked", policy_result["reason"])
        return {"status": "blocked", "reason": policy_result["reason"]}

    # ── Step 3: Execute syscall ───────────────────────────
    exec_result = _dispatch(call_type, payload)

    if not exec_result["success"]:
        _log_and_score(call_type, user, payload, "blocked", exec_result["error"])
        return {"status": "blocked", "reason": exec_result["error"]}

    # ── Step 4: Log success + run threat detection ────────
    _log_and_score(call_type, user, payload, "allowed", None)

    # Build response
    response = {"status": "allowed"}
    if "content" in exec_result:
        response["content"] = exec_result["content"]
    if "output" in exec_result:
        response["output"] = exec_result["output"]
    if "entries" in exec_result:
        response["entries"] = exec_result["entries"]
    if "message" in exec_result:
        response["message"] = exec_result["message"]

    return response


def _dispatch(call_type: str, payload: dict) -> dict:
    """Route to the correct syscall wrapper function."""
    if call_type == "file_read":
        return safe_file_read(payload.get("file_path", ""))
    elif call_type == "file_write":
        return safe_file_write(payload.get("file_path", ""), payload.get("data", ""))
    elif call_type == "file_delete":
        return safe_file_delete(payload.get("file_path", ""))
    elif call_type == "dir_list":
        return safe_dir_list(payload.get("file_path", ""))
    elif call_type == "exec_process":
        return safe_exec_process(payload.get("command", ""))
    elif call_type == "system_info":
        return {
            "success": True, 
            "message": "SysCallGuardian Gateway Operational",
            "content": "Status: ONLINE\nNodes: 3 Active\nProtected: 256 endpoints\nUptime: 45d 02h 17m\nOS: SecureOS v2.4.1 (Kernel 6.1.12-sg)"
        }
    return {"success": False, "error": "Unknown call type."}


def _log_and_score(call_type, user, payload, status, reason):
    """Write audit log and run threat analysis."""
    target = payload.get("file_path") or payload.get("command") or ""
    delta  = compute_risk_delta(status, call_type, user["role"])

    log_syscall(
        user_id     = user["user_id"],
        call_type   = call_type,
        target_path = target,
        status      = status,
        reason      = reason,
        risk_delta  = delta,
    )

    analyze_event(
        user_id   = user["user_id"],
        username  = user["username"],
        call_type = call_type,
        status    = status,
        target    = target,
    )
