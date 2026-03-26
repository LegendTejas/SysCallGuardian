"""
routes/log_routes.py
Vanshika — Flask routes for logs, threats, and dashboard data.

Endpoints:
    GET  /api/logs                → fetch all logs (admin) or own logs (user)
    GET  /api/logs/verify         → verify entire log chain integrity
    GET  /api/logs/verify/<id>    → verify a single log entry
    GET  /api/threats             → list all flagged/suspicious users
    GET  /api/dashboard/stats     → summary stats for the dashboard
    GET  /api/dashboard/activity  → recent syscall activity
"""

from flask import Blueprint, request, jsonify, g

# Tejas's decorators — used as-is
from auth_rbac.permission_middleware import require_auth, require_role

# Vanshika's modules
from syscall_layer.logger import get_logs, verify_all_logs, verify_single_log
from syscall_layer.threat_engine import get_flagged_users, get_dashboard_stats

log_bp = Blueprint("log", __name__)


# ── GET /api/logs ─────────────────────────────────────────────────────────────

@log_bp.route("/api/logs", methods=["GET"])
@require_auth
def api_get_logs():
    """
    Fetch syscall logs.

    - Admin/Developer : can see ALL logs (or filter by user_id query param)
    - Guest           : can only see their own logs

    Query params:
        ?limit=100          → max logs to return (default 100)
        ?user_id=3          → filter by user (admin/developer only)

    Response:
        [ { id, user_id, username, call_type, target_path, status, reason,
            risk_delta, log_hash, timestamp }, ... ]
    """
    role    = g.user["role"]
    user_id = g.user["user_id"]

    limit = int(request.args.get("limit", 100))

    # Guests can only see their own logs
    if role == "guest":
        logs = get_logs(limit=limit, user_id=user_id)
        return jsonify(logs), 200

    # Admin/Developer can filter or see all
    filter_user = request.args.get("user_id")
    if filter_user:
        logs = get_logs(limit=limit, user_id=int(filter_user))
    else:
        logs = get_logs(limit=limit)

    return jsonify(logs), 200


# ── GET /api/logs/verify ──────────────────────────────────────────────────────

@log_bp.route("/api/logs/verify", methods=["GET"])
@require_auth
@require_role("admin")
def api_verify_all_logs():
    """
    Verify the entire log hash chain for tampering.
    Admin only.

    Response (clean):
        { "valid": true, "checked": 150 }

    Response (tampered):
        { "valid": false, "broken_at_log_id": 42, "reason": "Hash mismatch at log ID 42." }
    """
    result = verify_all_logs()
    status = 200 if result["valid"] else 409
    return jsonify(result), status


# ── GET /api/logs/verify/<id> ─────────────────────────────────────────────────

@log_bp.route("/api/logs/verify/<int:log_id>", methods=["GET"])
@require_auth
@require_role("admin")
def api_verify_single_log(log_id: int):
    """
    Verify a single log entry's hash.
    Admin only.

    Response:
        { "valid": true,  "log_id": 42 }
        { "valid": false, "log_id": 42, "reason": "Hash mismatch..." }
    """
    result = verify_single_log(log_id)
    status = 200 if result["valid"] else 409
    return jsonify(result), status


# ── GET /api/threats ──────────────────────────────────────────────────────────

@log_bp.route("/api/threats", methods=["GET"])
@require_auth
@require_role("admin")
def api_get_threats():
    """
    Return list of all flagged/suspicious users.
    Admin only.

    Response:
        [
          { "id": 3, "username": "baduser", "role": "guest",
            "risk_score": 75.0, "is_flagged": 1 },
          ...
        ]
    """
    flagged = get_flagged_users()
    return jsonify(flagged), 200


# ── GET /api/dashboard/stats ──────────────────────────────────────────────────

@log_bp.route("/api/dashboard/stats", methods=["GET"])
@require_auth
@require_role("developer")   # developer and above can see stats
def api_dashboard_stats():
    """
    Summary statistics for the dashboard.

    Response:
        {
          "total_calls":    250,
          "allowed_calls":  210,
          "blocked_calls":  40,
          "flagged_users":  3,
          "top_users":      [ { "username": "alice", "call_count": 80 }, ... ],
          "recent_activity": [ { "call_type": "file_read", "status": "allowed", ... }, ... ]
        }
    """
    stats = get_dashboard_stats()
    return jsonify(stats), 200


# ── GET /api/dashboard/activity ───────────────────────────────────────────────

@log_bp.route("/api/dashboard/activity", methods=["GET"])
@require_auth
@require_role("developer")
def api_dashboard_activity():
    """
    Recent syscall activity feed for the dashboard.

    Query params:
        ?limit=20  → how many recent entries (default 20)

    Response:
        [ { username, call_type, target_path, status, timestamp }, ... ]
    """
    limit  = int(request.args.get("limit", 20))
    recent = get_logs(limit=limit)
    return jsonify(recent), 200
