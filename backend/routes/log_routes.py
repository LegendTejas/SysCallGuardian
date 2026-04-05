
"""
routes/log_routes.py
Vanshika — Flask routes for logs, integrity verification, and threat data.
"""

from flask import Blueprint, request, jsonify, g

from auth_rbac.permission_middleware import require_auth, require_role
from logging_detection.audit_logger  import get_logs
from logging_detection.log_integrity import verify_all_logs, verify_single_log
from logging_detection.threat_detection import get_suspicious_users, get_threat_events

log_bp = Blueprint("logs", __name__)


@log_bp.route("/api/logs", methods=["GET"])
@require_auth
@require_role("guest")
def api_get_logs():
    """
    GET /api/logs
    Query params: user, status, call_type, date, from, to, page
    RBAC:
      - Admin: sees all logs globally
      - Developer: sees all logs but with sensitive target_path sanitized
      - Guest: sees only their own logs
    """
    user_filter = request.args.get("user")
    role = g.user["role"]
    
    # Guest: strictly own logs only
    if role == "guest":
        user_filter = g.user["username"]
    # Developer: can see general logs for debugging
    # (no user filter override — they see all, but paths are sanitized below)

    result = get_logs(
        user      = user_filter,
        status    = request.args.get("status"),
        call_type = request.args.get("call_type"),
        date      = request.args.get("date"),
        from_dt   = request.args.get("from"),
        to_dt     = request.args.get("to"),
        page      = int(request.args.get("page", 1)),
        per_page  = int(request.args.get("per_page", 20)),
    )
    
    # Sanitize sensitive paths for non-admin users
    if role != "admin" and "logs" in result:
        SENSITIVE_PREFIXES = ("/etc/shadow", "/etc/passwd", "/root/", "/home/admin", "/sys/")
        for log in result["logs"]:
            path = log.get("target_path", "")
            if path and any(path.startswith(p) for p in SENSITIVE_PREFIXES):
                log["target_path"] = "[REDACTED — restricted path]"
    
    return jsonify(result), 200


@log_bp.route("/api/logs/verify", methods=["GET"])
@require_auth
@require_role("admin")
def api_verify_all_logs():
    """GET /api/logs/verify — full chain verification (admin only)"""
    result = verify_all_logs()
    return jsonify({
        "status":  "valid" if result["valid"] else "tampered",
        "message": result["message"],
        "tampered_ids": result.get("tampered_ids", []),
    }), 200


@log_bp.route("/api/logs/verify/<int:log_id>", methods=["GET"])
@require_auth
@require_role("admin")
def api_verify_single_log(log_id: int):
    """GET /api/logs/verify/<id> — single log hash verification"""
    result = verify_single_log(log_id)
    return jsonify(result), 200


@log_bp.route("/api/threats", methods=["GET"])
@require_auth
@require_role("admin")
def api_get_threats():
    """GET /api/threats — flagged users with risk scores"""
    users = get_suspicious_users()
    return jsonify(users), 200


@log_bp.route("/api/threats/events", methods=["GET"])
@require_auth
@require_role("admin")
def api_get_threat_events():
    """GET /api/threats/events — chronological threat log (raw events)"""
    events = get_threat_events()
    return jsonify(events), 200


@log_bp.route("/api/dashboard/stats", methods=["GET"])
@require_auth
@require_role("guest")
def api_dashboard_stats():
    """GET /api/dashboard/stats with filtering"""
    from database.db import get_connection
    conn = get_connection()
    user_id = g.user["user_id"]
    role = g.user["role"]
    is_admin = role == "admin"

    # Query Params
    f_user = request.args.get("user")
    f_status = request.args.get("status")
    f_call = request.args.get("call_type")
    f_role = request.args.get("role")

    try:
        # Permission Enforcement
        if not is_admin:
            f_user = g.user["username"] # Non-admins see only themselves
            f_role = None # Cannot filter by role

        conditions = []
        params = []
        
        if f_user:
            conditions.append("u.username = ?")
            params.append(f_user)
        if f_status:
            conditions.append("l.status = ?")
            params.append(f_status)
        if f_call:
            conditions.append("l.call_type = ?")
            params.append(f_call)
        if f_role and is_admin:
            conditions.append("u.role = ?")
            params.append(f_role)
            
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total   = conn.execute(f"SELECT COUNT(*) FROM syscall_logs l JOIN users u ON l.user_id=u.id {where}", params).fetchone()[0]
        
        # Breakdown queries
        def get_count(s):
            c = list(conditions) + ["l.status = ?"]
            p = list(params) + [s]
            w = "WHERE " + " AND ".join(c)
            return conn.execute(f"SELECT COUNT(*) FROM syscall_logs l JOIN users u ON l.user_id=u.id {w}", p).fetchone()[0]

        allowed = get_count('allowed')
        blocked = get_count('blocked')
        flagged = get_count('flagged')
        
        if is_admin:
            sus_users = conn.execute("SELECT COUNT(*) FROM users WHERE is_flagged=1").fetchone()[0]
        else:
            sus_users = 0
        
        top_query = f"""SELECT u.username, COUNT(*) as call_count
                        FROM syscall_logs l JOIN users u ON l.user_id=u.id
                        {where}
                        GROUP BY u.username ORDER BY call_count DESC LIMIT 5"""
        top_users = conn.execute(top_query, params).fetchall()

        return jsonify({
            "total_calls":     total,
            "allowed":         allowed,
            "blocked":         blocked,
            "flagged":         flagged,
            "suspicious_users": sus_users,
            "top_users":       [{"username": r["username"], "call_count": r["call_count"]} for r in top_users],
        }), 200
    finally:
        conn.close()


@log_bp.route("/api/dashboard/activity", methods=["GET"])
@require_auth
@require_role("guest")
def api_dashboard_activity():
    """GET /api/dashboard/activity — hourly timeline with filtering"""
    from database.db import get_connection
    conn = get_connection()
    user_id = g.user["user_id"]
    role = g.user["role"]
    is_admin = role == "admin"

    # Query Params
    f_user = request.args.get("user")
    f_status = request.args.get("status")
    f_call = request.args.get("call_type")
    f_role = request.args.get("role")

    try:
        if not is_admin:
            f_user = g.user["username"]
            f_role = None

        conditions = ["l.timestamp >= datetime('now', '-24 hours')"]
        params = []
        
        if f_user:
            conditions.append("u.username = ?")
            params.append(f_user)
        if f_status:
            conditions.append("l.status = ?")
            params.append(f_status)
        if f_call:
            conditions.append("l.call_type = ?")
            params.append(f_call)
        if f_role and is_admin:
            conditions.append("u.role = ?")
            params.append(f_role)
            
        where = "WHERE " + " AND ".join(conditions)

        query = f"""SELECT strftime('%H:00', l.timestamp) as hour,
                          SUM(CASE WHEN l.status='allowed' THEN 1 ELSE 0 END) as allowed,
                          SUM(CASE WHEN l.status='blocked' THEN 1 ELSE 0 END) as blocked,
                          COUNT(*) as calls
                   FROM syscall_logs l JOIN users u ON l.user_id = u.id
                   {where}
                   GROUP BY hour ORDER BY hour ASC"""
        rows = conn.execute(query, params).fetchall()
        return jsonify([dict(r) for r in rows]), 200
    finally:
        conn.close()


@log_bp.route("/api/dashboard/extended", methods=["GET"])
@require_auth
@require_role("guest")
def api_dashboard_extended():
    """GET /api/dashboard/extended — heatmap, risk, role distribution with filtering"""
    from database.db import get_connection
    conn = get_connection()
    user_id = g.user["user_id"]
    role = g.user["role"]
    is_admin = role == "admin"

    # Query Params
    f_user = request.args.get("user")
    f_status = request.args.get("status")
    f_call = request.args.get("call_type")
    f_role = request.args.get("role")

    try:
        if not is_admin:
            f_user = g.user["username"]
            f_role = None

        conditions = []
        params = []
        
        if f_user:
            conditions.append("u.username = ?")
            params.append(f_user)
        if f_status:
            conditions.append("l.status = ?")
            params.append(f_status)
        if f_call:
            conditions.append("l.call_type = ?")
            params.append(f_call)
        if f_role and is_admin:
            conditions.append("u.role = ?")
            params.append(f_role)
            
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        # 1. Heatmap (User x Syscall)
        heatmap_query = f"""SELECT u.username, l.call_type, COUNT(*) as count 
                           FROM syscall_logs l JOIN users u ON l.user_id=u.id 
                           {where}
                           GROUP BY u.username, l.call_type"""
        heatmap = conn.execute(heatmap_query, params).fetchall()

        # 2. Syscall Types by Decision (syscall_status)
        syscall_status = conn.execute(f"SELECT l.call_type, l.status, COUNT(*) as count FROM syscall_logs l JOIN users u ON l.user_id=u.id {where} GROUP BY l.call_type, l.status", params).fetchall()

        # 3. Role Distribution (role_dist)
        if is_admin:
            role_dist = conn.execute(f"SELECT u.role, COUNT(*) as count FROM syscall_logs l JOIN users u ON l.user_id = u.id {where} GROUP BY u.role", params).fetchall()
        else:
            role_dist = conn.execute(f"SELECT u.role, COUNT(*) as count FROM syscall_logs l JOIN users u ON l.user_id = u.id WHERE u.id=? GROUP BY u.role", (user_id,)).fetchall()

        # 4. User Risks (user_risks)
        if is_admin:
            user_risks = conn.execute("SELECT username, risk_score FROM users ORDER BY risk_score DESC").fetchall()
        else:
            user_risks = conn.execute(f"SELECT username, risk_score FROM users WHERE id=?", (user_id,)).fetchall()

        # 5. Recent Logs (recent_logs)
        log_query = f"""SELECT u.username as user, l.call_type, l.status, l.timestamp, l.target_path
                       FROM syscall_logs l JOIN users u ON l.user_id = u.id 
                       {where}
                       ORDER BY l.timestamp DESC LIMIT 100"""
        recent_logs_raw = conn.execute(log_query, params).fetchall()

        # Sanitize paths for non-admin
        recent_logs = []
        SENSITIVE_PREFIXES = ("/etc/shadow", "/etc/passwd", "/root/", "/home/admin", "/sys/")
        for r in recent_logs_raw:
            entry = dict(r)
            if not is_admin and entry.get("target_path"):
                if any(entry["target_path"].startswith(p) for p in SENSITIVE_PREFIXES):
                    entry["target_path"] = "[REDACTED]"
            recent_logs.append(entry)

        return jsonify({
            "heatmap": [dict(r) for r in heatmap],
            "syscall_status": [dict(r) for r in syscall_status],
            "role_dist": [dict(r) for r in role_dist],
            "user_risks": [dict(r) for r in user_risks],
            "recent_logs": recent_logs,
        }), 200
    finally:
        conn.close()
