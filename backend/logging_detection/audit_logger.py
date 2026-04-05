"""
logging_detection/audit_logger.py
Vanshika — Secure audit logger with SHA-256 hash chaining.

Every log entry contains:
  - SHA-256 hash of its own data
  - prev_hash: hash of the previous log entry (chain)
  This makes tampering detectable — any edit breaks the chain.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from database.db import get_connection


def _hash_entry(user_id: int, call_type: str, target_path: str,
                status: str, reason: str, risk_delta: float,
                timestamp: str, prev_hash: str) -> str:
    """Compute SHA-256 hash of a log entry's content."""
    data = json.dumps({
        "user_id":     user_id,
        "call_type":   call_type,
        "target_path": target_path,
        "status":      status,
        "reason":      reason,
        "risk_delta":  risk_delta,
        "timestamp":   timestamp,
        "prev_hash":   prev_hash,
    }, sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _get_last_hash(conn) -> str:
    """Fetch the hash of the most recent log entry (head of chain)."""
    row = conn.execute(
        "SELECT log_hash FROM syscall_logs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["log_hash"] if row else "GENESIS"


def log_syscall(user_id: int, call_type: str, target_path: str,
                status: str, reason: str = None, risk_delta: float = 0.0):
    """
    Write a syscall event to the audit log with SHA-256 hash chaining.

    Args:
        user_id     : ID of the acting user
        call_type   : e.g. "file_read", "exec_process"
        target_path : file path or command string
        status      : "allowed", "blocked", or "flagged"
        reason      : why it was blocked/flagged (None if allowed)
        risk_delta  : risk score increment for this event
    """
    import os
    if call_type in {"file_read", "file_write", "file_delete", "dir_list", "system_dir_access"}:
        target_path = os.path.normpath(target_path) if target_path else ""

    conn = get_connection()
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = _get_last_hash(conn)
        log_hash  = _hash_entry(
            user_id, call_type, target_path or "",
            status, reason or "", risk_delta, timestamp, prev_hash
        )

        conn.execute(
            """INSERT INTO syscall_logs
               (user_id, call_type, target_path, status, reason, risk_delta, log_hash, prev_hash, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, call_type, target_path, status, reason, risk_delta, log_hash, prev_hash, timestamp)
        )

        # Update user's cumulative risk score
        if risk_delta > 0:
            conn.execute(
                "UPDATE users SET risk_score = MIN(risk_score + ?, 100.0) WHERE id = ?",
                (risk_delta, user_id)
            )

        conn.commit()
    finally:
        conn.close()


def get_logs(user: str = None, status: str = None, call_type: str = None,
             date: str = None, from_dt: str = None, to_dt: str = None,
             page: int = 1, per_page: int = 20) -> dict:
    """
    Fetch paginated, filterable log entries.

    Returns: { page, total, logs: [...] }
    """
    conn = get_connection()
    try:
        conditions = []
        params     = []

        if user:
            conditions.append("u.username = ?")
            params.append(user)
        if status:
            conditions.append("l.status = ?")
            params.append(status)
        if call_type:
            conditions.append("l.call_type = ?")
            params.append(call_type)
        if date:
            conditions.append("DATE(l.timestamp) = ?")
            params.append(date)
        if from_dt:
            conditions.append("l.timestamp >= ?")
            params.append(from_dt)
        if to_dt:
            conditions.append("l.timestamp <= ?")
            params.append(to_dt)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM syscall_logs l JOIN users u ON l.user_id=u.id {where}",
            params
        ).fetchone()[0]

        offset = (page - 1) * per_page
        rows = conn.execute(
            f"""SELECT l.id, u.username, l.call_type, l.target_path,
                       l.status, l.reason, l.risk_delta, l.log_hash, l.timestamp
                FROM syscall_logs l
                JOIN users u ON l.user_id = u.id
                {where}
                ORDER BY l.id DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, offset]
        ).fetchall()

        logs = [
            {
                "id":          row["id"],
                "user":        row["username"],
                "call_type":   row["call_type"],
                "target_path": row["target_path"],
                "status":      row["status"],
                "reason":      row["reason"],
                "risk_delta":  row["risk_delta"],
                "timestamp":   row["timestamp"],
                "hash_preview": row["log_hash"][:12] + "…",
            }
            for row in rows
        ]

        return {"page": page, "total": total, "logs": logs}
    finally:
        conn.close()
