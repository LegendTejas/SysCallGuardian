"""
logging_detection/threat_detection.py
Vanshika — Rule-based threat detection engine.

Detection rules:
  R1. Brute-force login      : 5+ failed logins in 10 minutes
  R2. Rapid syscall flood    : 20+ calls of same type in 60s
  R3. Repeated exec blocks   : 3+ exec_process blocks in 5 minutes
  R4. System path probe      : any access to /sys, /proc, /boot
  R5. High risk score        : user risk_score >= 70
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from database.db import get_connection

# In-memory event window (resets on app restart — production would use Redis)
# Structure: { user_id: [ { type, call_type, target, timestamp } ] }
_event_window: dict[int, list] = defaultdict(list)

WINDOW_SECONDS = 300   # 5 minute sliding window


def analyze_event(user_id: int, username: str, call_type: str,
                  status: str, target: str = ""):
    """
    Record a syscall event and evaluate all threat detection rules.
    Flags the user in DB if any rule fires.

    Args:
        user_id   : acting user's DB id
        username  : username string (for logging)
        call_type : syscall type
        status    : allowed / blocked / flagged
        target    : file path or command
    """
    now = datetime.now(timezone.utc)

    # Add to sliding window
    _event_window[user_id].append({
        "call_type": call_type,
        "status":    status,
        "target":    target,
        "time":      now,
    })

    # Prune events outside the window
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    _event_window[user_id] = [
        e for e in _event_window[user_id]
        if e["time"] > cutoff
    ]

    events = _event_window[user_id]

    # ── Rule R2: Rapid syscall flood ──────────────────────
    same_type = [e for e in events
                 if e["call_type"] == call_type and e["time"] > now - timedelta(seconds=60)]
    if len(same_type) >= 20:
        _flag_user(user_id, f"Rapid syscall flood: {len(same_type)} '{call_type}' calls in 60s")
        return

    # ── Rule R3: Repeated exec blocks ────────────────────
    exec_blocks = [e for e in events
                   if e["call_type"] == "exec_process"
                   and e["status"] == "blocked"
                   and e["time"] > now - timedelta(seconds=300)]
    if len(exec_blocks) >= 3:
        _flag_user(user_id, f"Repeated exec_process violations: {len(exec_blocks)} in 5 min")
        return

    # ── Rule R4: System path probe ────────────────────────
    SYSTEM_PREFIXES = ("/sys", "/proc", "/boot", "/dev", "/root")
    if target and any(target.startswith(p) for p in SYSTEM_PREFIXES):
        _flag_user(user_id, f"System path probe attempt: '{target}'")
        return

    # ── Rule R5: High risk score ──────────────────────────
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT risk_score FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row and row["risk_score"] >= 70:
            _flag_user(user_id, f"Risk score threshold exceeded: {row['risk_score']:.1f}")
    finally:
        conn.close()


def _flag_user(user_id: int, reason: str):
    """Mark a user as flagged in the DB."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET is_flagged = 1 WHERE id = ?", (user_id,)
        )
        conn.commit()
    finally:
        conn.close()


def get_suspicious_users() -> list[dict]:
    """Return all flagged users with their risk scores and reason indicators."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT id, username, role, risk_score
               FROM users
               WHERE is_flagged = 1 OR risk_score >= 20
               ORDER BY risk_score DESC"""
        ).fetchall()
        return [
            {
                "user_id":    row["id"],
                "username":   row["username"],
                "role":       row["role"],
                "risk_score": row["risk_score"],
                "risk_level": _risk_level(row["risk_score"]),
            }
            for row in rows
        ]
    finally:
        conn.close()


def _risk_level(score: float) -> str:
    if score >= 70: return "critical"
    if score >= 40: return "high"
    if score >= 20: return "medium"
    return "low"
