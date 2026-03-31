"""
logging_detection/risk_scoring.py
Vanshika — Risk delta computation for each syscall event.

Risk deltas are added to the user's cumulative risk_score in the DB.
Score range: 0.0 – 100.0

Scoring rules:
  - Blocked call       : +base delta (depends on call type)
  - Suspicious call    : +half of base delta
  - Allowed call       : 0.0 (no risk increment on success)
  - Admin calls        : 0.0 (admins don't accumulate risk)
"""

# Base risk delta per blocked call type
BLOCKED_RISK_MAP = {
    "exec_process":       15.0,   # highest risk — execution
    "file_delete":        10.0,
    "system_dir_access":  20.0,   # very high — kernel/system
    "file_write":          8.0,
    "dir_list":            5.0,
    "file_read":           3.0,
}

DEFAULT_BLOCKED_RISK = 5.0


def compute_risk_delta(status: str, call_type: str, role: str) -> float:
    """
    Return the risk score delta for a single syscall event.

    Args:
        status    : "allowed", "blocked", or "flagged"
        call_type : syscall type string
        role      : user's role

    Returns:
        float delta to add to user's risk_score
    """
    # Admins never accumulate risk
    if role == "admin":
        return 0.0

    if status == "allowed":
        return 0.0

    base = BLOCKED_RISK_MAP.get(call_type, DEFAULT_BLOCKED_RISK)

    if status == "flagged":
        return base * 0.5   # suspicious is half risk of a hard block

    return base   # blocked gets full risk delta


def get_risk_level(score: float) -> str:
    """Classify a risk score into a human-readable level."""
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"
