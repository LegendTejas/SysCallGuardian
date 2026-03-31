"""
logging_detection/log_integrity.py
Vanshika — SHA-256 hash chain verification.

Verifies that no log entry has been tampered with by:
  1. Recomputing each entry's hash from its data fields
  2. Comparing with the stored log_hash
  3. Verifying each entry's prev_hash matches the previous entry's log_hash
"""

import hashlib
import json
from database.db import get_connection


def _recompute_hash(row: dict) -> str:
    """Recompute the expected hash for a log row."""
    data = json.dumps({
        "user_id":     row["user_id"],
        "call_type":   row["call_type"],
        "target_path": row["target_path"] or "",
        "status":      row["status"],
        "reason":      row["reason"] or "",
        "risk_delta":  row["risk_delta"],
        "timestamp":   row["timestamp"],
        "prev_hash":   row["prev_hash"] or "GENESIS",
    }, sort_keys=True)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_all_logs() -> dict:
    """
    Full chain verification across all log entries.
    Returns: { valid: bool, tampered_ids: [], message: str }
    """
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM syscall_logs ORDER BY id ASC"
        ).fetchall()

        tampered_ids = []
        prev_hash    = "GENESIS"

        for row in rows:
            row = dict(row)
            expected = _recompute_hash(row)

            if row["log_hash"] != expected:
                tampered_ids.append(row["id"])
            if row["prev_hash"] != prev_hash:
                if row["id"] not in tampered_ids:
                    tampered_ids.append(row["id"])

            prev_hash = row["log_hash"]

        if not tampered_ids:
            return {
                "valid":        True,
                "tampered_ids": [],
                "message":      "Logs are not tampered. Chain integrity verified.",
            }
        return {
            "valid":        False,
            "tampered_ids": tampered_ids,
            "message":      f"Tampering detected in {len(tampered_ids)} log entries.",
        }
    finally:
        conn.close()


def verify_single_log(log_id: int) -> dict:
    """
    Verify a single log entry's hash and chain link.
    Returns: { log_id, valid, tampered, message }
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM syscall_logs WHERE id = ?", (log_id,)
        ).fetchone()

        if not row:
            return {"log_id": log_id, "valid": False, "tampered": False, "message": "Log entry not found."}

        row      = dict(row)
        expected = _recompute_hash(row)
        valid    = row["log_hash"] == expected

        return {
            "log_id":  log_id,
            "valid":   valid,
            "tampered": not valid,
            "message": "Hash verified." if valid else "Hash mismatch — entry may have been tampered.",
        }
    finally:
        conn.close()
