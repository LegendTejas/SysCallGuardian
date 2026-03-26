"""
policy_engine/policy_loader.py
Tejas — Load policies from DB and sync from JSON/YAML files.
"""

import json
import os
from database.db import get_connection

# In-memory policy cache
_policy_cache: list[dict] = []


def load_policies() -> list[dict]:
    """Load all active policies from DB into memory. Call at app startup."""
    global _policy_cache
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, name, rule_json, is_active FROM policies WHERE is_active = 1"
        ).fetchall()
        _policy_cache = [
            {
                "id":       row["id"],
                "name":     row["name"],
                "rule":     json.loads(row["rule_json"]),
                "is_active": bool(row["is_active"]),
            }
            for row in rows
        ]
        return _policy_cache
    finally:
        conn.close()


def get_cached_policies() -> list[dict]:
    """Return in-memory policy cache (load if empty)."""
    if not _policy_cache:
        load_policies()
    return _policy_cache


def reload_policies():
    """Force-refresh policy cache from DB."""
    load_policies()


def get_all_policies_from_db() -> list[dict]:
    """Return all policies including inactive ones (for admin UI)."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT id, name, rule_json, is_active, updated_at FROM policies"
        ).fetchall()
        return [
            {
                "id":         row["id"],
                "name":       row["name"],
                "rule_json":  json.loads(row["rule_json"]),
                "is_active":  bool(row["is_active"]),
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    finally:
        conn.close()


def create_policy(name: str, rule: dict) -> dict:
    """Insert a new policy into DB."""
    _validate_rule(rule)
    conn = get_connection()
    try:
        cursor = conn.execute(
            "INSERT INTO policies (name, rule_json) VALUES (?, ?)",
            (name, json.dumps(rule))
        )
        conn.commit()
        reload_policies()
        return {"success": True, "id": cursor.lastrowid}
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            return {"success": False, "error": f"Policy '{name}' already exists."}
        return {"success": False, "error": str(e)}
    finally:
        conn.close()


def update_policy(policy_id: int, rule: dict = None, is_active: bool = None) -> dict:
    """Update an existing policy's rule and/or active flag."""
    conn = get_connection()
    try:
        existing = conn.execute(
            "SELECT * FROM policies WHERE id = ?", (policy_id,)
        ).fetchone()
        if not existing:
            return {"success": False, "error": f"Policy ID {policy_id} not found."}

        new_rule      = json.dumps(rule) if rule else existing["rule_json"]
        new_is_active = int(is_active) if is_active is not None else existing["is_active"]

        conn.execute(
            "UPDATE policies SET rule_json=?, is_active=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (new_rule, new_is_active, policy_id)
        )
        conn.commit()
        reload_policies()
        return {"success": True, "message": "Policy updated."}
    finally:
        conn.close()


def import_from_file(filepath: str) -> dict:
    """
    Import policies from policies/access_policy.json or a YAML file.
    Skips duplicates silently.
    """
    if not os.path.exists(filepath):
        return {"success": False, "error": f"File not found: {filepath}"}
    try:
        if filepath.endswith((".yaml", ".yml")):
            import yaml
            with open(filepath) as f:
                entries = yaml.safe_load(f)
        else:
            with open(filepath) as f:
                entries = json.load(f)

        created = skipped = 0
        for entry in entries:
            result = create_policy(entry["name"], entry["rule"])
            if result["success"]:
                created += 1
            else:
                skipped += 1

        return {"success": True, "created": created, "skipped": skipped}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Validation ────────────────────────────────────────────────────────────────

VALID_ACTIONS = {
    "file_read", "file_write", "file_delete",
    "dir_list", "exec_process", "system_dir_access"
}
VALID_ROLES = {"admin", "developer", "guest"}


def _validate_rule(rule: dict):
    if "action" not in rule:
        raise ValueError("Policy rule must contain 'action'.")
    if rule["action"] not in VALID_ACTIONS:
        raise ValueError(f"Invalid action '{rule['action']}'. Valid: {VALID_ACTIONS}")
    for key in ("allow_roles", "deny_roles"):
        if key in rule:
            invalid = set(rule[key]) - VALID_ROLES
            if invalid:
                raise ValueError(f"Unknown roles in '{key}': {invalid}")