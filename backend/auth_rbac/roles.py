"""
auth_rbac/roles.py
Role definitions, permission map, and access decision logic.
"""

import json
from database.db import get_connection

# Role hierarchy: index = privilege level. Higher = more access.
ROLE_HIERARCHY = ["guest", "developer", "admin"]

# In-memory permission cache
_permission_cache: dict[str, set[str]] = {}


def load_permissions() -> dict[str, set[str]]:
    """Load role → permissions map from DB into cache. Call at app startup."""
    global _permission_cache
    conn = get_connection()
    try:
        rows = conn.execute("SELECT role, permissions FROM roles").fetchall()
        _permission_cache = {
            row["role"]: set(json.loads(row["permissions"]))
            for row in rows
        }
        return _permission_cache
    finally:
        conn.close()


def get_permissions(role: str) -> set[str]:
    """Return permission set for a role. Loads from DB if cache is empty."""
    if not _permission_cache:
        load_permissions()
    return _permission_cache.get(role, set())


def can_perform(role: str, permission: str) -> bool:
    """
    Core access decision.
    Returns True if role has the given permission.

    Examples:
        can_perform("developer", "file_write")   → True
        can_perform("guest", "exec_process")     → False
        can_perform("admin", "manage_policies")  → True
    """
    return permission in get_permissions(role)


def has_minimum_role(user_role: str, required_role: str) -> bool:
    """
    Hierarchy check: does user_role meet or exceed required_role?

    Examples:
        has_minimum_role("admin", "developer")  → True
        has_minimum_role("guest", "developer")  → False
    """
    try:
        return ROLE_HIERARCHY.index(user_role) >= ROLE_HIERARCHY.index(required_role)
    except ValueError:
        return False


def get_all_roles() -> dict:
    """Return full role → permissions map (for admin dashboard)."""
    if not _permission_cache:
        load_permissions()
    return {role: list(perms) for role, perms in _permission_cache.items()}
