"""
policy_engine/policy_evaluator.py
Tejas — Rule evaluation engine. Core of the policy decision system.

Policy Rule Format (stored as JSON in DB):
{
  "action":      "exec_process",
  "allow_roles": ["admin", "developer"],
  "deny_roles":  ["guest"],
  "conditions":  {
    "max_risk_score": 60,
    "time_range": ["09:00", "18:00"]   # UTC
  }
}

Decision order:
  1. No matching active policy   → ALLOW (default permissive)
  2. Role in deny_roles          → DENY
  3. Role not in allow_roles     → DENY
  4. Condition fails             → DENY
  5. All checks pass             → ALLOW
"""

from datetime import datetime, timezone
from policy_engine.policy_loader import get_cached_policies


def evaluate(action: str, role: str, context: dict = None) -> dict:
    """
    Evaluate whether role can perform action under active policies.

    Args:
        action  : syscall type e.g. "exec_process", "file_write"
        role    : user role e.g. "admin", "developer", "guest"
        context : dict with runtime info e.g. { "risk_score": 45.0 }

    Returns:
        {
          "allowed": bool,
          "reason":  str,
          "policy":  str | None   ← name of deciding policy
        }
    """
    context  = context or {}
    policies = get_cached_policies()

    matching = [p for p in policies if p["rule"].get("action") == action]

    if not matching:
        return {
            "allowed": True,
            "reason":  "No active policy restricts this action.",
            "policy":  None,
        }

    for policy in matching:
        rule   = policy["rule"]
        name   = policy["name"]

        # 1. Explicit deny
        if role in rule.get("deny_roles", []):
            return {
                "allowed": False,
                "reason":  f"Role '{role}' is explicitly denied by policy '{name}'.",
                "policy":  name,
            }

        # 2. Not in allow list
        allow_roles = rule.get("allow_roles", [])
        if allow_roles and role not in allow_roles:
            return {
                "allowed": False,
                "reason":  f"Role '{role}' is not permitted for '{action}' (policy: '{name}').",
                "policy":  name,
            }

        # 3. Condition checks
        result = _check_conditions(rule.get("conditions", {}), context, name)
        if not result["passed"]:
            return {
                "allowed": False,
                "reason":  result["reason"],
                "policy":  name,
            }

    return {
        "allowed": True,
        "reason":  "All policy checks passed.",
        "policy":  None,
    }


def _check_conditions(conditions: dict, context: dict, policy_name: str) -> dict:
    """
    Evaluate optional conditions.

    Supported:
      max_risk_score : deny if context["risk_score"] > value
      time_range     : deny if current UTC time is outside ["HH:MM", "HH:MM"]
    """
    if not conditions:
        return {"passed": True, "reason": ""}

    # max_risk_score
    max_risk = conditions.get("max_risk_score")
    if max_risk is not None:
        user_risk = context.get("risk_score", 0.0)
        if user_risk > max_risk:
            return {
                "passed": False,
                "reason": (
                    f"Risk score {user_risk:.1f} exceeds limit {max_risk} "
                    f"(policy: '{policy_name}')."
                ),
            }

    # time_range
    time_range = conditions.get("time_range")
    if time_range and len(time_range) == 2:
        now   = datetime.now(timezone.utc).strftime("%H:%M")
        start, end = time_range
        if not (start <= now <= end):
            return {
                "passed": False,
                "reason": (
                    f"Access outside allowed window {start}–{end} UTC "
                    f"(policy: '{policy_name}')."
                ),
            }

    return {"passed": True, "reason": ""}
