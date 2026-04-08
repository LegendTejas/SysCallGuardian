"""
tests/test_policy.py
pytest test suite for RBAC and Policy Engine.

Coverage:
  - Role permission map (can_perform, has_minimum_role)
  - Policy evaluation: default allow, deny_roles, allow_roles
  - Condition evaluation: max_risk_score, time_range
  - Policy CRUD: create, update, disable
  - Dynamic policy reload affects evaluation
  - Flask middleware decorators (require_auth, require_role, require_permission)
"""

import pytest
import json
from unittest.mock import patch
from datetime import datetime, timezone

from auth_rbac.roles              import load_permissions, can_perform, has_minimum_role, get_permissions
from policy_engine.policy_loader  import (
    create_policy, update_policy, get_all_policies_from_db, reload_policies
)
from policy_engine.policy_evaluator import evaluate
from database.db                  import get_connection


# ── RBAC: Permission Map ──────────────────────────────────────────────────────

class TestPermissionMap:

    def test_admin_has_all_permissions(self):
        admin_perms = get_permissions("admin")
        for perm in ["file_read","file_write","file_delete","dir_list",
                     "exec_process","system_dir_access","view_logs",
                     "manage_policies","view_dashboard"]:
            assert perm in admin_perms, f"Admin missing: {perm}"

    def test_developer_permissions(self):
        dev_perms = get_permissions("developer")
        assert "file_read"   in dev_perms
        assert "file_write"  in dev_perms
        assert "exec_process" in dev_perms
        assert "view_logs"   in dev_perms
        # Developer must NOT have these
        assert "system_dir_access" not in dev_perms
        assert "manage_policies"   not in dev_perms

    def test_guest_permissions(self):
        guest_perms = get_permissions("guest")
        assert "file_read" in guest_perms
        assert "dir_list"  in guest_perms
        # Guest must NOT have these
        assert "file_write"        not in guest_perms
        assert "exec_process"      not in guest_perms
        assert "file_delete"       not in guest_perms
        assert "system_dir_access" not in guest_perms
        assert "manage_policies"   not in guest_perms

    def test_can_perform_true(self):
        assert can_perform("admin",     "manage_policies") is True
        assert can_perform("developer", "file_write")      is True
        assert can_perform("guest",     "file_read")       is True

    def test_can_perform_false(self):
        assert can_perform("guest",     "exec_process")      is False
        assert can_perform("developer", "manage_policies")   is False
        assert can_perform("guest",     "system_dir_access") is False

    def test_unknown_role_has_no_permissions(self):
        assert can_perform("superuser", "file_read") is False
        assert get_permissions("superuser") == set()

    def test_has_minimum_role_hierarchy(self):
        # Admin meets all requirements
        assert has_minimum_role("admin",     "admin")     is True
        assert has_minimum_role("admin",     "developer") is True
        assert has_minimum_role("admin",     "guest")     is True
        # Developer meets developer and guest
        assert has_minimum_role("developer", "developer") is True
        assert has_minimum_role("developer", "guest")     is True
        assert has_minimum_role("developer", "admin")     is False
        # Guest only meets guest
        assert has_minimum_role("guest",     "guest")     is True
        assert has_minimum_role("guest",     "developer") is False
        assert has_minimum_role("guest",     "admin")     is False

    def test_has_minimum_role_unknown(self):
        assert has_minimum_role("unknown", "guest") is False


# ── Policy Evaluation: Default Behavior ──────────────────────────────────────

class TestPolicyEvaluationDefaults:

    def test_no_policy_for_action_allows_by_default(self):
        # "net_socket" has no policy in default seed — should allow
        result = evaluate("net_socket", "guest", {})
        assert result["allowed"] is True
        assert result["policy"]  is None

    def test_admin_exec_allowed_by_default(self):
        result = evaluate("exec_process", "admin", {"risk_score": 0.0})
        assert result["allowed"] is True

    def test_developer_exec_allowed_with_low_risk(self):
        result = evaluate("exec_process", "developer", {"risk_score": 10.0})
        assert result["allowed"] is True

    def test_guest_file_read_allowed_no_policy(self):
        # No policy restricts file_read → default allow
        result = evaluate("file_read", "guest", {})
        assert result["allowed"] is True


# ── Policy Evaluation: Deny Rules ─────────────────────────────────────────────

class TestPolicyDenyRules:

    def test_guest_exec_blocked_by_deny_roles(self):
        result = evaluate("exec_process", "guest", {})
        assert result["allowed"] is False
        assert "guest" in result["reason"]

    def test_guest_file_write_blocked(self):
        result = evaluate("file_write", "guest", {})
        assert result["allowed"] is False

    def test_guest_file_delete_blocked(self):
        result = evaluate("file_delete", "guest", {})
        assert result["allowed"] is False

    def test_developer_file_delete_blocked(self):
        result = evaluate("file_delete", "developer", {})
        assert result["allowed"] is False

    def test_developer_system_dir_blocked(self):
        result = evaluate("system_dir_access", "developer", {})
        assert result["allowed"] is False

    def test_guest_system_dir_blocked(self):
        result = evaluate("system_dir_access", "guest", {})
        assert result["allowed"] is False

    def test_admin_system_dir_allowed(self):
        result = evaluate("system_dir_access", "admin", {"risk_score": 0.0})
        assert result["allowed"] is True


# ── Policy Evaluation: Conditions ─────────────────────────────────────────────

class TestPolicyConditions:

    def test_high_risk_score_blocks_developer_exec(self):
        # high_risk_exec_block: max_risk_score = 60
        result = evaluate("exec_process", "developer", {"risk_score": 90.0})
        assert result["allowed"] is False
        assert "90" in result["reason"] or "Risk score" in result["reason"]

    def test_risk_at_exact_limit_is_allowed(self):
        result = evaluate("exec_process", "developer", {"risk_score": 60.0})
        assert result["allowed"] is True   # 60 == max, not > max

    def test_risk_just_over_limit_is_blocked(self):
        result = evaluate("exec_process", "developer", {"risk_score": 60.1})
        assert result["allowed"] is False

    def test_zero_risk_always_allowed_for_developer(self):
        result = evaluate("exec_process", "developer", {"risk_score": 0.0})
        assert result["allowed"] is True

    def test_time_range_condition_within_window(self):
        # Create a policy with a time range that covers "00:00"–"23:59" (always open)
        create_policy("always_open_test", {
            "action": "file_write",
            "allow_roles": ["developer"],
            "conditions": {"time_range": ["00:00", "23:59"]}
        })
        reload_policies()
        result = evaluate("file_write", "developer", {"risk_score": 0.0})
        assert result["allowed"] is True

    def test_time_range_condition_outside_window(self):
        # Create a policy with an impossible time range
        create_policy("always_closed_test", {
            "action": "dir_list",
            "allow_roles": ["developer", "guest"],
            "conditions": {"time_range": ["99:00", "99:59"]}
        })
        reload_policies()
        result = evaluate("dir_list", "developer", {"risk_score": 0.0})
        assert result["allowed"] is False
        assert "window" in result["reason"]

    def test_context_defaults_to_empty_on_none(self):
        # Should not crash when context is None
        result = evaluate("exec_process", "developer", None)
        assert isinstance(result["allowed"], bool)


# ── Policy CRUD ────────────────────────────────────────────────────────────────

class TestPolicyCRUD:

    def test_create_policy_success(self):
        result = create_policy("test_new_policy", {
            "action": "file_read",
            "allow_roles": ["admin"]
        })
        assert result["success"] is True
        assert "id" in result

    def test_create_duplicate_policy_fails(self):
        create_policy("dup_policy", {"action": "file_read", "allow_roles": ["admin"]})
        result = create_policy("dup_policy", {"action": "file_read", "allow_roles": ["admin"]})
        assert result["success"] is False
        assert "already exists" in result["error"]

    def test_create_policy_invalid_action(self):
        with pytest.raises(ValueError, match="Invalid action"):
            create_policy("bad_action", {"action": "launch_missiles", "allow_roles": ["admin"]})

    def test_create_policy_missing_action(self):
        with pytest.raises(ValueError, match="must contain 'action'"):
            create_policy("no_action", {"allow_roles": ["admin"]})

    def test_create_policy_invalid_role(self):
        with pytest.raises(ValueError, match="Unknown roles"):
            create_policy("bad_role", {"action": "file_read", "allow_roles": ["hacker"]})

    def test_update_policy_rule(self):
        result = create_policy("updatable", {"action": "dir_list", "allow_roles": ["admin"]})
        pid    = result["id"]
        update = update_policy(pid, rule={"action": "dir_list", "allow_roles": ["admin", "developer"]})
        assert update["success"] is True
        # Verify in DB
        conn = get_connection()
        row  = conn.execute("SELECT rule_json FROM policies WHERE id=?", (pid,)).fetchone()
        conn.close()
        rule = json.loads(row["rule_json"])
        assert "developer" in rule["allow_roles"]

    def test_update_policy_disable(self):
        result = create_policy("disableable", {"action": "file_read", "allow_roles": ["admin"]})
        pid    = result["id"]
        update = update_policy(pid, is_active=False)
        assert update["success"] is True
        conn = get_connection()
        row  = conn.execute("SELECT is_active FROM policies WHERE id=?", (pid,)).fetchone()
        conn.close()
        assert row["is_active"] == 0

    def test_update_nonexistent_policy(self):
        result = update_policy(99999, is_active=False)
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_get_all_policies_returns_list(self):
        policies = get_all_policies_from_db()
        assert isinstance(policies, list)
        assert len(policies) >= 5   # at least the 5 seeded defaults

    def test_disabled_policy_not_evaluated(self):
        # Create a policy that blocks admin file_read
        result = create_policy("block_admin_read", {
            "action": "file_read",
            "deny_roles": ["admin"]
        })
        pid = result["id"]
        reload_policies()

        # Should be blocked now
        blocked = evaluate("file_read", "admin", {})
        assert blocked["allowed"] is False

        # Disable the policy
        update_policy(pid, is_active=False)
        reload_policies()

        # Should be allowed now (policy no longer active)
        allowed = evaluate("file_read", "admin", {})
        assert allowed["allowed"] is True


# ── Flask Middleware Decorators ────────────────────────────────────────────────

class TestMiddlewareDecorators:
    """
    Tests for @require_auth, @require_role, @require_permission
    using a minimal Flask test client.
    """

    @pytest.fixture
    def app(self):
        from flask import Flask, jsonify, g
        from auth_rbac.permission_middleware import require_auth, require_role, require_permission

        app = Flask(__name__)
        app.config["TESTING"] = True

        @app.route("/protected")
        @require_auth
        def protected():
            return jsonify({"user": g.user["username"], "role": g.user["role"]})

        @app.route("/admin-only")
        @require_auth
        @require_role("admin")
        def admin_only():
            return jsonify({"ok": True})

        @app.route("/need-exec")
        @require_auth
        @require_permission("exec_process")
        def need_exec():
            return jsonify({"ok": True})

        return app

    def test_protected_route_no_token(self, app):
        with app.test_client() as c:
            resp = c.get("/protected")
            assert resp.status_code == 401

    def test_protected_route_malformed_header(self, app):
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": "Token abc123"})
            assert resp.status_code == 401

    def test_protected_route_valid_token(self, app):
        from auth_rbac.auth_controller import register_user, login_user
        register_user("mw_admin", "ValidPass1", "admin")
        token = login_user("mw_admin", "ValidPass1")["token"]
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["user"] == "mw_admin"
            assert data["role"] == "admin"

    def test_require_role_admin_with_admin_token(self, app):
        from auth_rbac.auth_controller import register_user, login_user
        register_user("mw_admin2", "ValidPass1", "admin")
        token = login_user("mw_admin2", "ValidPass1")["token"]
        with app.test_client() as c:
            resp = c.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    def test_require_role_admin_with_guest_token(self, app):
        from auth_rbac.auth_controller import register_user, login_user
        register_user("mw_guest", "ValidPass1", "guest")
        token = login_user("mw_guest", "ValidPass1")["token"]
        with app.test_client() as c:
            resp = c.get("/admin-only", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    def test_require_permission_exec_guest_denied(self, app):
        from auth_rbac.auth_controller import register_user, login_user
        register_user("mw_guest2", "ValidPass1", "guest")
        token = login_user("mw_guest2", "ValidPass1")["token"]
        with app.test_client() as c:
            resp = c.get("/need-exec", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 403

    def test_require_permission_exec_developer_allowed(self, app):
        from auth_rbac.auth_controller import register_user, login_user
        register_user("mw_dev", "ValidPass1", "developer")
        token = login_user("mw_dev", "ValidPass1")["token"]
        with app.test_client() as c:
            resp = c.get("/need-exec", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 200

    def test_logged_out_token_rejected(self, app):
        from auth_rbac.auth_controller import register_user, login_user, logout_user
        register_user("mw_logout", "ValidPass1", "developer")
        token = login_user("mw_logout", "ValidPass1")["token"]
        logout_user(token)
        with app.test_client() as c:
            resp = c.get("/protected", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 401
