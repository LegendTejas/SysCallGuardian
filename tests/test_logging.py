"""
tests/test_logging.py
pytest test suite for Logging & Threat Detection.

Coverage:
  - audit_logger: write log, verify hash stored, pagination, filters
  - log_integrity: valid chain, tamper detection (edit), tamper detection (delete link)
  - risk_scoring: delta values per call type and role
  - threat_detection: R2 rapid flood, R3 exec blocks, R4 system path, R5 risk threshold
  - End-to-end: blocked calls raise risk_score in DB
"""

import os
import pytest

os.environ["TESTING"] = "true"

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))


# ── Audit Logger ──────────────────────────────────────────────────────────────

class TestAuditLogger:

    @pytest.fixture(autouse=True)
    def register_user(self, fresh_db):
        from auth_rbac.auth_controller import register_user
        from database.db import get_connection
        register_user("log_user", "LogPass1", "developer")
        conn = get_connection()
        row  = conn.execute("SELECT id FROM users WHERE username='log_user'").fetchone()
        conn.close()
        self.user_id = row["id"]

    def test_log_creates_db_entry(self):
        from logging_detection.audit_logger import log_syscall
        from database.db import get_connection
        log_syscall(self.user_id, "file_read", "/test.txt", "allowed")
        conn = get_connection()
        row  = conn.execute(
            "SELECT * FROM syscall_logs WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (self.user_id,)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["call_type"]   == "file_read"
        assert row["target_path"] == os.path.normpath("/test.txt")
        assert row["status"]      == "allowed"

    def test_log_stores_sha256_hash(self):
        from logging_detection.audit_logger import log_syscall
        from database.db import get_connection
        log_syscall(self.user_id, "file_write", "out.txt", "allowed")
        conn = get_connection()
        row  = conn.execute(
            "SELECT log_hash FROM syscall_logs WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (self.user_id,)
        ).fetchone()
        conn.close()
        assert row["log_hash"] is not None
        assert len(row["log_hash"]) == 64   # SHA-256 = 64 hex chars

    def test_log_stores_prev_hash_chain(self):
        from logging_detection.audit_logger import log_syscall
        from database.db import get_connection
        log_syscall(self.user_id, "file_read", "a.txt", "allowed")
        log_syscall(self.user_id, "file_read", "b.txt", "allowed")
        conn  = get_connection()
        rows  = conn.execute(
            "SELECT log_hash, prev_hash FROM syscall_logs ORDER BY id ASC"
        ).fetchall()
        conn.close()
        # Second entry's prev_hash must equal first entry's log_hash
        assert rows[-1]["prev_hash"] == rows[-2]["log_hash"]

    def test_first_log_prev_hash_is_genesis(self):
        from logging_detection.audit_logger import log_syscall
        from database.db import get_connection
        log_syscall(self.user_id, "file_read", "first.txt", "allowed")
        conn = get_connection()
        row  = conn.execute(
            "SELECT prev_hash FROM syscall_logs ORDER BY id ASC LIMIT 1"
        ).fetchone()
        conn.close()
        assert row["prev_hash"] == "GENESIS"

    def test_log_increments_user_risk_score(self):
        from logging_detection.audit_logger import log_syscall
        from database.db import get_connection
        log_syscall(self.user_id, "exec_process", "bad_cmd", "blocked", risk_delta=15.0)
        conn = get_connection()
        row  = conn.execute("SELECT risk_score FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["risk_score"] == 15.0

    def test_log_risk_score_capped_at_100(self):
        from logging_detection.audit_logger import log_syscall
        from database.db import get_connection
        # Set risk to 95 first
        conn = get_connection()
        conn.execute("UPDATE users SET risk_score=95.0 WHERE id=?", (self.user_id,))
        conn.commit()
        conn.close()
        log_syscall(self.user_id, "exec_process", "cmd", "blocked", risk_delta=15.0)
        conn = get_connection()
        row  = conn.execute("SELECT risk_score FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["risk_score"] == 100.0   # capped, not 110

    def test_get_logs_pagination(self):
        from logging_detection.audit_logger import log_syscall, get_logs
        for i in range(15):
            log_syscall(self.user_id, "file_read", f"f{i}.txt", "allowed")
        result = get_logs(page=1, per_page=8)
        assert result["total"] == 15
        assert len(result["logs"]) == 8

    def test_get_logs_second_page(self):
        from logging_detection.audit_logger import log_syscall, get_logs
        for i in range(15):
            log_syscall(self.user_id, "file_read", f"f{i}.txt", "allowed")
        result = get_logs(page=2, per_page=8)
        assert len(result["logs"]) == 7   # 15 - 8 = 7

    def test_get_logs_filter_by_status(self):
        from logging_detection.audit_logger import log_syscall, get_logs
        log_syscall(self.user_id, "file_read",  "a.txt", "allowed")
        log_syscall(self.user_id, "exec_process","b",    "blocked")
        log_syscall(self.user_id, "file_write", "c.txt", "allowed")
        result = get_logs(status="blocked")
        assert result["total"] == 1
        assert result["logs"][0]["status"] == "blocked"

    def test_get_logs_filter_by_call_type(self):
        from logging_detection.audit_logger import log_syscall, get_logs
        log_syscall(self.user_id, "file_read",   "a.txt", "allowed")
        log_syscall(self.user_id, "exec_process","ls",    "allowed")
        result = get_logs(call_type="exec_process")
        assert result["total"] == 1

    def test_get_logs_most_recent_first(self):
        from logging_detection.audit_logger import log_syscall, get_logs
        log_syscall(self.user_id, "file_read", "first.txt",  "allowed")
        log_syscall(self.user_id, "file_read", "second.txt", "blocked")
        result = get_logs(page=1, per_page=10)
        assert result["logs"][0]["target_path"] == "second.txt"


# ── Log Integrity ─────────────────────────────────────────────────────────────

class TestLogIntegrity:

    @pytest.fixture(autouse=True)
    def setup_logs(self, fresh_db):
        from auth_rbac.auth_controller import register_user
        from database.db import get_connection
        from logging_detection.audit_logger import log_syscall
        register_user("integrity_user", "IntPass1", "developer")
        conn    = get_connection()
        row     = conn.execute("SELECT id FROM users WHERE username='integrity_user'").fetchone()
        conn.close()
        self.user_id = row["id"]
        # Write 5 chained log entries
        for i in range(5):
            log_syscall(self.user_id, "file_read", f"file{i}.txt", "allowed")

    def test_verify_all_valid_chain(self):
        from logging_detection.log_integrity import verify_all_logs
        result = verify_all_logs()
        assert result["valid"] is True
        assert result["tampered_ids"] == []

    def test_verify_single_valid_entry(self):
        from logging_detection.log_integrity import verify_single_log
        from database.db import get_connection
        conn = get_connection()
        row  = conn.execute("SELECT id FROM syscall_logs LIMIT 1").fetchone()
        conn.close()
        result = verify_single_log(row["id"])
        assert result["valid"]   is True
        assert result["tampered"] is False

    def test_verify_single_nonexistent(self):
        from logging_detection.log_integrity import verify_single_log
        result = verify_single_log(99999)
        assert result["valid"]   is False
        assert result["tampered"] is False

    def test_tamper_detection_hash_edit(self):
        """Directly corrupt a log_hash in DB — chain verifier must catch it."""
        from logging_detection.log_integrity import verify_all_logs
        from database.db import get_connection
        conn = get_connection()
        row  = conn.execute("SELECT id FROM syscall_logs ORDER BY id ASC LIMIT 1 OFFSET 2").fetchone()
        conn.execute(
            "UPDATE syscall_logs SET log_hash='deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE id=?",
            (row["id"],)
        )
        conn.commit()
        conn.close()
        result = verify_all_logs()
        assert result["valid"] is False
        assert row["id"] in result["tampered_ids"]

    def test_tamper_detection_data_edit(self):
        """Edit a log's target_path — hash recompute will mismatch stored hash."""
        from logging_detection.log_integrity import verify_all_logs
        from database.db import get_connection
        conn = get_connection()
        row  = conn.execute("SELECT id FROM syscall_logs ORDER BY id ASC LIMIT 1").fetchone()
        p = "/etc/passwd" if os.name != 'nt' else "\\etc\\passwd"
        conn.execute(
            "UPDATE syscall_logs SET target_path=? WHERE id=?",
            (p, row["id"])
        )
        conn.commit()
        conn.close()
        result = verify_all_logs()
        assert result["valid"] is False

    def test_empty_log_table_is_valid(self, fresh_db):
        from logging_detection.log_integrity import verify_all_logs
        result = verify_all_logs()
        assert result["valid"] is True
        assert result["tampered_ids"] == []


# ── Risk Scoring ──────────────────────────────────────────────────────────────

class TestRiskScoring:

    def test_allowed_call_zero_delta(self):
        from logging_detection.risk_scoring import compute_risk_delta
        assert compute_risk_delta("allowed", "exec_process", "developer") == 0.0
        assert compute_risk_delta("allowed", "file_write",   "guest")     == 0.0

    def test_admin_always_zero_delta(self):
        from logging_detection.risk_scoring import compute_risk_delta
        for call in ["exec_process","file_delete","system_dir_access","file_write"]:
            assert compute_risk_delta("blocked", call, "admin") == 0.0

    def test_exec_blocked_highest_delta(self):
        from logging_detection.risk_scoring import compute_risk_delta
        delta = compute_risk_delta("blocked", "exec_process", "developer")
        assert delta == 15.0

    def test_system_dir_blocked_highest_delta(self):
        from logging_detection.risk_scoring import compute_risk_delta
        delta = compute_risk_delta("blocked", "system_dir_access", "guest")
        assert delta == 20.0

    def test_file_delete_blocked_delta(self):
        from logging_detection.risk_scoring import compute_risk_delta
        assert compute_risk_delta("blocked", "file_delete", "developer") == 10.0

    def test_flagged_is_half_of_blocked(self):
        from logging_detection.risk_scoring import compute_risk_delta
        blocked  = compute_risk_delta("blocked", "exec_process", "developer")
        flagged  = compute_risk_delta("flagged", "exec_process", "developer")
        assert flagged == blocked * 0.5

    def test_risk_level_classification(self):
        from logging_detection.risk_scoring import get_risk_level
        assert get_risk_level(0)   == "low"
        assert get_risk_level(20)  == "medium"
        assert get_risk_level(40)  == "high"
        assert get_risk_level(70)  == "critical"
        assert get_risk_level(100) == "critical"


# ── Threat Detection ──────────────────────────────────────────────────────────

class TestThreatDetection:

    @pytest.fixture(autouse=True)
    def setup_user(self, fresh_db):
        from auth_rbac.auth_controller import register_user
        from database.db import get_connection
        import logging_detection.threat_detection as td
        td._event_window.clear()   # clear sliding window between tests
        register_user("threat_user", "ThreatPass1", "developer")
        conn = get_connection()
        row  = conn.execute("SELECT id FROM users WHERE username='threat_user'").fetchone()
        conn.close()
        self.user_id = row["id"]

    def test_normal_behavior_no_flag(self):
        from logging_detection.threat_detection import analyze_event
        from database.db import get_connection
        # 3 normal calls — should not flag
        for _ in range(3):
            analyze_event(self.user_id, "threat_user", "file_read", "allowed", "test.txt")
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["is_flagged"] == 0

    def test_r2_rapid_syscall_flood(self):
        """R2: 20+ calls of same type in 60s → flag user."""
        from logging_detection.threat_detection import analyze_event
        from database.db import get_connection
        for _ in range(21):
            analyze_event(self.user_id, "threat_user", "file_read", "allowed", "test.txt")
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["is_flagged"] == 1

    def test_r3_repeated_exec_blocks(self):
        """R3: 3+ exec_process blocks in 5 min → flag user."""
        from logging_detection.threat_detection import analyze_event
        from database.db import get_connection
        for _ in range(3):
            analyze_event(self.user_id, "threat_user", "exec_process", "blocked", "/bin/sh")
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["is_flagged"] == 1

    def test_r4_system_path_probe(self):
        """R4: access to /sys, /proc, /boot → instant flag."""
        from logging_detection.threat_detection import analyze_event
        from database.db import get_connection
        p = "/sys/kernel/debug" if os.name != 'nt' else "\\sys\\kernel\\debug"
        analyze_event(self.user_id, "threat_user", "dir_list", "blocked", p)
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["is_flagged"] == 1

    def test_r4_proc_path_probe(self):
        from logging_detection.threat_detection import analyze_event
        from database.db import get_connection
        p = "/proc/meminfo" if os.name != 'nt' else "\\proc\\meminfo"
        analyze_event(self.user_id, "threat_user", "file_read", "blocked", p)
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["is_flagged"] == 1

    def test_r5_high_risk_score_flags(self):
        """R5: risk_score >= 70 → flag user."""
        from logging_detection.threat_detection import analyze_event
        from database.db import get_connection
        conn = get_connection()
        conn.execute("UPDATE users SET risk_score=75.0 WHERE id=?", (self.user_id,))
        conn.commit()
        conn.close()
        analyze_event(self.user_id, "threat_user", "file_read", "blocked", "any.txt")
        conn = get_connection()
        row  = conn.execute("SELECT is_flagged FROM users WHERE id=?", (self.user_id,)).fetchone()
        conn.close()
        assert row["is_flagged"] == 1

    def test_get_suspicious_users_returns_flagged(self):
        from logging_detection.threat_detection import analyze_event, get_suspicious_users
        from database.db import get_connection
        # Flag the user
        conn = get_connection()
        conn.execute("UPDATE users SET is_flagged=1, risk_score=85.0 WHERE id=?", (self.user_id,))
        conn.commit()
        conn.close()
        users = get_suspicious_users()
        assert any(u["user_id"] == self.user_id for u in users)

    def test_get_suspicious_users_includes_high_risk_unflagged(self):
        """Users with risk >= 20 appear even if not explicitly flagged."""
        from logging_detection.threat_detection import get_suspicious_users
        from database.db import get_connection
        conn = get_connection()
        conn.execute("UPDATE users SET risk_score=25.0 WHERE id=?", (self.user_id,))
        conn.commit()
        conn.close()
        users = get_suspicious_users()
        assert any(u["user_id"] == self.user_id for u in users)
