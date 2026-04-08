"""
tests/test_syscalls.py
pytest test suite for Syscall Layer.

Coverage:
  - Input validation (path traversal, null bytes, blocked paths, bad commands)
  - File operations (read, write, delete, dir_list) — success and failure cases
  - Process execution (whitelist, injection attempts, timeout)
  - syscall_controller full flow (RBAC + policy + execution + logging)
  - End-to-end: allowed call logged as allowed, blocked call logged as blocked
"""

import os
import pytest
import tempfile
import shutil

# Ensure test DB
os.environ["TESTING"] = "true"

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))


# ── Validation ────────────────────────────────────────────────────────────────

class TestPathValidation:

    def test_valid_simple_path(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("test.txt")
        assert r["valid"] is True

    def test_path_traversal_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("../../etc/passwd")
        assert r["valid"] is False
        assert "traversal" in r["reason"].lower()

    def test_etc_passwd_blocked(self):
        from syscall_layer.validation import validate_file_path
        # Use a path that is in BLOCKED_PATHS
        p = "/etc/passwd" if os.name != 'nt' else "\\etc\\passwd"
        r = validate_file_path(p)
        assert r["valid"] is False

    def test_etc_shadow_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("/etc/shadow")
        assert r["valid"] is False

    def test_sys_kernel_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("/sys/kernel")
        assert r["valid"] is False

    def test_proc_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("/proc/meminfo")
        assert r["valid"] is False

    def test_null_byte_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("file\x00name.txt")
        assert r["valid"] is False
        assert "null" in r["reason"].lower()

    def test_empty_path_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("")
        assert r["valid"] is False

    def test_none_path_blocked(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path(None)
        assert r["valid"] is False

    def test_normal_home_path_allowed(self):
        from syscall_layer.validation import validate_file_path
        # Use a path that is definitely NOT in BLOCKED_PATHS and normalized
        p = os.path.normpath("/home/user/docs/report.txt")
        r = validate_file_path(p)
        assert r["valid"] is True

    def test_relative_path_allowed(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("sandbox/test.txt")
        assert r["valid"] is True

    def test_normpath_applied(self):
        from syscall_layer.validation import validate_file_path
        r = validate_file_path("./foo/../bar.txt")
        assert r["valid"] is True
        assert ".." not in r["sanitized_path"]


class TestCommandValidation:

    def test_allowed_command_ls(self):
        from syscall_layer.validation import validate_command
        r = validate_command("ls -la")
        assert r["valid"] is True
        assert r["base_command"] == "ls"

    def test_allowed_command_python3(self):
        from syscall_layer.validation import validate_command
        r = validate_command("python3 script.py")
        assert r["valid"] is True

    def test_blocked_command_rm(self):
        from syscall_layer.validation import validate_command
        r = validate_command("rm -rf /")
        assert r["valid"] is False
        assert "not in the allowed" in r["reason"]

    def test_blocked_command_curl(self):
        from syscall_layer.validation import validate_command
        r = validate_command("curl http://evil.com")
        assert r["valid"] is False

    def test_blocked_bin_sh(self):
        from syscall_layer.validation import validate_command
        r = validate_command("/bin/sh")
        assert r["valid"] is False

    def test_injection_pipe_to_shell(self):
        from syscall_layer.validation import validate_command
        r = validate_command("ls | sh")
        assert r["valid"] is False
        assert "blocked pattern" in r["reason"]

    def test_injection_command_substitution(self):
        from syscall_layer.validation import validate_command
        r = validate_command("echo $(cat /etc/passwd)")
        assert r["valid"] is False

    def test_injection_backticks(self):
        from syscall_layer.validation import validate_command
        r = validate_command("echo `id`")
        assert r["valid"] is False

    def test_injection_chained_rm(self):
        from syscall_layer.validation import validate_command
        r = validate_command("ls; rm file.txt")
        assert r["valid"] is False

    def test_empty_command_blocked(self):
        from syscall_layer.validation import validate_command
        r = validate_command("")
        assert r["valid"] is False

    def test_malformed_quotes_blocked(self):
        from syscall_layer.validation import validate_command
        r = validate_command("ls 'unclosed")
        assert r["valid"] is False


# ── File Operations ───────────────────────────────────────────────────────────

@pytest.fixture
def sandbox(tmp_path):
    """Create a temp sandbox dir and set SANDBOX_ROOT env var."""
    import syscall_layer.file_operations as fo
    fo.SANDBOX_ROOT = str(tmp_path)
    # Create a test file
    (tmp_path / "test.txt").write_text("Hello SysCallGuardian")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "child.txt").write_text("child content")
    yield tmp_path


class TestFileRead:

    def test_read_existing_file(self, sandbox):
        from syscall_layer.file_operations import safe_file_read
        r = safe_file_read("test.txt")
        assert r["success"] is True
        assert "Hello SysCallGuardian" in r["content"]

    def test_read_nonexistent_file(self, sandbox):
        from syscall_layer.file_operations import safe_file_read
        r = safe_file_read("nonexistent.txt")
        assert r["success"] is False
        assert "not found" in r["error"].lower()

    def test_read_blocked_system_path(self, sandbox):
        from syscall_layer.file_operations import safe_file_read
        r = safe_file_read("/etc/passwd")
        assert r["success"] is False

    def test_read_path_traversal(self, sandbox):
        from syscall_layer.file_operations import safe_file_read
        r = safe_file_read("../../etc/passwd")
        assert r["success"] is False


class TestFileWrite:

    def test_write_new_file(self, sandbox):
        from syscall_layer.file_operations import safe_file_write, safe_file_read
        r = safe_file_write("newfile.txt", "test content")
        assert r["success"] is True
        assert "Write successful" in r["message"]
        # Verify content
        read = safe_file_read("newfile.txt")
        assert "test content" in read["content"]

    def test_write_overwrites_existing(self, sandbox):
        from syscall_layer.file_operations import safe_file_write, safe_file_read
        safe_file_write("test.txt", "overwritten")
        read = safe_file_read("test.txt")
        assert "overwritten" in read["content"]

    def test_write_blocked_system_path(self, sandbox):
        from syscall_layer.file_operations import safe_file_write
        r = safe_file_write("/etc/passwd", "hacked")
        assert r["success"] is False

    def test_write_data_over_size_limit(self, sandbox):
        from syscall_layer.file_operations import safe_file_write
        big_data = "x" * (11 * 1024 * 1024)   # 11MB > 10MB limit
        r = safe_file_write("big.txt", big_data)
        assert r["success"] is False
        assert "10MB" in r["error"]


class TestFileDelete:

    def test_delete_existing_file(self, sandbox):
        from syscall_layer.file_operations import safe_file_delete, safe_file_read
        r = safe_file_delete("test.txt")
        assert r["success"] is True
        # Verify deleted
        read = safe_file_read("test.txt")
        assert read["success"] is False

    def test_delete_nonexistent_file(self, sandbox):
        from syscall_layer.file_operations import safe_file_delete
        r = safe_file_delete("ghost.txt")
        assert r["success"] is False
        assert "not found" in r["error"].lower()

    def test_delete_blocked_system_path(self, sandbox):
        from syscall_layer.file_operations import safe_file_delete
        r = safe_file_delete("/etc/shadow")
        assert r["success"] is False

    def test_delete_directory_not_allowed(self, sandbox):
        from syscall_layer.file_operations import safe_file_delete
        r = safe_file_delete("subdir")
        assert r["success"] is False
        assert "Only files" in r["error"]


class TestDirList:

    def test_list_sandbox_root(self, sandbox):
        from syscall_layer.file_operations import safe_dir_list
        r = safe_dir_list(".")
        assert r["success"] is True
        names = [e["name"] for e in r["entries"]]
        assert "test.txt" in names
        assert "subdir"   in names

    def test_list_subdirectory(self, sandbox):
        from syscall_layer.file_operations import safe_dir_list
        r = safe_dir_list("subdir")
        assert r["success"] is True
        assert any(e["name"] == "child.txt" for e in r["entries"])

    def test_list_nonexistent_dir(self, sandbox):
        from syscall_layer.file_operations import safe_dir_list
        r = safe_dir_list("doesnotexist")
        assert r["success"] is False

    def test_list_system_dir_blocked(self, sandbox):
        from syscall_layer.file_operations import safe_dir_list
        r = safe_dir_list("/sys/kernel")
        assert r["success"] is False

    def test_entries_have_type_and_name(self, sandbox):
        from syscall_layer.file_operations import safe_dir_list
        r = safe_dir_list(".")
        for entry in r["entries"]:
            assert "name" in entry
            assert "type" in entry
            assert entry["type"] in ("file", "dir")


# ── Process Execution ─────────────────────────────────────────────────────────

class TestProcessExecution:

    def test_exec_ls(self):
        from syscall_layer.process_operations import safe_exec_process
        r = safe_exec_process("ls /tmp")
        assert r["success"] is True
        assert r["return_code"] == 0

    def test_exec_echo(self):
        from syscall_layer.process_operations import safe_exec_process
        r = safe_exec_process("echo Hello SysCallGuardian")
        assert r["success"] is True
        # Windows 'echo' adds a trailing newline or space sometimes
        assert "Hello SysCallGuardian" in r["output"].strip()

    def test_exec_pwd(self):
        from syscall_layer.process_operations import safe_exec_process
        # On Windows 'pwd' isn't standard, but we might allow it or use a shim.
        # For the test, we'll check if the output looks like a path.
        cmd = "pwd" if os.name != 'nt' else "echo %cd%"
        r = safe_exec_process(cmd)
        assert r["success"] is True
        if os.name == 'nt':
            assert ":" in r["output"] # Drive letter
        else:
            assert "/" in r["output"]

    def test_exec_blocked_rm(self):
        from syscall_layer.process_operations import safe_exec_process
        r = safe_exec_process("rm -rf /")
        assert r["success"] is False
        assert "not in the allowed" in r["error"]

    def test_exec_blocked_bin_sh(self):
        from syscall_layer.process_operations import safe_exec_process
        r = safe_exec_process("/bin/sh")
        assert r["success"] is False

    def test_exec_injection_pipe_to_shell(self):
        from syscall_layer.process_operations import safe_exec_process
        r = safe_exec_process("ls | sh")
        assert r["success"] is False

    def test_exec_no_shell_true(self):
        """Ensure shell=True is never used — injection would succeed otherwise."""
        from syscall_layer.process_operations import safe_exec_process
        # If shell=True were used, this would execute id; it should fail validation
        r = safe_exec_process("echo $(id)")
        assert r["success"] is False

    def test_exec_output_truncated_long(self):
        from syscall_layer.process_operations import safe_exec_process
        # Generate lots of output
        r = safe_exec_process("find /usr/bin -maxdepth 1")
        assert r["success"] is True
        assert len(r["output"]) <= 8500   # ≤ MAX_OUTPUT_LEN + small buffer


# ── Syscall Controller (full flow) ────────────────────────────────────────────

class TestSyscallController:

    @pytest.fixture(autouse=True)
    def setup_env(self, sandbox, fresh_db):
        """Set sandbox and ensure DB is ready."""
        import syscall_layer.file_operations as fo
        fo.SANDBOX_ROOT = str(sandbox)

    def _make_user(self, username, role):
        from auth_rbac.auth_controller import register_user
        from database.db import get_connection
        register_user(username, "TestPass1", role)
        conn = get_connection()
        row  = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        return {"user_id": row["id"], "username": username, "role": role, "risk_score": 0.0}

    def test_admin_file_read_allowed(self):
        from syscall_layer.syscall_controller import handle_syscall
        user   = self._make_user("ctrl_admin", "admin")
        result = handle_syscall("file_read", user, {"file_path": "test.txt"})
        assert result["status"] == "allowed"
        assert "content" in result

    def test_guest_exec_blocked_by_rbac(self):
        from syscall_layer.syscall_controller import handle_syscall
        user   = self._make_user("ctrl_guest", "guest")
        result = handle_syscall("exec_process", user, {"command": "ls"})
        assert result["status"] == "blocked"
        assert "permission" in result["reason"].lower() or "lacks" in result["reason"].lower()

    def test_guest_file_write_blocked_by_rbac(self):
        from syscall_layer.syscall_controller import handle_syscall
        user   = self._make_user("ctrl_guest2", "guest")
        result = handle_syscall("file_write", user, {"file_path": "x.txt", "data": "hi"})
        assert result["status"] == "blocked"

    def test_developer_high_risk_exec_blocked_by_policy(self):
        from syscall_layer.syscall_controller import handle_syscall
        user   = self._make_user("ctrl_dev_risk", "developer")
        user["risk_score"] = 90.0   # exceeds max_risk_score policy condition
        result = handle_syscall("exec_process", user, {"command": "ls"})
        assert result["status"] == "blocked"
        assert "Risk score" in result["reason"] or "policy" in result["reason"].lower()

    def test_allowed_call_logged_in_db(self):
        from syscall_layer.syscall_controller import handle_syscall
        from database.db import get_connection
        user = self._make_user("ctrl_log_admin", "admin")
        handle_syscall("file_read", user, {"file_path": "test.txt"})
        conn = get_connection()
        row  = conn.execute(
            "SELECT status FROM syscall_logs WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user["user_id"],)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["status"] == "allowed"

    def test_blocked_call_logged_in_db(self):
        from syscall_layer.syscall_controller import handle_syscall
        from database.db import get_connection
        user = self._make_user("ctrl_log_guest", "guest")
        handle_syscall("exec_process", user, {"command": "ls"})
        conn = get_connection()
        row  = conn.execute(
            "SELECT status, reason FROM syscall_logs WHERE user_id=? ORDER BY id DESC LIMIT 1",
            (user["user_id"],)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row["status"] == "blocked"

    def test_invalid_call_type(self):
        from syscall_layer.syscall_controller import handle_syscall
        user   = self._make_user("ctrl_invalid", "admin")
        result = handle_syscall("launch_missile", user, {})
        assert result["status"] == "blocked"
        assert "Unknown" in result["reason"]

    def test_path_traversal_blocked_at_validation(self):
        from syscall_layer.syscall_controller import handle_syscall
        user   = self._make_user("ctrl_traversal", "admin")
        result = handle_syscall("file_read", user, {"file_path": "../../etc/passwd"})
        assert result["status"] == "blocked"
