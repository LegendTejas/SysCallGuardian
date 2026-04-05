"""
syscall/syscall_wrapper.py
Vanshika — Secure System Call Wrapper Layer.

This is the CORE of Vanshika's work.
Every file/command operation passes through here AFTER RBAC approval.

Flow:
    Request → RBAC (Tejas) → syscall_wrapper (Vanshika) → OS
                                       ↓
                               logger + threat_engine (Vanshika)
"""

import os
import re
import subprocess

# ── Constants ─────────────────────────────────────────────────────────────────

# The only directory users are allowed to work inside
SAFE_BASE_DIR = os.path.abspath("user_sandbox")

# Dangerous path patterns that must always be blocked
BLOCKED_PATH_PATTERNS = [
    r"\.\.",            # path traversal: ../../etc/passwd
    r"^/etc",           # system config
    r"^/root",          # root home
    r"^/sys",           # kernel sys
    r"^/proc",          # process info
    r"^/bin",           # system binaries
    r"^/usr",           # system programs
    r"^/boot",          # bootloader
    r"^/dev",           # device files
    r"^/var",           # system logs/data
]

# Commands that are allowed to execute
ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "echo", "cat", "date", "id"}

# Commands that are always blocked no matter what
BLOCKED_COMMANDS = {
    "rm", "rmdir", "dd", "mkfs", "shutdown", "reboot", "halt",
    "sudo", "su", "chmod", "chown", "kill", "pkill", "wget",
    "curl", "nc", "netcat", "bash", "sh", "python", "perl",
    "iptables", "passwd", "useradd", "userdel"
}


# ── Path Sanitization ─────────────────────────────────────────────────────────

def sanitize_path(raw_path: str) -> dict:
    """
    Validate and sanitize a file path before any operation.

    Checks:
      1. Path is not empty
      2. No dangerous patterns (../, /etc, /root, etc.)
      3. Path stays inside SAFE_BASE_DIR after resolving

    Returns:
        { "safe": True,  "path": <resolved_path> }
        { "safe": False, "reason": <why_blocked> }
    """
    if not raw_path or not raw_path.strip():
        return {"safe": False, "reason": "Path cannot be empty."}

    raw_path = raw_path.strip()

    # Check against dangerous patterns
    for pattern in BLOCKED_PATH_PATTERNS:
        if re.search(pattern, raw_path):
            return {
                "safe": False,
                "reason": f"Blocked path pattern detected: '{pattern}' in '{raw_path}'."
            }

    # Resolve absolute path and make sure it stays inside sandbox
    resolved = os.path.abspath(os.path.join(SAFE_BASE_DIR, raw_path.lstrip("/")))

    if not resolved.startswith(SAFE_BASE_DIR):
        return {
            "safe": False,
            "reason": f"Path escapes sandbox directory. Resolved: '{resolved}'."
        }

    return {"safe": True, "path": resolved}


# ── Command Validation ────────────────────────────────────────────────────────

def validate_command(command: str) -> dict:
    """
    Validate a shell command before execution.

    Checks:
      1. Command is not empty
      2. Base command is not in BLOCKED_COMMANDS
      3. Base command is in ALLOWED_COMMANDS whitelist

    Returns:
        { "safe": True }
        { "safe": False, "reason": <why_blocked> }
    """
    if not command or not command.strip():
        return {"safe": False, "reason": "Command cannot be empty."}

    # Extract just the base command (first word)
    base_cmd = command.strip().split()[0].lower()

    # Check blocked list first
    if base_cmd in BLOCKED_COMMANDS:
        return {
            "safe": False,
            "reason": f"Command '{base_cmd}' is explicitly blocked for security reasons."
        }

    # Check against whitelist
    if base_cmd not in ALLOWED_COMMANDS:
        return {
            "safe": False,
            "reason": f"Command '{base_cmd}' is not in the allowed commands list."
        }

    return {"safe": True}


# ── Syscall Operations ────────────────────────────────────────────────────────

def do_file_read(path: str) -> dict:
    """
    Safely read a file from inside the sandbox.

    Returns:
        { "success": True,  "content": <file_content> }
        { "success": False, "reason": <error_message> }
    """
    check = sanitize_path(path)
    if not check["safe"]:
        return {"success": False, "reason": check["reason"]}

    safe_path = check["path"]

    if not os.path.exists(safe_path):
        return {"success": False, "reason": f"File not found: '{path}'."}

    if not os.path.isfile(safe_path):
        return {"success": False, "reason": f"'{path}' is not a file."}

    try:
        with open(safe_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return {"success": True, "content": content}
    except Exception as e:
        return {"success": False, "reason": f"Read error: {str(e)}"}


def do_file_write(path: str, content: str) -> dict:
    """
    Safely write content to a file inside the sandbox.

    Returns:
        { "success": True,  "message": "Written successfully." }
        { "success": False, "reason": <error_message> }
    """
    check = sanitize_path(path)
    if not check["safe"]:
        return {"success": False, "reason": check["reason"]}

    safe_path = check["path"]

    # Create parent directories if they don't exist
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)

    try:
        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content or "")
        return {"success": True, "message": f"File '{path}' written successfully."}
    except Exception as e:
        return {"success": False, "reason": f"Write error: {str(e)}"}


def do_file_delete(path: str) -> dict:
    """
    Safely delete a file from inside the sandbox.

    Returns:
        { "success": True,  "message": "Deleted successfully." }
        { "success": False, "reason": <error_message> }
    """
    check = sanitize_path(path)
    if not check["safe"]:
        return {"success": False, "reason": check["reason"]}

    safe_path = check["path"]

    if not os.path.exists(safe_path):
        return {"success": False, "reason": f"File not found: '{path}'."}

    if not os.path.isfile(safe_path):
        return {"success": False, "reason": f"'{path}' is not a regular file."}

    try:
        os.remove(safe_path)
        return {"success": True, "message": f"File '{path}' deleted successfully."}
    except Exception as e:
        return {"success": False, "reason": f"Delete error: {str(e)}"}


def do_execute(command: str) -> dict:
    """
    Safely execute a whitelisted shell command.

    Returns:
        { "success": True,  "output": <stdout>, "stderr": <stderr> }
        { "success": False, "reason": <error_message> }
    """
    check = validate_command(command)
    if not check["safe"]:
        return {"success": False, "reason": check["reason"]}

    try:
        result = subprocess.run(
            command.strip().split(),
            capture_output=True,
            text=True,
            timeout=5,          # never hang more than 5 seconds
            cwd=SAFE_BASE_DIR   # run inside the sandbox directory
        )
        return {
            "success": True,
            "output":  result.stdout,
            "stderr":  result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "reason": "Command timed out after 5 seconds."}
    except Exception as e:
        return {"success": False, "reason": f"Execution error: {str(e)}"}
