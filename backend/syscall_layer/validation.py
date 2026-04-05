"""
syscall_layer/validation.py
Vanshika — Input validation and path sanitization for all syscall operations.
"""

import os
import re
import shlex

# Directories that are always blocked regardless of role
# We normalize these on startup for the current OS
BLOCKED_PATHS = [
    os.path.normpath(p) for p in [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/proc", "/sys/kernel", "/dev",
        "/boot", "/root",
    ]
]

# Only these commands are whitelisted for exec_process
ALLOWED_COMMANDS = {
    "ls", "pwd", "whoami", "echo", "cat", "head", "tail",
    "python3", "python", "node", "java", "grep", "find",
    "mkdir", "touch", "cp", "mv", "wc", "sort", "uniq",
    "dir", "type", "cls", "ver", "copy", "move", "del", "attrib",
    "hostname", "ipconfig", "netstat",
}

# Blocked command patterns (even if base command is allowed)
BLOCKED_PATTERNS = [
    r";\s*rm\s",          # chained rm
    r"\|\s*sh",           # pipe to shell
    r"&&\s*curl",         # chained curl
    r">\s*/etc",          # redirect to /etc
    r"`.*`",              # backtick substitution
    r"\$\(",              # command substitution
    r"\.\.\/",            # path traversal
]


def validate_file_path(path: str) -> dict:
    """
    Validate and sanitize a file path.
    Returns { valid: bool, reason: str, sanitized_path: str }
    """
    if not path or not isinstance(path, str):
        return {"valid": False, "reason": "Path must be a non-empty string.", "sanitized_path": ""}

    # Normalize the path (removes ../ traversal, converts / to \ on Windows)
    sanitized = os.path.normpath(path)

    # Block absolute system paths
    for blocked in BLOCKED_PATHS:
        if sanitized == blocked or sanitized.startswith(blocked + os.sep):
            return {
                "valid": False,
                "reason": f"Access to '{blocked}' is restricted.",
                "sanitized_path": sanitized,
            }

    # Block path traversal attempts (after normalization)
    parts = sanitized.split(os.sep)
    if ".." in parts or sanitized.startswith(".."):
        return {
            "valid": False,
            "reason": "Path traversal (../) is not permitted.",
            "sanitized_path": sanitized,
        }

    # Block null bytes
    if "\x00" in path:
        return {
            "valid": False,
            "reason": "Null bytes in path are not allowed.",
            "sanitized_path": sanitized,
        }

    return {"valid": True, "reason": "", "sanitized_path": sanitized}


def validate_command(command: str) -> dict:
    """
    Validate a command string for exec_process.
    Returns { valid: bool, reason: str, base_command: str }
    """
    if not command or not isinstance(command, str):
        return {"valid": False, "reason": "Command must be a non-empty string.", "base_command": ""}

    command = command.strip()

    # Extract base command (first token)
    try:
        tokens     = shlex.split(command)
        base_cmd   = os.path.basename(tokens[0]) if tokens else ""
    except ValueError as e:
        return {"valid": False, "reason": f"Malformed command: {e}", "base_command": ""}

    # Whitelist check
    if base_cmd not in ALLOWED_COMMANDS:
        return {
            "valid":        False,
            "reason":       f"Command '{base_cmd}' is not in the allowed command list.",
            "base_command": base_cmd,
        }

    # Pattern checks for injection attempts
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return {
                "valid":        False,
                "reason":       f"Command contains a blocked pattern: '{pattern}'.",
                "base_command": base_cmd,
            }

    return {"valid": True, "reason": "", "base_command": base_cmd}


def validate_write_data(data: str) -> dict:
    """Validate data payload for file_write."""
    if data is None:
        return {"valid": False, "reason": "Write data cannot be null."}
    if not isinstance(data, str):
        return {"valid": False, "reason": "Write data must be a string."}
    if len(data) > 10 * 1024 * 1024:   # 10MB limit
        return {"valid": False, "reason": "Write data exceeds 10MB limit."}
    return {"valid": True, "reason": ""}
