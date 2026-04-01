"""
audit_log.py — OS-Level Audit Logging Module

Uses os.open() with O_APPEND flag so concurrent writes cannot corrupt the log.
This is an OS-level guarantee — the kernel ensures atomicity of O_APPEND writes
on most POSIX systems and Windows.
"""

import os
import stat
import time
from datetime import datetime

LOG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "audit.log")


def _ensure_log_exists():
    """Create the log file if it doesn't exist, with restricted permissions."""
    if not os.path.exists(LOG_PATH):
        # O_CREAT | O_WRONLY — create with OS flags, not Python's open()
        fd = os.open(LOG_PATH, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)


def log(user: str, action: str, target: str = "-", result: str = "OK", extra: str = ""):
    """
    Append an audit entry to the log file using OS-level O_APPEND flag.

    OS Concept: O_APPEND makes the seek-to-end + write atomic at the kernel level,
    preventing log corruption even with multiple concurrent processes writing.
    """
    _ensure_log_exists()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pid = os.getpid()
    entry = f"[{timestamp}] PID={pid} | USER={user:<20} | ACTION={action:<25} | TARGET={target:<30} | RESULT={result}"
    if extra:
        entry += f" | INFO={extra}"
    entry += "\n"

    # Ensure file is writable before open (Windows fix)
    try:
        os.chmod(LOG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    # O_WRONLY | O_APPEND: OS guarantees atomic append — no seek needed
    fd = os.open(LOG_PATH, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, entry.encode("utf-8"))
    finally:
        os.close(fd)

    # After writing, make log read-only to prevent tampering (until next write)
    # os.chmod — directly invokes chmod(2) syscall
    try:
        os.chmod(LOG_PATH, stat.S_IRUSR | stat.S_IRGRP)  # 0o440
    except OSError:
        pass  # On Windows, chmod is limited but we still call it


def read_log() -> list[str]:
    """Read the full audit log. Temporarily grant read permission."""
    _ensure_log_exists()
    try:
        os.chmod(LOG_PATH, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        fd = os.open(LOG_PATH, os.O_RDONLY)
        try:
            size = os.fstat(fd).st_size   # os.fstat() — stat() on an open file descriptor
            if size == 0:
                return []
            data = os.read(fd, size)
            return data.decode("utf-8").strip().split("\n")
        finally:
            os.close(fd)
    except OSError:
        return []
