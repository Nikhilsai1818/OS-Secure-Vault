"""
process_mgmt.py — OS-Level Process Management Module

OS Concepts demonstrated:
- os.getpid() / os.getppid() — process identity the OS maintains per process
- subprocess.Popen() — creates new child processes via fork()+exec() on POSIX,
  or CreateProcess() on Windows
- Process isolation: child process cannot access parent's memory
- Signal handling: signal.SIGTERM for graceful process termination
- os.waitpid() — wait(2) syscall: parent waits for child to finish (prevents zombies)
- Timeout enforcement: if scanner exceeds time limit, parent kills the child
"""

import os
import sys
import time
import signal
import subprocess
import threading
import tempfile
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


# ── Malware Scanner Subprocess ────────────────────────────────────────────────

# Known "malicious" signatures (simulated, for demonstration)
MALWARE_SIGNATURES = [
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",   # Standard AV test string
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR",  # EICAR test file content
    b"<script>eval(",                          # Basic XSS payload
    b"rm -rf /",                               # Shell bomb
    b"DROP TABLE",                             # SQL injection
    b"\x4d\x5a\x90\x00",                      # PE executable header (MZ)
    b"VIRUS_PAYLOAD_DEMO",                     # Demo marker
]

SCANNER_SCRIPT = os.path.join(BASE_DIR, "modules", "_scanner_worker.py")



def scan_file_in_subprocess(filepath: str, timeout: int = 10) -> dict:
    """
    Scan a file for malware by launching it as a CHILD PROCESS.

    OS Concepts:
    - subprocess.Popen → CreateProcess (Windows) or fork()+exec() (POSIX)
    - Child gets its own PID, isolated address space
    - Parent waits with a timeout; kills child if it hangs (prevents zombie)
    - os.getpid() shown alongside child PID to illustrate parent-child relationship

    Returns a scan result dict.
    """
    parent_pid = os.getpid()

    try:
        # Launch CHILD process — isolated from parent's memory
        proc = subprocess.Popen(
            [sys.executable, SCANNER_SCRIPT, filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        child_pid = proc.pid

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            exit_code = proc.returncode

            if stdout.strip():
                result = json.loads(stdout.strip())
            else:
                result = {
                    "verdict": "SCAN_ERROR",
                    "error": stderr.strip() or "No output from scanner",
                }
        except subprocess.TimeoutExpired:
            # Child process exceeded timeout — kill it
            proc.kill()
            proc.communicate()  # Reap to prevent zombie process
            result = {
                "verdict": "TIMEOUT",
                "error": f"Scanner exceeded {timeout}s limit. Process killed.",
            }
            child_pid = proc.pid

        result["parent_pid"] = parent_pid
        result["child_pid"] = child_pid
        return result

    except Exception as e:
        return {
            "verdict": "LAUNCH_ERROR",
            "error": str(e),
            "parent_pid": parent_pid,
        }


# ── Process Info ──────────────────────────────────────────────────────────────

def get_process_info() -> dict:
    """
    Return current process metadata from the OS.

    OS Concept: Every running process has a PID assigned by the kernel.
    The kernel maintains the process table entry with these values.
    """
    info = {
        "pid":  os.getpid(),    # getpid(2) syscall
        "ppid": os.getppid(),   # getppid(2) — parent PID
        "cwd":  os.getcwd(),    # getcwd(2) — current working directory
    }

    # UID/GID only exist on POSIX
    if hasattr(os, "getuid"):
        info["uid"]  = os.getuid()   # getuid(2)
        info["gid"]  = os.getgid()   # getgid(2)
        info["euid"] = os.geteuid()  # geteuid(2) — effective UID
    else:
        import ctypes
        info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0

    return info


def list_active_processes() -> list[dict]:
    """
    List running Python processes using the OS (cross-platform).
    Uses a subprocess to call the OS process listing command.

    OS Concept: Demonstrates how the OS tracks all running processes.
    """
    try:
        if sys.platform == "win32":
            cmd = ["tasklist", "/FI", "IMAGENAME eq python.exe", "/FO", "CSV"]
        else:
            cmd = ["ps", "aux"]

        # Subprocess: child process runs the OS's process-listing command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        lines = result.stdout.strip().split("\n")
        return lines[:20]   # Return first 20 lines max
    except Exception as e:
        return [f"Could not list processes: {e}"]
