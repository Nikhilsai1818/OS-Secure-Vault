#!/usr/bin/env python3
"""
_scanner_worker.py — Runs in a CHILD PROCESS isolated from the main app.
Scans a file for malware signatures and reports result via stdout + exit code.

OS Concept: This process has its own PID, address space, and file descriptors.
It CANNOT access the parent process's memory (session data, encryption keys, etc.)
That is process isolation at the OS level.
"""
import sys
import os
import json

SIGNATURES = [
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR",
    b"<script>eval(",
    b"rm -rf /",
    b"DROP TABLE",
    b"\x4d\x5a\x90\x00",
    b"VIRUS_PAYLOAD_DEMO",
]

def scan(filepath):
    pid = os.getpid()
    ppid = os.getppid()
    result = {
        "scanner_pid": pid,
        "parent_pid": ppid,
        "file": filepath,
        "threats_found": [],
        "verdict": "CLEAN",
        "bytes_scanned": 0,
    }
    try:
        fd = os.open(filepath, os.O_RDONLY)
        size = os.fstat(fd).st_size
        data = os.read(fd, min(size, 10 * 1024 * 1024))  # max 10 MB scan window
        os.close(fd)
        result["bytes_scanned"] = len(data)
        for sig in SIGNATURES:
            if sig in data:
                result["threats_found"].append(sig.decode("utf-8", errors="replace"))
                result["verdict"] = "THREAT_DETECTED"
    except Exception as e:
        result["verdict"] = "SCAN_ERROR"
        result["error"] = str(e)
    print(json.dumps(result))
    sys.exit(1 if result["verdict"] == "THREAT_DETECTED" else 0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"verdict": "ERROR", "error": "No filepath given"}))
        sys.exit(2)
    scan(sys.argv[1])
