# OS-Level Secure File Management System

A **true OS-level** command-line application built in Python that directly invokes OS APIs, syscalls, and kernel interfaces. No browser, no web server, no HTTP.

## OS Concepts Demonstrated

| Concept | Where Used |
|---|---|
| `os.open()` / `os.read()` / `os.write()` (POSIX syscalls) | All file operations |
| `os.stat()` / `os.fstat()` → `stat(2)` → inode data | File listing, permissions |
| `os.chmod()` → `chmod(2)` | Permissions module |
| `os.access()` → `access(2)` | Access control checks |
| File locking (`msvcrt.locking` / `fcntl.flock`) | Shadow DB writes |
| `O_APPEND` atomic writes | Audit log (no corruption) |
| `O_EXCL` TOCTOU protection | Vault file creation |
| `os.urandom()` → `/dev/urandom` / `BCryptGenRandom` | Encryption IV + salts |
| `os.getpid()` / `os.getppid()` | Process info, sessions |
| `subprocess.Popen()` → `fork()+exec()` / `CreateProcess()` | Malware scanner |
| Process isolation (child ≠ parent address space) | Malware scanner |
| `os.unlink()` → `unlink(2)` | File deletion |
| AES-256-GCM + PBKDF2-HMAC-SHA256 | Encryption module |
| bcrypt adaptive hashing | Authentication |
| TOTP 2FA (RFC 6238) | Auth module |

## How to Run

### 1. Install dependencies
```powershell
cd "c:\Users\nikhi\OneDrive\Desktop\OS PROJECT"
pip install -r requirements.txt
```

### 2. Launch the CLI
```powershell
python main.py
```

### 3. Run tests
```powershell
python -m pytest tests/ -v
```

## Project Structure

```
OS PROJECT/
├── main.py                  ← CLI entry point (run this)
├── requirements.txt
├── modules/
│   ├── auth.py              ← Registration, login, bcrypt, 2FA, file locking
│   ├── encryption.py        ← AES-256-GCM, PBKDF2, os.urandom, O_EXCL
│   ├── filesystem.py        ← os.open/read/write/stat/unlink, inode data
│   ├── permissions.py       ← chmod, ACL, os.access(), permission bit parsing
│   ├── process_mgmt.py      ← subprocess, PID/PPID, process isolation, kill
│   ├── sharing.py           ← ACL grant/revoke for file sharing
│   └── audit_log.py         ← O_APPEND atomic log writes, chmod to 0o440
├── data/
│   ├── shadow.db            ← Bcrypt-hashed credentials (like /etc/shadow)
│   ├── vault/               ← Encrypted files + .meta.json ACL sidecars
│   └── audit.log            ← Tamper-evident audit trail
├── tests/
│   └── test_modules.py      ← pytest tests: encryption, auth, audit, processes
└── _archive/                ← Old React/Node.js web app (preserved)
    ├── frontend/
    └── backend/
```

## Quick Demo Flow

```
1. Register   → shadow.db written with bcrypt hash, chmod 0o600
2. Login      → bcrypt.checkpw(), session stored in process memory only
3. Upload     → malware scan in child process → AES-256-GCM encrypt → store via os.open(O_EXCL)
4. List       → os.stat() on each vault file → shows real inode numbers
5. Permissions→ os.chmod() + os.access() + permission bit breakdown
6. Share      → ACL update in metadata sidecar
7. Download   → ACL check → decrypt → os.write() to destination
8. Audit Log  → O_APPEND writes, set to read-only after each entry
```

## Architecture

This is a **pure OS-level** application:
- No web server (no Express, no Flask)
- No browser (no React)
- No HTTP/JWT tokens — session is an in-memory Python dict tied to the process
- All file I/O uses raw POSIX file descriptors (`os.open`, `os.read`, `os.write`)
- The malware scanner runs in a completely isolated child process
