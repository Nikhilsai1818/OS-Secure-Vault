"""
auth.py — OS-Level User Authentication Module

OS Concepts demonstrated:
- File locking (msvcrt on Windows / fcntl on POSIX) to prevent concurrent writes
- os.chmod() to restrict shadow file to owner-only (like /etc/shadow on Linux)
- os.stat() to verify file permissions at runtime
- In-memory session (no HTTP cookies, no JWT tokens over network)
- os.urandom() via pyotp for TOTP secret generation
"""

import os
import json
import stat
import time
import bcrypt
import pyotp
import qrcode
import io

# Platform-specific file locking
import sys
if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SHADOW_PATH = os.path.join(BASE_DIR, "data", "shadow.db")
PUBLIC_KEYS_PATH = os.path.join(BASE_DIR, "data", "public_keys.json")

# ── In-Memory Session ─────────────────────────────────────────────────────────
# No HTTP, no JWT network token. The session lives in process memory only.
_current_session: dict | None = None


def get_session() -> dict | None:
    return _current_session


def _set_session(username: str, user: dict, is_decoy: bool = False, private_key=None):
    global _current_session
    _current_session = {
        "username": username,
        "effective_user": username + "_decoy" if is_decoy else username,
        "logged_in_at": time.time(),
        "pid": os.getpid(),     # OS Concept: session tied to this process
        "is_decoy": is_decoy,
        "private_key": private_key
    }


def logout():
    global _current_session
    _current_session = None


# ── Shadow Database Helpers ───────────────────────────────────────────────────

def _load_shadow() -> dict:
    """Read and parse the shadow credential store."""
    if not os.path.exists(SHADOW_PATH):
        return {}
    fd = os.open(SHADOW_PATH, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            return {}
        raw = os.read(fd, size)
        return json.loads(raw.decode("utf-8"))
    finally:
        os.close(fd)


def _save_shadow(db: dict):
    """
    Write the shadow DB with OS-level file locking.

    OS Concept: File locks prevent two processes writing simultaneously,
    which could corrupt the JSON. This is the same problem /etc/shadow solves
    on Linux (vlock / lockfile mechanism).
    """
    data = json.dumps(db, indent=2).encode("utf-8")

    # Open for writing with O_CREAT — create if not exists
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(SHADOW_PATH, flags, 0o600)
    try:
        # ── Lock the file descriptor ─────────────────────────────────────────
        if sys.platform == "win32":
            # Windows: msvcrt.locking locks a byte range
            msvcrt.locking(fd, msvcrt.LK_NBLCK, len(data))
        else:
            # POSIX: fcntl exclusive lock
            fcntl.flock(fd, fcntl.LOCK_EX)

        os.write(fd, data)

        # ── Unlock ────────────────────────────────────────────────────────────
        if sys.platform == "win32":
            try:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, len(data))
            except Exception:
                pass
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

    # After writing, set permissions to 600 (owner read/write only)
    # os.chmod → chmod(2) syscall, mimics /etc/shadow permission model
    os.chmod(SHADOW_PATH, stat.S_IRUSR | stat.S_IWUSR)  # 0o600


def _verify_shadow_permissions():
    """
    OS Concept: Verify our shadow file has secure permissions.
    On Linux this would check that it's not world-readable (like /etc/shadow is 640).
    """
    try:
        file_stat = os.stat(SHADOW_PATH)   # stat(2) syscall
        mode = file_stat.st_mode & 0o777
        if mode & 0o077:  # Check if group or others have any permission
            print(f"  [SECURITY WARNING] shadow.db has loose permissions: {oct(mode)}")
            # Auto-fix
            os.chmod(SHADOW_PATH, stat.S_IRUSR | stat.S_IWUSR)
            print(f"  [FIXED] Permissions corrected to 0o600")
    except FileNotFoundError:
        pass


def _load_public_keys() -> dict:
    if not os.path.exists(PUBLIC_KEYS_PATH):
        return {}
    fd = os.open(PUBLIC_KEYS_PATH, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        return json.loads(os.read(fd, size).decode("utf-8")) if size > 0 else {}
    finally:
        os.close(fd)

def _save_public_keys(db: dict):
    data = json.dumps(db, indent=2).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(PUBLIC_KEYS_PATH, flags, 0o644)
    try:
        if sys.platform == "win32":
            msvcrt.locking(fd, msvcrt.LK_NBLCK, len(data))
        else:
            fcntl.flock(fd, fcntl.LOCK_EX)
            
        os.write(fd, data)
        
        if sys.platform == "win32":
            try: msvcrt.locking(fd, msvcrt.LK_UNLCK, len(data))
            except Exception: pass
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    os.chmod(PUBLIC_KEYS_PATH, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH) # 0o644

def get_public_key(username: str) -> str:
    db = _load_public_keys()
    return db.get(username, "")

# ── Authentication API ─────────────────────────────────────────────────────────

def register(username: str, password: str) -> tuple[bool, str]:
    """
    Register a new user. Password is hashed with bcrypt (adaptive KDF).
    Returns (success: bool, message: str)
    """
    if len(username) < 3 or len(username) > 32:
        return False, "Username must be 3–32 characters."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if len(password) > 72:
        # bcrypt silently truncates at 72 bytes — reject to prevent confusion
        return False, "Password too long (max 72 chars, bcrypt limit)."

    db = _load_shadow()
    if username in db:
        return False, f"User '{username}' already exists."

    # bcrypt: adaptive cost factor, salted automatically
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

    # Generate RSA keypair
    from modules.encryption import generate_rsa_keypair
    pem_private, pem_public = generate_rsa_keypair(password)
    del password  # memory hygiene

    db[username] = {
        "password_hash": pw_hash.decode("utf-8"),
        "decoy_password_hash": None,
        "two_factor_enabled": False,
        "two_factor_secret": None,
        "created_at": time.time(),
        "uid": len(db) + 1000,    # simulated UID, like /etc/passwd
        "private_key": pem_private.decode("utf-8")
    }
    _save_shadow(db)
    
    # Save public key
    pub_db = _load_public_keys()
    pub_db[username] = pem_public.decode("utf-8")
    _save_public_keys(pub_db)
    
    return True, f"User '{username}' registered. UID={db[username]['uid']}"


def login(username: str, password: str, totp_token: str = "") -> tuple[bool, str]:
    """
    Authenticate a user. Returns (success, message).
    On success, sets the in-memory session.

    OS Concept: Timing-safe comparison via bcrypt.checkpw() to prevent
    timing side-channel attacks (a fundamental OS security concept).
    """
    _verify_shadow_permissions()
    db = _load_shadow()

    if username not in db:
        # Constant-time fake check to prevent username enumeration
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False, "Invalid credentials."

    user = db[username]
    stored_hash = user["password_hash"].encode("utf-8")

    # bcrypt.checkpw: timing-safe comparison (constant time)
    is_valid = bcrypt.checkpw(password.encode("utf-8"), stored_hash)
    
    is_decoy = False
    if not is_valid and user.get("decoy_password_hash"):
        # Check against decoy password if main fails
        if bcrypt.checkpw(password.encode("utf-8"), user["decoy_password_hash"].encode("utf-8")):
            is_valid = True
            is_decoy = True
            
    del password  # memory hygiene
    if not is_valid:
        return False, "Invalid credentials."

    # Check 2FA if enabled
    if user["two_factor_enabled"]:
        if not totp_token:
            return False, "2FA_REQUIRED"
        totp = pyotp.TOTP(user["two_factor_secret"])
        if not totp.verify(totp_token, valid_window=1):
            return False, "Invalid 2FA token."

    private_key_obj = None
    if is_valid and not is_decoy and user.get("private_key"):
        from modules.encryption import load_private_key
        try:
            private_key_obj = load_private_key(user["private_key"].encode('utf-8'), password)
        except Exception as e:
            pass # Failsafe if password doesn't match private key for some reason
            
    _set_session(username, user, is_decoy=is_decoy, private_key=private_key_obj)
    return True, f"Welcome, {username}! (Session PID={os.getpid()})"


def setup_2fa(username: str) -> tuple[bool, str, str]:
    """
    Generate a TOTP secret and save it. Returns (success, secret, otpauth_uri).
    OS Concept: pyotp.random_base32() uses os.urandom() internally.
    """
    db = _load_shadow()
    if username not in db:
        return False, "", ""

    secret = pyotp.random_base32()   # Uses os.urandom() → OS kernel entropy
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="OS-SecureFS")

    db[username]["two_factor_secret"] = secret
    _save_shadow(db)

    return True, secret, uri


def enable_2fa(username: str, token: str) -> tuple[bool, str]:
    """Verify a TOTP token and mark 2FA as enabled."""
    db = _load_shadow()
    if username not in db or not db[username].get("two_factor_secret"):
        return False, "2FA not set up yet."

    totp = pyotp.TOTP(db[username]["two_factor_secret"])
    if not totp.verify(token, valid_window=1):
        return False, "Invalid token. 2FA not enabled."

    db[username]["two_factor_enabled"] = True
    _save_shadow(db)
    return True, "2FA enabled successfully."


def setup_decoy(username: str, decoy_password: str) -> tuple[bool, str]:
    """Set up a plausible deniability decoy password."""
    if len(decoy_password) < 8:
        del decoy_password
        return False, "Decoy password must be at least 8 characters."
        
    db = _load_shadow()
    if username not in db:
        del decoy_password
        return False, "User not found."
        
    # Check that decoy password is not the same as main password
    if bcrypt.checkpw(decoy_password.encode("utf-8"), db[username]["password_hash"].encode("utf-8")):
        del decoy_password
        return False, "Decoy password must be different from main password."
        
    pw_hash = bcrypt.hashpw(decoy_password.encode("utf-8"), bcrypt.gensalt(rounds=12))
    db[username]["decoy_password_hash"] = pw_hash.decode("utf-8")
    _save_shadow(db)
    del decoy_password
    return True, "Decoy password configured successfully."


def user_exists(username: str) -> bool:
    db = _load_shadow()
    return username in db


def get_user_info(username: str) -> dict | None:
    db = _load_shadow()
    if username not in db:
        return None
    u = db[username].copy()
    u.pop("password_hash", None)
    u.pop("two_factor_secret", None)
    return u
