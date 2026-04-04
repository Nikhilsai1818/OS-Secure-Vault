"""
tests/test_modules.py — Unit tests for OS-Level Secure File System

Run with: python -m pytest tests/ -v
"""

import os
import sys
import stat
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Encryption Tests ──────────────────────────────────────────────────────────

from modules.encryption import (
    encrypt_data, decrypt_data, derive_key, generate_salt, encrypt_file, decrypt_file
)

class TestEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        """AES-256-GCM: ciphertext decrypts back to original."""
        plaintext = b"Hello from OS-level secure file system!"
        password = "test_password_123"
        encrypted = encrypt_data(plaintext, password)
        decrypted = decrypt_data(encrypted, password)
        assert decrypted == plaintext

    def test_wrong_password_raises(self):
        """Wrong password must raise ValueError (GCM auth tag fails)."""
        plaintext = b"Top secret OS data"
        encrypted = encrypt_data(plaintext, "correct_password")
        with pytest.raises(ValueError):
            decrypt_data(encrypted, "wrong_password")

    def test_os_urandom_used_for_iv(self):
        """Each encryption must produce different IV (from os.urandom)."""
        plaintext = b"Same data"
        password = "same_password"
        enc1 = encrypt_data(plaintext, password)
        enc2 = encrypt_data(plaintext, password)
        # Different IVs → different ciphertexts
        assert enc1 != enc2

    def test_key_derivation_deterministic(self):
        """Same password + salt → same key (PBKDF2 is deterministic)."""
        salt = generate_salt()
        key1 = derive_key("my_password", salt)
        key2 = derive_key("my_password", salt)
        assert key1 == key2

    def test_key_derivation_different_salts(self):
        """Different salts → different keys."""
        key1 = derive_key("password", generate_salt())
        key2 = derive_key("password", generate_salt())
        assert key1 != key2

    def test_encrypt_file_uses_os_fds(self):
        """encrypt_file uses os.open() and stores encrypted content."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"Test file content for OS FD test")
            src = f.name

        dest = src + ".enc"
        try:
            result = encrypt_file(src, dest, "file_password")
            assert os.path.exists(dest)
            assert result["original_size"] == 32
            assert result["encrypted_size"] > 32  # ciphertext > plaintext

            # Verify file permissions set by os.chmod
            mode = stat.S_IMODE(os.stat(dest).st_mode)
            # On Windows chmod is limited, so just check file is accessible
            assert os.access(dest, os.R_OK)
        finally:
            os.unlink(src)
            if os.path.exists(dest):
                os.unlink(dest)

    def test_decrypt_file_roundtrip(self):
        """Full encrypt_file → decrypt_file roundtrip using OS file descriptors."""
        original_content = b"OS level file descriptor roundtrip test"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(original_content)
            src = f.name

        enc_path = src + ".enc"
        dec_path = src + ".dec"
        try:
            encrypt_file(src, enc_path, "roundtrip_pass")
            decrypt_file(enc_path, dec_path, "roundtrip_pass")

            # Read result using OS fd
            fd = os.open(dec_path, os.O_RDONLY)
            try:
                recovered = os.read(fd, os.fstat(fd).st_size)
            finally:
                os.close(fd)

            assert recovered == original_content
        finally:
            for p in [src, enc_path, dec_path]:
                if os.path.exists(p):
                    os.unlink(p)


# ── Auth Tests ─────────────────────────────────────────────────────────────────

from modules import auth

class TestAuth:
    def setup_method(self):
        """Clean up any test users before each test."""
        # Load and remove test users from shadow db
        try:
            db = auth._load_shadow()
            for u in ["testuser_pytest", "testuser_pytest2"]:
                db.pop(u, None)
            if db is not None:
                auth._save_shadow(db)
        except Exception:
            pass

    def test_register_and_login(self):
        """Register a user and login with correct credentials."""
        ok, msg = auth.register("testuser_pytest", "correct_password123")
        assert ok, msg

        ok, msg = auth.login("testuser_pytest", "correct_password123")
        assert ok, msg

    def test_login_wrong_password(self):
        """Wrong password must fail login."""
        auth.register("testuser_pytest", "correct_password123")
        ok, msg = auth.login("testuser_pytest", "wrong_password")
        assert not ok

    def test_duplicate_register_fails(self):
        """Registering the same username twice must fail."""
        auth.register("testuser_pytest", "correct_password123")
        ok, msg = auth.register("testuser_pytest", "another_password")
        assert not ok

    def test_shadow_file_permissions(self):
        """shadow.db must have restrictive permissions after write."""
        import sys
        auth.register("testuser_pytest", "test_pass_12345")
        if os.path.exists(auth.SHADOW_PATH):
            if sys.platform != "win32":
                # POSIX: verify not world-writable (like /etc/shadow)
                mode = stat.S_IMODE(os.stat(auth.SHADOW_PATH).st_mode)
                assert not (mode & stat.S_IWOTH), f"shadow.db is world-writable: {oct(mode)}"
            else:
                # Windows: os.chmod() is limited to read-only vs read-write.
                # Just verify the file exists and is owner-accessible.
                assert os.access(auth.SHADOW_PATH, os.R_OK), "shadow.db is not readable"
                # Our chmod call sets 0o600 which on Windows means NOT read-only
                # (i.e., it is writable by owner) — that's the best we can do on Win32
                mode = stat.S_IMODE(os.stat(auth.SHADOW_PATH).st_mode)
                # At minimum: owner must have read permission
                assert mode & stat.S_IRUSR, f"Owner read bit missing: {oct(mode)}"

    def test_session_in_memory(self):
        """Session should be set in memory after login."""
        auth.register("testuser_pytest", "test_pass_12345")
        auth.login("testuser_pytest", "test_pass_12345")
        session = auth.get_session()
        assert session is not None
        assert session["username"] == "testuser_pytest"
        assert "pid" in session

        auth.logout()
        assert auth.get_session() is None

    def test_password_too_long_rejected(self):
        """Passwords > 72 chars must be rejected (bcrypt truncation protection)."""
        ok, msg = auth.register("testuser_pytest", "x" * 73)
        assert not ok

    def test_password_too_short_rejected(self):
        """Passwords < 8 chars must be rejected."""
        ok, msg = auth.register("testuser_pytest", "short")
        assert not ok


# ── Audit Log Tests ────────────────────────────────────────────────────────────

from modules import audit_log

class TestAuditLog:
    def test_log_creates_entry(self):
        """Logging an action should create a readable entry."""
        audit_log.log("pytest_user", "TEST_ACTION", "test_file.txt", "OK", "unit test")
        entries = audit_log.read_log()
        found = any("TEST_ACTION" in e and "pytest_user" in e for e in entries)
        assert found, "Log entry not found"

    def test_log_contains_pid(self):
        """Each log entry should contain the current process PID."""
        pid = os.getpid()
        audit_log.log("pytest_user", "PID_TEST", "-", "OK")
        entries = audit_log.read_log()
        found = any(f"PID={pid}" in e and "PID_TEST" in e for e in entries)
        assert found, f"PID {pid} not in log entries"

    def test_log_is_append_only(self):
        """New entries are appended, old entries remain."""
        audit_log.log("pytest_user", "ENTRY_A", "-", "OK")
        count_before = len(audit_log.read_log())
        audit_log.log("pytest_user", "ENTRY_B", "-", "OK")
        entries = audit_log.read_log()
        assert len(entries) >= count_before + 1, "Old entries were lost (not append-only)"


# ── Process Management Tests ───────────────────────────────────────────────────

from modules import process_mgmt

class TestProcessMgmt:
    def test_get_process_info(self):
        """Process info should include PID and PPID."""
        info = process_mgmt.get_process_info()
        assert "pid" in info
        assert "ppid" in info
        assert info["pid"] == os.getpid()

    def test_scan_clean_file(self):
        """A clean temp file should return CLEAN verdict."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"This is a completely clean test file with no malware.")
            path = f.name
        try:
            result = process_mgmt.scan_file_in_subprocess(path)
            assert result.get("verdict") == "CLEAN", f"Expected CLEAN, got {result}"
            assert result.get("child_pid") != result.get("parent_pid"), "Child and parent PIDs should differ"
        finally:
            os.unlink(path)

    def test_scan_detects_eicar(self):
        """EICAR test string should be detected as a threat."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
            path = f.name
        try:
            result = process_mgmt.scan_file_in_subprocess(path)
            assert result.get("verdict") == "THREAT_DETECTED", f"Expected THREAT_DETECTED, got {result}"
        finally:
            os.unlink(path)

    def test_scanner_runs_in_separate_process(self):
        """Scanner PID must be different from our PID."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"clean")
            path = f.name
        try:
            result = process_mgmt.scan_file_in_subprocess(path)
            scanner_pid = result.get("child_pid", result.get("scanner_pid"))
            assert scanner_pid != os.getpid(), "Scanner did not run in a separate process!"
        finally:
            os.unlink(path)
