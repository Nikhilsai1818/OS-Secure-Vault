"""
filesystem.py — OS-Level File System Module

OS Concepts demonstrated:
- os.open() with POSIX flags (O_RDONLY, O_WRONLY, O_CREAT, O_EXCL, O_TRUNC)
- os.stat() / os.fstat() — maps to stat(2) syscall, returns real kernel inode data
- os.listdir(), os.path, os.unlink()
- File descriptors (integer handles to kernel file table entries)
- TOCTOU (Time-of-Check-Time-of-Use) race prevention with O_EXCL
"""

import os
import stat
import json
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "data", "vault")


def _meta_path(vault_filename: str) -> str:
    return os.path.join(VAULT_DIR, vault_filename + ".meta.json")


def _load_meta(vault_filename: str) -> dict:
    mp = _meta_path(vault_filename)
    if not os.path.exists(mp):
        return {}
    fd = os.open(mp, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            return {}
        return json.loads(os.read(fd, size).decode("utf-8"))
    finally:
        os.close(fd)


def _save_meta(vault_filename: str, meta: dict):
    mp = _meta_path(vault_filename)
    data = json.dumps(meta, indent=2).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(mp, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(mp, stat.S_IRUSR | stat.S_IWUSR)  # 0o600


def store_file(owner: str, original_name: str, encrypted_payload: bytes) -> str:
    """
    Write an encrypted file to the vault using raw OS file descriptors.

    OS Concept: O_EXCL prevents TOCTOU — if two processes try to create the
    same file simultaneously, only one succeeds (kernel atomically checks).
    Returns the vault filename (ID).
    """
    os.makedirs(VAULT_DIR, exist_ok=True)

    # Generate a unique vault ID from timestamp + process ID
    # os.getpid() — OS-provided unique process identifier
    vault_id = f"{int(time.time()*1000)}_{os.getpid()}"
    vault_filename = f"{vault_id}.enc"
    vault_path = os.path.join(VAULT_DIR, vault_filename)

    # O_EXCL: fail if file exists → prevents race conditions (TOCTOU protection)
    fd = os.open(vault_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, encrypted_payload)
    finally:
        os.close(fd)

    # Set restrictive permissions: owner read/write only
    os.chmod(vault_path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    # Save sidecar metadata
    file_stat = os.stat(vault_path)   # stat(2) syscall — real kernel inode data
    _save_meta(vault_filename, {
        "vault_id": vault_id,
        "vault_filename": vault_filename,
        "original_name": original_name,
        "owner": owner,
        "shared_with": [],          # ACL: list of usernames with read access
        "size_bytes": file_stat.st_size,
        "inode": file_stat.st_ino,  # Real OS inode number from the kernel
        "created_at": time.time(),
        "permissions": oct(stat.S_IMODE(file_stat.st_mode)),  # e.g., '0o600'
    })

    return vault_filename


def list_files(username: str) -> list[dict]:
    """
    List all vault files owned by or shared with username.
    Uses os.stat() to get real OS-level file metadata.
    """
    os.makedirs(VAULT_DIR, exist_ok=True)
    results = []

    for name in os.listdir(VAULT_DIR):
        if not name.endswith(".enc"):
            continue
        meta = _load_meta(name)
        if not meta:
            continue

        is_owner = meta.get("owner") == username
        is_shared = username in meta.get("shared_with", [])

        if not (is_owner or is_shared):
            continue

        # Get live OS stat data (not just stored metadata)
        vault_path = os.path.join(VAULT_DIR, name)
        try:
            file_stat = os.stat(vault_path)   # Live stat(2) syscall each time
            live_size = file_stat.st_size
            live_mtime = datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            live_perms = oct(stat.S_IMODE(file_stat.st_mode))
            inode = file_stat.st_ino
        except OSError:
            continue

        results.append({
            "vault_filename": name,
            "original_name": meta.get("original_name", "unknown"),
            "owner": meta.get("owner", "?"),
            "is_owner": is_owner,
            "shared_with": meta.get("shared_with", []),
            "size_bytes": live_size,
            "inode": inode,
            "permissions": live_perms,
            "modified": live_mtime,
        })

    return results


def read_file(vault_filename: str, username: str) -> tuple[bytes | None, str]:
    """
    Read an encrypted file's raw bytes. Checks ACL first.
    Returns (data, error_message). If error_message is empty, data is valid.

    OS Concept: Access control check before os.open() — like kernel
    permission check before read(2) is allowed.
    """
    meta = _load_meta(vault_filename)
    if not meta:
        return None, "File not found."

    owner = meta.get("owner")
    shared_with = meta.get("shared_with", [])

    if username != owner and username not in shared_with:
        return None, "Access Denied: you do not have read permission on this file."

    vault_path = os.path.join(VAULT_DIR, vault_filename)
    fd = os.open(vault_path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        data = os.read(fd, size) if size > 0 else b""
        return data, ""
    finally:
        os.close(fd)


def read_file_salt(vault_filename: str, username: str) -> bytes | None:
    """Read the first bytes of the file to extract the salt (for PKI sharing)."""
    vault_path = os.path.join(VAULT_DIR, vault_filename)
    if not os.path.exists(vault_path):
        return None
    fd = os.open(vault_path, os.O_RDONLY)
    try:
        data = os.read(fd, 100) # read enough to grab salt_hex
        parts = data.decode("utf-8").split(":")
        if len(parts) >= 2:
            return bytes.fromhex(parts[0])
    except Exception:
        pass
    finally:
        os.close(fd)
    return None


def delete_file(vault_filename: str, username: str) -> tuple[bool, str]:
    """
    Delete a file. Only the owner can delete.
    Uses os.unlink() — maps to the unlink(2) syscall.
    """
    meta = _load_meta(vault_filename)
    if not meta:
        return False, "File not found."

    if meta.get("owner") != username:
        return False, "Access Denied: only the owner can delete this file."

    vault_path = os.path.join(VAULT_DIR, vault_filename)
    meta_path = _meta_path(vault_filename)

    try:
        os.unlink(vault_path)   # unlink(2) syscall — removes directory entry
        os.unlink(meta_path)
        return True, "File deleted."
    except OSError as e:
        return False, f"OS Error: {e}"


def get_file_stat(vault_filename: str) -> dict | None:
    """
    Return raw OS stat information for a vault file.
    Demonstrates the full stat(2) structure returned by the kernel.
    """
    vault_path = os.path.join(VAULT_DIR, vault_filename)
    if not os.path.exists(vault_path):
        return None

    s = os.stat(vault_path)
    return {
        "st_mode":  oct(s.st_mode),      # File type + permission bits
        "st_ino":   s.st_ino,            # Inode number (unique per filesystem)
        "st_dev":   s.st_dev,            # Device ID the file lives on
        "st_nlink": s.st_nlink,          # Number of hard links
        "st_size":  s.st_size,           # File size in bytes
        "st_atime": datetime.fromtimestamp(s.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
        "st_mtime": datetime.fromtimestamp(s.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "st_ctime": datetime.fromtimestamp(s.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
    }
