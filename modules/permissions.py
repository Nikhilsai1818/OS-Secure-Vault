"""
permissions.py — OS-Level Access Control Module

OS Concepts demonstrated:
- os.chmod() — chmod(2) syscall, changes inode permission bits
- os.access() — access(2) syscall, checks effective UID permissions
- stat module: S_IRUSR, S_IWUSR, S_IRGRP etc. (Unix permission bit constants)
- ACL (Access Control List) stored in metadata sidecars
- The concept of owner/group/other permission model (Unix discretionary access control)
"""

import os
import stat
import json

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
VAULT_DIR = os.path.join(BASE_DIR, "data", "vault")


# ── Unix Permission Bit Constants (documented for educational clarity) ─────────

PERM_BITS = {
    "owner_read":  stat.S_IRUSR,   # 0o400
    "owner_write": stat.S_IWUSR,   # 0o200
    "owner_exec":  stat.S_IXUSR,   # 0o100
    "group_read":  stat.S_IRGRP,   # 0o040
    "group_write": stat.S_IWGRP,   # 0o020
    "group_exec":  stat.S_IXGRP,   # 0o010
    "other_read":  stat.S_IROTH,   # 0o004
    "other_write": stat.S_IWOTH,   # 0o002
    "other_exec":  stat.S_IXOTH,   # 0o001
}


def _meta_path(vault_filename: str) -> str:
    return os.path.join(VAULT_DIR, vault_filename + ".meta.json")


def _load_meta(vault_filename: str) -> dict:
    mp = _meta_path(vault_filename)
    if not os.path.exists(mp):
        return {}
    fd = os.open(mp, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        return json.loads(os.read(fd, size).decode("utf-8")) if size > 0 else {}
    finally:
        os.close(fd)


def _save_meta(vault_filename: str, meta: dict):
    mp = _meta_path(vault_filename)
    data = json.dumps(meta, indent=2).encode("utf-8")
    fd = os.open(mp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.chmod(mp, stat.S_IRUSR | stat.S_IWUSR)


def chmod_file(vault_filename: str, requesting_user: str, mode_octal: int) -> tuple[bool, str]:
    """
    Change the OS-level permission bits on a vault file.

    OS Concept: os.chmod() directly calls the chmod(2) syscall.
    The kernel updates the inode's i_mode field.
    Only the owner (or root) can chmod on POSIX systems.

    mode_octal: e.g., 0o600, 0o644, 0o400
    """
    meta = _load_meta(vault_filename)
    if not meta:
        return False, "File not found."

    if meta.get("owner") != requesting_user:
        return False, "Access Denied: only the file owner can change permissions."

    vault_path = os.path.join(VAULT_DIR, vault_filename)
    if not os.path.exists(vault_path):
        return False, "Vault file missing on disk."

    try:
        # Direct OS syscall — changes permission bits in the inode
        os.chmod(vault_path, mode_octal)
        # Verify by reading back stat
        new_mode = oct(stat.S_IMODE(os.stat(vault_path).st_mode))
        meta["permissions"] = new_mode
        _save_meta(vault_filename, meta)
        return True, f"Permissions changed to {new_mode}"
    except OSError as e:
        return False, f"chmod failed: {e}"


def check_access(vault_filename: str, username: str, mode: str = "read") -> tuple[bool, str]:
    """
    Check whether 'username' has 'mode' access to vault_filename.

    OS Concept: This simulates the kernel's permission check:
    1. Is user the owner? → check owner bits
    2. Is user in the shared list (our ACL)? → check group bits
    3. Otherwise → check other bits (we deny by default)

    Also calls os.access() on the actual file to validate real OS permissions.
    """
    meta = _load_meta(vault_filename)
    if not meta:
        return False, "File not found."

    owner = meta.get("owner")
    shared_with = meta.get("shared_with", [])

    is_owner = (username == owner)
    is_shared = (username in shared_with)

    if not (is_owner or is_shared):
        return False, f"Access Denied: {username} has no entry in ACL for this file."

    vault_path = os.path.join(VAULT_DIR, vault_filename)
    if not os.path.exists(vault_path):
        return False, "File missing on disk."

    # os.access() — access(2) syscall: checks real file permission bits
    # F_OK = file exists, R_OK = readable, W_OK = writable
    check_mode = os.R_OK if mode == "read" else os.W_OK
    if not os.access(vault_path, check_mode):
        return False, f"OS denies {mode} access (file mode: {oct(stat.S_IMODE(os.stat(vault_path).st_mode))})"

    return True, "Access granted."


def get_permissions(vault_filename: str) -> dict | None:
    """
    Return a human-readable permission breakdown for a vault file.
    Reads live from the OS stat structure (not cached metadata).

    OS Concept: Parsing stat(2)'s st_mode field into readable bits.
    """
    vault_path = os.path.join(VAULT_DIR, vault_filename)
    if not os.path.exists(vault_path):
        return None

    s = os.stat(vault_path)
    mode = s.st_mode
    meta = _load_meta(vault_filename)

    def bit(mask): return "✓" if mode & mask else "✗"

    return {
        "file": vault_filename,
        "original_name": meta.get("original_name", "?"),
        "owner": meta.get("owner", "?"),
        "shared_with": meta.get("shared_with", []),
        "raw_mode": oct(stat.S_IMODE(mode)),
        "inode": s.st_ino,
        "permissions_table": {
            "Owner  read":  bit(stat.S_IRUSR),
            "Owner  write": bit(stat.S_IWUSR),
            "Owner  exec":  bit(stat.S_IXUSR),
            "Group  read":  bit(stat.S_IRGRP),
            "Group  write": bit(stat.S_IWGRP),
            "Group  exec":  bit(stat.S_IXGRP),
            "Others read":  bit(stat.S_IROTH),
            "Others write": bit(stat.S_IWOTH),
            "Others exec":  bit(stat.S_IXOTH),
        }
    }


def grant_access(vault_filename: str, owner: str, target_user: str, encrypted_aes_key: bytes = None) -> tuple[bool, str]:
    """Add target_user to the ACL (shared_with list) for this file."""
    meta = _load_meta(vault_filename)
    if not meta:
        return False, "File not found."
    if meta.get("owner") != owner:
        return False, "Only the owner can grant access."
    if target_user in meta.get("shared_with", []):
        return False, f"{target_user} already has access."

    meta.setdefault("shared_with", []).append(target_user)
    if encrypted_aes_key is not None:
        meta.setdefault("shared_keys", {})[target_user] = encrypted_aes_key.hex()
        
    _save_meta(vault_filename, meta)
    return True, f"Access granted to {target_user}."


def revoke_access(vault_filename: str, owner: str, target_user: str) -> tuple[bool, str]:
    """Remove target_user from the ACL."""
    meta = _load_meta(vault_filename)
    if not meta:
        return False, "File not found."
    if meta.get("owner") != owner:
        return False, "Only the owner can revoke access."

    shared = meta.get("shared_with", [])
    if target_user not in shared:
        return False, f"{target_user} does not have access."

    shared.remove(target_user)
    meta["shared_with"] = shared
    _save_meta(vault_filename, meta)
    return True, f"Access revoked for {target_user}."
