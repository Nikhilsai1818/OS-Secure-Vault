"""
sharing.py — Secure File Sharing Module

OS Concepts demonstrated:
- ACL update (access control list — who can access what)
- os.stat() to verify file existence and metadata before sharing
- Atomic metadata update to prevent partial-share corruption
- All actions logged to audit trail (O_APPEND log writes)
"""

import os
from modules.permissions import grant_access, revoke_access, _load_meta
from modules import audit_log


def share_file(vault_filename: str, owner: str, target_user: str, enc_password: str = "") -> tuple[bool, str]:
    """
    Grant 'target_user' read access to vault_filename using Zero-Knowledge PKI.

    OS Concept: We update the ACL (Access Control List) stored in the metadata.
    Cryptography Concept: We derive the file's AES key using the owner's password, 
    then encrypt that AES key using the target's RSA public key.
    """
    from modules.auth import user_exists, get_public_key
    from modules.encryption import derive_key, rsa_encrypt
    from modules.filesystem import read_file_salt

    # Validate target user exists in shadow DB
    if not user_exists(target_user):
        audit_log.log(owner, "SHARE_ATTEMPT", vault_filename, "FAIL", f"target={target_user} not found")
        return False, f"User '{target_user}' does not exist."

    if target_user == owner:
        return False, "You cannot share a file with yourself."

    # Verify vault file actually exists on disk (os.stat → kernel lookup)
    meta = _load_meta(vault_filename)
    if not meta:
        return False, "File not found."
        
    salt = read_file_salt(vault_filename, owner)
    if not salt:
        return False, "Failed to read file salt."

    try:
        aes_key = derive_key(enc_password, salt)
        del enc_password
    except Exception as e:
        return False, f"Failed to derive file key (wrong password?)"
        
    pub_key_pem = get_public_key(target_user)
    if not pub_key_pem:
        return False, f"User {target_user} has no RSA public key registered."
        
    try:
        encrypted_aes_key = rsa_encrypt(pub_key_pem.encode('utf-8'), aes_key)
        del aes_key
    except Exception as e:
        return False, f"RSA Encryption failed: {e}"

    success, msg = grant_access(vault_filename, owner, target_user, encrypted_aes_key)
    result = "OK" if success else "FAIL"
    audit_log.log(owner, "SHARE_FILE", vault_filename, result, f"to={target_user}")

    return success, msg


def unshare_file(vault_filename: str, owner: str, target_user: str) -> tuple[bool, str]:
    """Revoke 'target_user' read access to vault_filename."""
    success, msg = revoke_access(vault_filename, owner, target_user)
    result = "OK" if success else "FAIL"
    audit_log.log(owner, "REVOKE_ACCESS", vault_filename, result, f"from={target_user}")
    return success, msg


def list_shared_by(username: str) -> list[dict]:
    """List all files owned by username that are shared with others."""
    from modules.filesystem import VAULT_DIR
    results = []
    if not os.path.exists(VAULT_DIR):
        return results
    for name in os.listdir(VAULT_DIR):
        if not name.endswith(".enc"):
            continue
        meta = _load_meta(name)
        if meta.get("owner") == username and meta.get("shared_with"):
            results.append({
                "vault_filename": name,
                "original_name": meta.get("original_name", "?"),
                "shared_with": meta.get("shared_with", []),
            })
    return results


def list_shared_with(username: str) -> list[dict]:
    """List all files that others have shared with 'username'."""
    from modules.filesystem import VAULT_DIR
    results = []
    if not os.path.exists(VAULT_DIR):
        return results
    for name in os.listdir(VAULT_DIR):
        if not name.endswith(".enc"):
            continue
        meta = _load_meta(name)
        if username in meta.get("shared_with", []):
            results.append({
                "vault_filename": name,
                "original_name": meta.get("original_name", "?"),
                "owner": meta.get("owner", "?"),
            })
    return results
