"""
encryption.py — OS-Level Encryption Module

Key OS concept: os.urandom() calls the OS CSPRNG directly:
  - Linux/macOS: reads from /dev/urandom (kernel entropy pool)
  - Windows: calls BCryptGenRandom() (Windows CNG API)

This is NOT a userspace RNG. The OS kernel is the source of randomness.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding


# ── Key Derivation ─────────────────────────────────────────────────────────────

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.
    This is a proper Key Derivation Function (KDF), fixing the old web app's
    raw hex key that was not derived from the user's password at all.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256 bits
        salt=salt,
        iterations=390_000,  # NIST-recommended minimum for PBKDF2-SHA256
    )
    return kdf.derive(password.encode("utf-8"))


def generate_salt() -> bytes:
    """
    Generate a random 16-byte salt using the OS CSPRNG.
    OS Concept: os.urandom() → kernel syscall → /dev/urandom or BCryptGenRandom
    """
    return os.urandom(16)


# ── RSA PKI ───────────────────────────────────────────────────────────────────

def generate_rsa_keypair(password: str) -> tuple[bytes, bytes]:
    """Generate RSA-2048 keys. Private key is encrypted with the given password."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private, pem_public

def load_private_key(pem_private: bytes, password: str):
    """Load an encrypted RSA private key."""
    return serialization.load_pem_private_key(
        pem_private,
        password=password.encode('utf-8')
    )

def rsa_encrypt(public_pem: bytes, plaintext: bytes) -> bytes:
    """Encrypt small data (e.g. AES keys) with RSA public key."""
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key.encrypt(
        plaintext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decrypt data with the RSA private key object."""
    return private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ── Encryption / Decryption ───────────────────────────────────────────────────

def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt data with AES-256-GCM.

    Output format (all base64-encoded, colon-separated):
        <salt_hex>:<iv_hex>:<ciphertext+tag_b64>

    OS Concept: Both salt and IV come from os.urandom() — OS kernel entropy.
    """
    salt = generate_salt()
    key = derive_key(password, salt)
    del password

    # os.urandom(12): 96-bit IV — OS entropy, not userspace PRNG
    iv = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    del key, plaintext

    # Pack: salt | iv | ciphertext+tag  — all in one blob for storage
    payload = (
        salt.hex() + ":"
        + iv.hex() + ":"
        + base64.b64encode(ciphertext_with_tag).decode("utf-8")
    )
    return payload.encode("utf-8")


def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    """
    Decrypt AES-256-GCM encrypted data.
    Raises ValueError on authentication failure (wrong password or tampered data).
    """
    try:
        parts = encrypted_payload.decode("utf-8").split(":")
        salt = bytes.fromhex(parts[0])
        iv = bytes.fromhex(parts[1])
        ciphertext_with_tag = base64.b64decode(parts[2])

        key = derive_key(password, salt)
        del password
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
        del key
        return plaintext
    except Exception:
        raise ValueError("Decryption failed: wrong password or corrupted data")


def decrypt_data_pki(encrypted_payload: bytes, private_key_obj, encrypted_aes_key: bytes) -> bytes:
    """Decrypt a file using PKI flow (we decrypt the AES key using RSA first)."""
    aes_key = rsa_decrypt(private_key_obj, encrypted_aes_key)
    
    parts = encrypted_payload.decode("utf-8").split(":")
    iv = bytes.fromhex(parts[1])
    ciphertext_with_tag = base64.b64decode(parts[2])
    
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext_with_tag, None)
    del aes_key
    return plaintext


def encrypt_file(source_path: str, dest_path: str, password: str) -> dict:
    """
    Read a file using raw OS file descriptors, encrypt it, and write to dest_path.

    OS Concept: Uses os.open() + os.read() instead of Python's open().
    These map directly to the open(2) and read(2) POSIX syscalls.
    """
    # os.O_RDONLY: open with read-only flag — OS kernel flag, not Python abstraction
    src_fd = os.open(source_path, os.O_RDONLY)
    try:
        file_size = os.fstat(src_fd).st_size  # fstat(2) syscall on file descriptor
        plaintext = os.read(src_fd, file_size) if file_size > 0 else b""
    finally:
        os.close(src_fd)   # close(2) syscall

    encrypted_payload = encrypt_data(plaintext, password)
    del plaintext, password

    # O_WRONLY | O_CREAT | O_EXCL: create new file, fail if it already exists
    # O_EXCL prevents TOCTOU race conditions (a classic OS security concern)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    dst_fd = os.open(dest_path, flags, 0o600)  # 0o600 = owner read/write only
    try:
        os.write(dst_fd, encrypted_payload)
    finally:
        os.close(dst_fd)

    return {
        "original_path": source_path,
        "encrypted_path": dest_path,
        "original_size": file_size,
        "encrypted_size": len(encrypted_payload),
    }


def decrypt_file(source_path: str, dest_path: str, password: str) -> dict:
    """
    Read an encrypted vault file, decrypt it, and write plaintext to dest_path.
    Uses low-level OS file descriptors throughout.
    """
    src_fd = os.open(source_path, os.O_RDONLY)
    try:
        size = os.fstat(src_fd).st_size
        encrypted_payload = os.read(src_fd, size)
    finally:
        os.close(src_fd)

    plaintext = decrypt_data(encrypted_payload, password)
    del encrypted_payload, password

    # O_WRONLY | O_CREAT | O_TRUNC: create or overwrite
    dst_fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        os.write(dst_fd, plaintext)
    finally:
        os.close(dst_fd)
        
    plaintext_len = len(plaintext)
    del plaintext

    return {
        "decrypted_path": dest_path,
        "decrypted_size": plaintext_len,
    }
