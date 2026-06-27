"""
Evidence-file encryption at rest using AES-256-GCM.

Each evidence file is encrypted on disk with a key derived from the application
secret. The on-disk format is:

    MAGIC (10 bytes) | nonce (12 bytes) | ciphertext+tag

AES-GCM provides confidentiality AND integrity (the authentication tag detects
tampering with the ciphertext). Files written before this feature existed have
no MAGIC header and are read back as-is, so legacy plaintext evidence keeps
working.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.logic.keyderive import derive_key

MAGIC = b'DEICMSENC1'      # marks a file as DEICMS-encrypted
NONCE_LEN = 12


def _key() -> bytes:
    return derive_key('evidence-file', 32)


def encrypt_file(path: str) -> None:
    """Encrypt the file at `path` in place (plaintext -> AES-256-GCM)."""
    with open(path, 'rb') as f:
        plaintext = f.read()
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    with open(path, 'wb') as f:
        f.write(MAGIC + nonce + ciphertext)


def is_encrypted(path: str) -> bool:
    """Return True if the file on disk carries the DEICMS encryption header."""
    try:
        with open(path, 'rb') as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def read_plaintext(path: str) -> bytes:
    """
    Return the plaintext bytes of an evidence file, decrypting if it is
    DEICMS-encrypted, or returning the raw bytes for legacy plaintext files.
    """
    with open(path, 'rb') as f:
        data = f.read()
    if data[:len(MAGIC)] != MAGIC:
        return data  # legacy plaintext file
    nonce = data[len(MAGIC):len(MAGIC) + NONCE_LEN]
    ciphertext = data[len(MAGIC) + NONCE_LEN:]
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)
