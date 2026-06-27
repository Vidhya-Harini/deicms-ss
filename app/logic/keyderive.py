"""
Derives purpose-specific symmetric keys from the application secret.

Both the private-key encryption (Fernet) and the evidence-file encryption
(AES-256-GCM) need a symmetric key. Rather than storing those keys, we derive
them deterministically from a master secret using PBKDF2-HMAC-SHA256, with a
different salt per purpose. The master secret comes from KEY_ENCRYPTION_SECRET
if set, otherwise from the Flask SECRET_KEY. This means the data at rest can
only be decrypted by a process that holds the application secret.
"""
import hashlib
from flask import current_app


def _master_secret() -> bytes:
    secret = (current_app.config.get('KEY_ENCRYPTION_SECRET')
              or current_app.config.get('SECRET_KEY')
              or 'deicms-default-secret')
    return secret.encode('utf-8')


def derive_key(purpose: str, length: int = 32) -> bytes:
    """Derive a `length`-byte key bound to `purpose` from the master secret."""
    salt = b'deicms-kdf-salt::' + purpose.encode('utf-8')
    return hashlib.pbkdf2_hmac('sha256', _master_secret(), salt, 200_000, dklen=length)
