"""
Key pair generation and signing utilities.

Uses Ed25519 from the cryptography library. Each investigator gets a key pair
when their account is created. The public key is stored in plaintext for
signature verification; the private key is encrypted at rest with Fernet
(authenticated symmetric encryption) using a key derived from the application
secret, so a stolen database alone does not reveal usable private keys.
"""
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)


def generate_key_pair():
    """
    Generate a new Ed25519 key pair.
    Returns (private_key_pem: str, public_key_pem: str).
    """
    private_key = Ed25519PrivateKey.generate()
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode('utf-8')
    public_key_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return private_key_pem, public_key_pem


# ── Private-key encryption at rest ──────────────────────────────────────────
def _fernet() -> Fernet:
    from app.logic.keyderive import derive_key
    return Fernet(base64.urlsafe_b64encode(derive_key('private-key', 32)))


def encrypt_private_key(private_key_pem: str) -> str:
    """Encrypt a PEM private key for storage. Returns a Fernet token string."""
    return _fernet().encrypt(private_key_pem.encode('utf-8')).decode('utf-8')


def load_private_key_pem(stored: str) -> str:
    """
    Return the usable PEM private key from a stored value, transparently
    decrypting a Fernet token, or returning a legacy plaintext PEM unchanged.
    """
    if stored is None:
        return None
    if stored.lstrip().startswith('-----BEGIN'):
        return stored  # legacy plaintext key
    try:
        return _fernet().decrypt(stored.encode('utf-8')).decode('utf-8')
    except InvalidToken:
        # Not a valid token and not a PEM — return as-is so the caller fails loudly
        return stored


def generate_encrypted_key_pair():
    """Generate a key pair with the private key already encrypted for storage."""
    private_pem, public_pem = generate_key_pair()
    return encrypt_private_key(private_pem), public_pem


def sign_payload(private_key_stored: str, payload: bytes) -> str:
    """
    Sign a byte payload with a stored private key (encrypted token or PEM).
    Returns the signature as a hex string.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    pem = load_private_key_pem(private_key_stored)
    private_key = load_pem_private_key(pem.encode('utf-8'), password=None)
    return private_key.sign(payload).hex()


def verify_signature(public_key_pem: str, payload: bytes, signature_hex: str) -> bool:
    """Verify a signature against a payload using a PEM public key."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    try:
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
        public_key.verify(bytes.fromhex(signature_hex), payload)
        return True
    except (InvalidSignature, Exception):
        return False
