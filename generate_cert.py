"""
Generate a self-signed TLS certificate so DEICMS can run over HTTPS in
development. Creates cert.pem and key.pem in the project root using the
`cryptography` library (already a project dependency).

A self-signed certificate encrypts traffic correctly, but because it is not
issued by a trusted Certificate Authority, the browser will show a one-time
"your connection is not private" warning on first visit. This is expected for
local development.
"""
from datetime import timedelta
import datetime
from datetime import timezone
import ipaddress
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CERT_PATH = os.path.join(BASE_DIR, 'cert.pem')
KEY_PATH = os.path.join(BASE_DIR, 'key.pem')


def generate_self_signed_cert(cert_path=CERT_PATH, key_path=KEY_PATH):
    """Create a 2048-bit RSA key and a self-signed certificate for localhost."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'IN'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'DEICMS Development'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'localhost'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) - datetime.timedelta(days=1))
        .not_valid_after(datetime.(datetime.now(timezone.utc) + timedelta(hours=2)).replace(tzinfo=None) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u'localhost'),
                x509.IPAddress(ipaddress.IPv4Address(u'127.0.0.1')),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path


def ensure_cert():
    """Generate the cert/key pair only if they do not already exist."""
    if not (os.path.exists(CERT_PATH) and os.path.exists(KEY_PATH)):
        generate_self_signed_cert()
    return CERT_PATH, KEY_PATH


if __name__ == '__main__':
    c, k = generate_self_signed_cert()
    print('Generated self-signed certificate:')
    print('  ' + c)
    print('  ' + k)
