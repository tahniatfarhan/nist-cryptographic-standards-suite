"""
Public Key Infrastructure (PKI) and X.509 Certificate Generator (RFC 5280)
"""

import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generate_self_signed_cert(
    private_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    common_name: str = "Tahniat Farhan",
    org_name: str = "UET Lahore - Cyber Security Dept",
    validity_days: int = 365
) -> x509.Certificate:
    """Generates an X.509 v3 Self-Signed Digital Certificate."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return cert


def verify_certificate_signature(cert: x509.Certificate, issuer_public_key: rsa.RSAPublicKey) -> bool:
    """Verifies that the X.509 certificate was signed by the specified public key."""
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False


def export_cert_pem(cert: x509.Certificate) -> bytes:
    """Exports X.509 Certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)
