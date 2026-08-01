"""
Asymmetric Cryptography, RSA-PSS Digital Signatures, and Hybrid Encryption:
- RSA-2048/4096 Key Pair Generation (NIST SP 800-56B / FIPS 186-4)
- Digital Signatures with RSA-PSS (FIPS 186-4)
- Hybrid Encryption: RSA-OAEP Wrapping AES-256-GCM Key (TLS/HTTPS Basis)
"""

from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

from nist_crypto.ciphers import encrypt_aes_gcm, decrypt_aes_gcm


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates RSA private/public keypair. Validates key_size >= 2048 per FIPS 186-4."""
    if key_size < 2048:
        raise ValueError("RSA key size must be at least 2048 bits per FIPS 186-4.")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return private_key, private_key.public_key()


def export_private_key_pem(private_key: rsa.RSAPrivateKey, password: str = None) -> bytes:
    """Exports RSA Private Key to PEM format. Optionally password-encrypts key."""
    if password:
        enc_algo = serialization.BestAvailableEncryption(password.encode())
    else:
        enc_algo = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
    )


def export_public_key_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """Exports RSA Public Key to PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sign_message(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Signs message using RSA-PSS with SHA-256 and MGF1 per FIPS 186-4."""
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes.")
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )


def verify_signature(signature: bytes, message: bytes, public_key: rsa.RSAPublicKey) -> bool:
    """
    Verifies RSA-PSS digital signature.
    Returns True if valid, False if signature is invalid or message was tampered with.
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def hybrid_encrypt(plaintext: bytes, public_key: rsa.RSAPublicKey) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Hybrid Encryption Scheme (Basis of TLS):
    1. Generates ephemeral AES-256 key and encrypts plaintext using AES-256-GCM.
    2. Encrypts the AES key using RSA-OAEP with SHA-256.
    Returns (encrypted_aes_key, ciphertext, tag, nonce).
    """
    ciphertext, tag, aes_key, nonce = encrypt_aes_gcm(plaintext)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key, ciphertext, tag, nonce


def hybrid_decrypt(encrypted_aes_key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Hybrid Decryption:
    1. Decrypts AES key using RSA-OAEP private key decryption.
    2. Decrypts ciphertext using AES-256-GCM.
    """
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypt_aes_gcm(ciphertext, tag, aes_key, nonce)
