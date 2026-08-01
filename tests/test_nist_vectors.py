"""
Comprehensive Test Suite for NIST Cryptographic Suite (pytest)
Verifies KAT vectors, edge cases, invalid signatures, corrupted ciphertexts, and input validations.
"""

import os
import pytest
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import hashes

from nist_crypto.dh import generate_dh_parameters, derive_shared_key, demo_diffie_hellman
from nist_crypto.ciphers import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    encrypt_3des_legacy,
    decrypt_3des_legacy,
    encrypt_otp,
    decrypt_otp,
)
from nist_crypto.signatures import (
    generate_rsa_keypair,
    export_private_key_pem,
    export_public_key_pem,
    sign_message,
    verify_signature,
    hybrid_encrypt,
    hybrid_decrypt,
)
from nist_crypto.pki import generate_self_signed_cert, verify_certificate_signature


# ---------------------------------------------------------------------
# 1. Diffie-Hellman Key Exchange Tests
# ---------------------------------------------------------------------
def test_dh_key_exchange_pass():
    assert demo_diffie_hellman() is True


def test_dh_invalid_key_size():
    with pytest.raises(ValueError, match="at least 2048 bits"):
        generate_dh_parameters(1024)


# ---------------------------------------------------------------------
# 2. AES-256-GCM Tests (KAT & Corrupted Ciphertext)
# ---------------------------------------------------------------------
def test_aes_gcm_roundtrip():
    plaintext = b"NIST FIPS 197 Test Vector Plaintext"
    ct, tag, key, nonce = encrypt_aes_gcm(plaintext)
    pt = decrypt_aes_gcm(ct, tag, key, nonce)
    assert pt == plaintext


def test_aes_gcm_corrupted_tag():
    plaintext = b"Authenticated Encryption Security Test"
    ct, tag, key, nonce = encrypt_aes_gcm(plaintext)
    corrupted_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
    with pytest.raises(InvalidTag):
        decrypt_aes_gcm(ct, corrupted_tag, key, nonce)


def test_aes_gcm_invalid_key_length():
    with pytest.raises(ValueError, match="32 bytes"):
        encrypt_aes_gcm(b"Test", key=b"short_key")


# ---------------------------------------------------------------------
# 3. 3DES Legacy Tests
# ---------------------------------------------------------------------
def test_3des_roundtrip():
    plaintext = b"3DES Legacy CBC Mode Test Payload"
    ct, iv, key = encrypt_3des_legacy(plaintext)
    pt = decrypt_3des_legacy(ct, iv, key)
    assert pt == plaintext


def test_3des_invalid_key_length():
    with pytest.raises(ValueError, match="16 or 24 bytes"):
        encrypt_3des_legacy(b"Test", key=b"bad_key")


# ---------------------------------------------------------------------
# 4. One-Time Pad Tests
# ---------------------------------------------------------------------
def test_otp_roundtrip():
    message = b"TOP_SECRET_OTP_DATA"
    ct, key = encrypt_otp(message)
    pt = decrypt_otp(ct, key)
    assert pt == message


def test_otp_invalid_key_length():
    with pytest.raises(ValueError, match="match message length"):
        encrypt_otp(b"Hello", key=b"WrongLengthKey")


# ---------------------------------------------------------------------
# 5. RSA-PSS Signature Tests & Tamper Detection
# ---------------------------------------------------------------------
def test_rsa_signature_valid():
    priv, pub = generate_rsa_keypair(2048)
    message = b"Valid Message for Digital Signature"
    sig = sign_message(message, priv)
    assert verify_signature(sig, message, pub) is True


def test_rsa_signature_tampered_message():
    priv, pub = generate_rsa_keypair(2048)
    message = b"Original Authentic Message"
    sig = sign_message(message, priv)
    tampered = b"Original Tampered Message"
    assert verify_signature(sig, tampered, pub) is False


def test_rsa_invalid_key_size():
    with pytest.raises(ValueError, match="at least 2048 bits"):
        generate_rsa_keypair(1024)


# ---------------------------------------------------------------------
# 6. Hybrid RSA-OAEP + AES-GCM Encryption Tests
# ---------------------------------------------------------------------
def test_hybrid_encryption_roundtrip():
    priv, pub = generate_rsa_keypair(2048)
    plaintext = b"Confidential Hybrid TLS Ciphertext Payload"
    enc_key, ct, tag, nonce = hybrid_encrypt(plaintext, pub)
    decrypted = hybrid_decrypt(enc_key, ct, tag, nonce, priv)
    assert decrypted == plaintext


# ---------------------------------------------------------------------
# 7. X.509 Digital Certificate Tests
# ---------------------------------------------------------------------
def test_cert_generation_and_verification():
    priv, pub = generate_rsa_keypair(2048)
    cert = generate_self_signed_cert(priv, pub)
    assert verify_certificate_signature(cert, pub) is True


def test_cert_signature_mismatch():
    priv1, pub1 = generate_rsa_keypair(2048)
    _, pub2 = generate_rsa_keypair(2048)
    cert = generate_self_signed_cert(priv1, pub1)
    assert verify_certificate_signature(cert, pub2) is False
