"""
Symmetric Cryptographic Ciphers:
- AES-256-GCM (NIST FIPS 197 / SP 800-38D)
- Triple DES / 3DES (NIST SP 800-67 - Legacy Deprecated)
- One-Time Pad / OTP (Information-Theoretic Security Demo)
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


def encrypt_aes_gcm(plaintext: bytes, key: bytes = None, nonce: bytes = None) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-256-GCM (Authenticated Encryption).
    Returns (ciphertext, tag, key, nonce).
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")
    
    if key is None:
        key = os.urandom(32)  # 256-bit key
    elif len(key) != 32:
        raise ValueError("AES-256 key must be exactly 32 bytes (256 bits).")
        
    if nonce is None:
        nonce = os.urandom(12)  # 96-bit recommended nonce for GCM
    elif len(nonce) < 8:
        raise ValueError("Nonce must be at least 8 bytes for GCM mode.")

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, encryptor.tag, key, nonce


def decrypt_aes_gcm(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypts ciphertext and verifies GCM authentication tag.
    Raises InvalidTag exception if authentication fails.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes.")
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def encrypt_3des_legacy(plaintext: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes]:
    """
    DEPRECATED LEGACY CIPHER: Triple DES (3DES) in CBC mode (NIST SP 800-67).
    Included strictly for academic syllabus completeness. Disallowed by NIST after 2023.
    """
    if key is None:
        key = DES3.adjust_key_parity(os.urandom(24))
    elif len(key) not in (16, 24):
        raise ValueError("3DES key must be 16 or 24 bytes.")

    cipher = DES3.new(key, DES3.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    return ciphertext, cipher.iv, key


def decrypt_3des_legacy(ciphertext: bytes, iv: bytes, key: bytes) -> bytes:
    """Decrypts 3DES CBC ciphertext."""
    decipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
    return unpad(decipher.decrypt(ciphertext), DES3.block_size)


def encrypt_otp(message: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
    """
    One-Time Pad (OTP) Encryption.
    Key must be truly random (CSPRNG), identical in length to message, and used exactly once.
    """
    if key is None:
        key = os.urandom(len(message))
    elif len(key) != len(message):
        raise ValueError("OTP key length must match message length exactly.")

    ciphertext = bytes(m ^ k for m, k in zip(message, key))
    return ciphertext, key


def decrypt_otp(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypts OTP ciphertext using XOR operation with key."""
    if len(key) != len(ciphertext):
        raise ValueError("OTP key length must match ciphertext length exactly.")
    return bytes(c ^ k for c, k in zip(ciphertext, key))
