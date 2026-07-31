"""
=====================================================================
 Implementation of NIST Security Standards Using Cryptographic
 Algorithms
=====================================================================
 Student   : Tahniat Farhan
 Reg. No   : 2025(S)-CYS-15
 Department: Cyber Security
 University: UET Lahore
 Course    : Introduction to Cyber Security / Cryptography Lab

 This script implements the cryptographic mechanisms behind the
 NIST / FIPS security standards required for the assignment:

   1. Diffie-Hellman Key Exchange      (NIST SP 800-56A)
   2. RSA Key Generation               (NIST SP 800-56B / FIPS 186-4)
   3. Digital Signature (RSA-PSS)      (FIPS 186-4)
   4. Digital Certificate (X.509)      (PKI / RFC 5280)
   5. AES-256-GCM Encryption           (FIPS 197 / SP 800-38D)
   6. Triple DES (3DES)                (legacy NIST SP 800-67, shown
                                         for syllabus completeness)
   7. Hybrid Encryption (RSA + AES)    (basis of TLS/HTTPS)
   8. One-Time Pad (OTP)               (information-theoretic demo)

 Run with:  python app.py
=====================================================================
"""

import os
import base64
import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

BACKEND = default_backend()
LINE = "=" * 70


def header(title):
    print("\n" + LINE)
    print(title)
    print(LINE)


def sub(msg):
    print(f"  -> {msg}")


# =====================================================================
# 1. DIFFIE-HELLMAN KEY EXCHANGE  (NIST SP 800-56A)
# =====================================================================
def demo_diffie_hellman():
    header("1. DIFFIE-HELLMAN KEY EXCHANGE (NIST SP 800-56A)")

    # Generate shared domain parameters (2048-bit MODP group)
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=BACKEND)
    sub("Generated 2048-bit DH domain parameters")

    # Two parties: Alice and Bob
    alice_private = parameters.generate_private_key()
    bob_private = parameters.generate_private_key()
    sub("Alice and Bob each generated a private/public key pair")

    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()

    # Each side computes the same shared secret independently
    alice_shared = alice_private.exchange(bob_public)
    bob_shared = bob_private.exchange(alice_public)

    # Derive a symmetric key from the shared secret using HKDF
    alice_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                      info=b"dh-demo").derive(alice_shared)
    bob_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"dh-demo").derive(bob_shared)

    print(f"  Alice derived key (hex): {alice_key.hex()[:32]}...")
    print(f"  Bob   derived key (hex): {bob_key.hex()[:32]}...")

    match = alice_key == bob_key
    print(f"  Keys match: {match}")
    print("  RESULT:", "PASS - Shared secret established securely" if match else "FAIL")
    return match


# =====================================================================
# 2. RSA KEY GENERATION  (NIST SP 800-56B / FIPS 186-4)
# =====================================================================
def demo_rsa_keygen():
    header("2. RSA-2048 KEY PAIR GENERATION (NIST FIPS 186-4)")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=BACKEND)
    public_key = private_key.public_key()

    # Save keys to disk (PEM format)
    with open("keys/rsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open("keys/rsa_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

    sub("RSA-2048 key pair generated")
    sub("Saved keys/rsa_private.pem and keys/rsa_public.pem")
    print("  RESULT: PASS")
    return private_key, public_key


# =====================================================================
# 3. DIGITAL SIGNATURE  (RSA-PSS, FIPS 186-4)
# =====================================================================
def demo_digital_signature(private_key, public_key):
    header("3. DIGITAL SIGNATURE - RSA-PSS / SHA-256 (FIPS 186-4)")

    message = b"Implementation of NIST Security Standards - Tahniat Farhan"
    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

    with open("signatures/message.txt", "wb") as f:
        f.write(message)
    with open("signatures/signature.sig", "wb") as f:
        f.write(signature)

    print(f"  Message   : {message.decode()}")
    print(f"  Signature : {base64.b64encode(signature).decode()[:60]}...")

    try:
        public_key.verify(
            signature, message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        verified = True
    except Exception:
        verified = False
    print(f"  Signature verification (unmodified message): {verified}")

    # Tamper test - prove integrity protection
    tampered = message.replace(b"Tahniat", b"Hacker!")
    try:
        public_key.verify(
            signature, tampered,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        tamper_detected = False
    except Exception:
        tamper_detected = True
    print(f"  Tampered message correctly rejected: {tamper_detected}")

    print("  RESULT:", "PASS" if verified and tamper_detected else "FAIL")
    return verified and tamper_detected


# =====================================================================
# 4. DIGITAL CERTIFICATE  (X.509 / PKI)
# =====================================================================
def demo_digital_certificate(private_key, public_key):
    header("4. DIGITAL CERTIFICATE - X.509 SELF-SIGNED (PKI)")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UET Lahore - Cyber Security Dept"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Tahniat Farhan"),
    ])

    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(private_key, hashes.SHA256(), backend=BACKEND))

    with open("certs/certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    sub("Self-signed X.509 certificate created and saved to certs/certificate.pem")
    print(f"  Subject      : {cert.subject.rfc4514_string()}")
    print(f"  Serial Number: {cert.serial_number}")
    print(f"  Valid From   : {cert.not_valid_before_utc}")
    print(f"  Valid Until  : {cert.not_valid_after_utc}")

    # Verify the certificate's signature was made by its own public key
    try:
        public_key.verify(
            cert.signature, cert.tbs_certificate_bytes,
            padding.PKCS1v15(), cert.signature_hash_algorithm)
        valid = True
    except Exception:
        valid = False
    print(f"  Certificate signature valid: {valid}")
    print("  RESULT:", "PASS" if valid else "FAIL")
    return valid


# =====================================================================
# 5. AES-256-GCM SYMMETRIC ENCRYPTION  (FIPS 197 / SP 800-38D)
# =====================================================================
def demo_aes():
    header("5. AES-256-GCM SYMMETRIC ENCRYPTION (NIST FIPS 197)")

    key = os.urandom(32)      # 256-bit key
    nonce = os.urandom(12)    # 96-bit nonce (recommended for GCM)
    plaintext = b"Confidential Cryptography Lab Report - UET Lahore"

    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=BACKEND).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, encryptor.tag), backend=BACKEND).decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"  Plaintext  : {plaintext.decode()}")
    print(f"  Ciphertext : {ciphertext.hex()[:50]}...")
    print(f"  Auth Tag   : {encryptor.tag.hex()}")
    print(f"  Decrypted  : {decrypted.decode()}")

    ok = decrypted == plaintext
    print("  RESULT:", "PASS" if ok else "FAIL")
    return ok, key


# =====================================================================
# 6. TRIPLE DES  (legacy symmetric algorithm, NIST SP 800-67)
# =====================================================================
def demo_3des():
    header("6. TRIPLE DES (3DES) ENCRYPTION (NIST SP 800-67, legacy)")

    key = DES3.adjust_key_parity(os.urandom(24))  # 192-bit (168 effective) key
    cipher = DES3.new(key, DES3.MODE_CBC)
    plaintext = b"Legacy symmetric cipher demo"

    ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))
    decipher = DES3.new(key, DES3.MODE_CBC, iv=cipher.iv)
    decrypted = unpad(decipher.decrypt(ciphertext), DES3.block_size)

    print(f"  Plaintext  : {plaintext.decode()}")
    print(f"  Ciphertext : {ciphertext.hex()}")
    print(f"  Decrypted  : {decrypted.decode()}")
    print("  Note: 3DES is deprecated by NIST (disallowed after 2023) and")
    print("        is included here only for syllabus/legacy comparison.")

    ok = decrypted == plaintext
    print("  RESULT:", "PASS" if ok else "FAIL")
    return ok


# =====================================================================
# 7. HYBRID ENCRYPTION  (RSA encrypts an AES key - basis of TLS)
# =====================================================================
def demo_hybrid(private_key, public_key, aes_key):
    header("7. HYBRID ENCRYPTION - RSA-OAEP WRAPS AES KEY (Basis of TLS)")

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))
    print(f"  RSA-encrypted AES key: {encrypted_key.hex()[:50]}...")

    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))

    ok = decrypted_key == aes_key
    print(f"  Recovered AES key matches original: {ok}")
    print("  RESULT:", "PASS" if ok else "FAIL")
    return ok


# =====================================================================
# 8. ONE-TIME PAD (OTP)
# =====================================================================
def demo_otp():
    header("8. ONE-TIME PAD (OTP) ENCRYPTION")

    message = b"OTP_IS_UNBREAKABLE"
    key = os.urandom(len(message))  # key must be same length, truly random, used once
    cipher = bytes(m ^ k for m, k in zip(message, key))
    decrypted = bytes(c ^ k for c, k in zip(cipher, key))

    print(f"  Original  : {message.decode()}")
    print(f"  Key (hex) : {key.hex()}")
    print(f"  Cipher    : {cipher.hex()}")
    print(f"  Decrypted : {decrypted.decode()}")

    ok = decrypted == message
    print("  RESULT:", "PASS" if ok else "FAIL")
    return ok


# =====================================================================
# MAIN
# =====================================================================
def main():
    print(LINE)
    print(" IMPLEMENTATION OF NIST SECURITY STANDARDS")
    print(" Student: Tahniat Farhan | Reg No: 2025(S)-CYS-15 | UET Lahore")
    print(LINE)

    results = {}
    results["Diffie-Hellman"] = demo_diffie_hellman()
    private_key, public_key = demo_rsa_keygen()
    results["Digital Signature"] = demo_digital_signature(private_key, public_key)
    results["Digital Certificate"] = demo_digital_certificate(private_key, public_key)
    results["AES-256-GCM"], aes_key = demo_aes()
    results["3DES"] = demo_3des()
    results["Hybrid RSA+AES"] = demo_hybrid(private_key, public_key, aes_key)
    results["One-Time Pad"] = demo_otp()

    header("SUMMARY OF RESULTS")
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")

    all_pass = all(results.values())
    print(LINE)
    print(" ALL NIST SECURITY STANDARDS IMPLEMENTED SUCCESSFULLY!" if all_pass
          else " SOME MODULES FAILED - CHECK OUTPUT ABOVE")
    print(LINE)


if __name__ == "__main__":
    main()
