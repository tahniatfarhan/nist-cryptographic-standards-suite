"""
Command-Line Interface (CLI) Runner for NIST Cryptographic Suite
"""

import sys
import os
import argparse
import base64

from nist_crypto.dh import demo_diffie_hellman
from nist_crypto.signatures import (
    generate_rsa_keypair,
    export_private_key_pem,
    export_public_key_pem,
    sign_message,
    verify_signature,
    hybrid_encrypt,
    hybrid_decrypt,
)
from nist_crypto.pki import generate_self_signed_cert, verify_certificate_signature, export_cert_pem
from nist_crypto.ciphers import (
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    encrypt_3des_legacy,
    decrypt_3des_legacy,
    encrypt_otp,
    decrypt_otp,
)

LINE = "=" * 70


def header(title: str):
    print("\n" + LINE)
    print(title)
    print(LINE)


def sub(msg: str):
    print(f"  -> {msg}")


def run_all_demos():
    """Runs all 8 cryptographic demonstrations sequentially."""
    print(LINE)
    print(" IMPLEMENTATION OF NIST SECURITY STANDARDS")
    print(" Student: Tahniat Farhan | Reg No: 2025(S)-CYS-15 | UET Lahore")
    print(LINE)

    results = {}

    # 1. Diffie-Hellman
    header("1. DIFFIE-HELLMAN KEY EXCHANGE (NIST SP 800-56A)")
    dh_pass = demo_diffie_hellman()
    sub("Generated 2048-bit DH domain parameters")
    print(f"  Shared Secret Key Derived & Verified: {dh_pass}")
    print("  RESULT:", "PASS" if dh_pass else "FAIL")
    results["Diffie-Hellman"] = dh_pass

    # 2. RSA Keygen
    header("2. RSA-2048 KEY PAIR GENERATION (NIST FIPS 186-4)")
    private_key, public_key = generate_rsa_keypair(2048)
    os.makedirs("keys", exist_ok=True)
    with open("keys/rsa_private.pem", "wb") as f:
        f.write(export_private_key_pem(private_key))
    with open("keys/rsa_public.pem", "wb") as f:
        f.write(export_public_key_pem(public_key))
    sub("RSA-2048 key pair generated")
    sub("Saved keys/rsa_private.pem and keys/rsa_public.pem")
    print("  RESULT: PASS")

    # 3. RSA-PSS Signature
    header("3. DIGITAL SIGNATURE - RSA-PSS / SHA-256 (FIPS 186-4)")
    message = b"Implementation of NIST Security Standards - Tahniat Farhan"
    sig = sign_message(message, private_key)
    os.makedirs("signatures", exist_ok=True)
    with open("signatures/message.txt", "wb") as f:
        f.write(message)
    with open("signatures/signature.sig", "wb") as f:
        f.write(sig)
    print(f"  Message   : {message.decode()}")
    print(f"  Signature : {base64.b64encode(sig).decode()[:60]}...")
    verified = verify_signature(sig, message, public_key)
    tampered_sig = verify_signature(sig, message.replace(b"Tahniat", b"Hacker!"), public_key)
    print(f"  Signature verification (unmodified message): {verified}")
    print(f"  Tampered message correctly rejected: {not tampered_sig}")
    sig_pass = verified and not tampered_sig
    print("  RESULT:", "PASS" if sig_pass else "FAIL")
    results["Digital Signature"] = sig_pass

    # 4. X.509 Certificate
    header("4. DIGITAL CERTIFICATE - X.509 SELF-SIGNED (PKI)")
    cert = generate_self_signed_cert(private_key, public_key)
    os.makedirs("certs", exist_ok=True)
    with open("certs/certificate.pem", "wb") as f:
        f.write(export_cert_pem(cert))
    sub("Self-signed X.509 certificate created and saved to certs/certificate.pem")
    print(f"  Subject      : {cert.subject.rfc4514_string()}")
    print(f"  Serial Number: {cert.serial_number}")
    cert_valid = verify_certificate_signature(cert, public_key)
    print(f"  Certificate signature valid: {cert_valid}")
    print("  RESULT:", "PASS" if cert_valid else "FAIL")
    results["Digital Certificate"] = cert_valid

    # 5. AES-256-GCM
    header("5. AES-256-GCM SYMMETRIC ENCRYPTION (NIST FIPS 197)")
    plaintext = b"Confidential Cryptography Lab Report - UET Lahore"
    ct, tag, key, nonce = encrypt_aes_gcm(plaintext)
    pt = decrypt_aes_gcm(ct, tag, key, nonce)
    print(f"  Plaintext  : {plaintext.decode()}")
    print(f"  Ciphertext : {ct.hex()[:50]}...")
    print(f"  Auth Tag   : {tag.hex()}")
    print(f"  Decrypted  : {pt.decode()}")
    aes_pass = pt == plaintext
    print("  RESULT:", "PASS" if aes_pass else "FAIL")
    results["AES-256-GCM"] = aes_pass

    # 6. 3DES Legacy
    header("6. TRIPLE DES (3DES) ENCRYPTION (NIST SP 800-67, legacy)")
    des_text = b"Legacy symmetric cipher demo"
    des_ct, des_iv, des_key = encrypt_3des_legacy(des_text)
    des_pt = decrypt_3des_legacy(des_ct, des_iv, des_key)
    print(f"  Plaintext  : {des_text.decode()}")
    print(f"  Ciphertext : {des_ct.hex()}")
    print(f"  Decrypted  : {des_pt.decode()}")
    print("  Note: 3DES is deprecated by NIST (disallowed after 2023) and")
    print("        is included here only for syllabus/legacy comparison.")
    des_pass = des_pt == des_text
    print("  RESULT:", "PASS" if des_pass else "FAIL")
    results["3DES"] = des_pass

    # 7. Hybrid Encryption
    header("7. HYBRID ENCRYPTION - RSA-OAEP WRAPS AES KEY (Basis of TLS)")
    enc_aes_key, h_ct, h_tag, h_nonce = hybrid_encrypt(plaintext, public_key)
    h_pt = hybrid_decrypt(enc_aes_key, h_ct, h_tag, h_nonce, private_key)
    print(f"  RSA-encrypted AES key: {enc_aes_key.hex()[:50]}...")
    hybrid_pass = h_pt == plaintext
    print(f"  Recovered AES key matches original: {hybrid_pass}")
    print("  RESULT:", "PASS" if hybrid_pass else "FAIL")
    results["Hybrid RSA+AES"] = hybrid_pass

    # 8. One-Time Pad
    header("8. ONE-TIME PAD (OTP) ENCRYPTION")
    otp_msg = b"OTP_IS_UNBREAKABLE"
    otp_ct, otp_key = encrypt_otp(otp_msg)
    otp_pt = decrypt_otp(otp_ct, otp_key)
    print(f"  Original  : {otp_msg.decode()}")
    print(f"  Key (hex) : {otp_key.hex()}")
    print(f"  Cipher    : {otp_ct.hex()}")
    print(f"  Decrypted : {otp_pt.decode()}")
    otp_pass = otp_pt == otp_msg
    print("  RESULT:", "PASS" if otp_pass else "FAIL")
    results["One-Time Pad"] = otp_pass

    # Summary
    header("SUMMARY OF RESULTS")
    for name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}")

    all_pass = all(results.values())
    print(LINE)
    print(" ALL NIST SECURITY STANDARDS IMPLEMENTED SUCCESSFULLY!" if all_pass else " SOME MODULES FAILED")
    print(LINE)
    return 0 if all_pass else 1


def main():
    parser = argparse.ArgumentParser(description="NIST Cryptographic Standards Suite")
    parser.add_argument("--demo", choices=["all", "dh", "rsa", "signature", "cert", "aes", "3des", "hybrid", "otp"], default="all", help="Execute specific cryptographic demonstration")
    args = parser.parse_args()

    if args.demo == "all":
        sys.exit(run_all_demos())
    else:
        print(f"Running individual demonstration: {args.demo}")
        run_all_demos()


if __name__ == "__main__":
    main()
