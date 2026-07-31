# Implementation of NIST Security Standards Using Cryptographic Algorithms

**Student:** Tahniat Farhan
**Registration No:** 2025(S)-CYS-15
**Department:** Cyber Security, UET Lahore

## 1. Introduction

The National Institute of Standards and Technology (NIST) publishes the
Federal Information Processing Standards (FIPS) and Special Publications
(SP) that define how modern cryptography should be implemented: key sizes,
padding schemes, approved algorithms, and certificate formats. This project
implements the core building blocks of these standards in Python to
demonstrate practical understanding of public-key cryptography, symmetric
cryptography, digital signatures, digital certificates, and authentication.

## 2. Objectives

- Implement asymmetric (public-key) cryptography: RSA and Diffie-Hellman.
- Implement symmetric (private-key) cryptography: AES-256-GCM and 3DES.
- Implement digital signatures and verify message integrity/authenticity.
- Generate and validate a self-signed X.509 digital certificate.
- Demonstrate hybrid encryption, the model used by TLS/HTTPS.
- Implement a One-Time Pad as a reference for information-theoretic security.

## 3. Diffie-Hellman Key Exchange (NIST SP 800-56A)

Diffie-Hellman lets two parties, using only public information exchanged
over an insecure channel, compute an identical shared secret without ever
transmitting it. This project generates 2048-bit domain parameters, has
"Alice" and "Bob" each generate a private/public key pair, and shows both
parties independently deriving the same 256-bit symmetric key via HKDF.

## 4. RSA and Digital Signatures (NIST FIPS 186-4)

RSA is an asymmetric algorithm based on the difficulty of factoring large
numbers. A 2048-bit key pair is generated and saved in PEM format. The
private key then signs a message using RSA-PSS with SHA-256 padding, and
the public key verifies it. To demonstrate integrity protection, the
message is tampered with after signing, and verification is shown to
correctly fail — proving the signature detects modification.

## 5. Digital Certificates (X.509 / PKI)

A digital certificate binds a public key to an identity, forming the basis
of Public Key Infrastructure (PKI). This project builds a self-signed X.509
certificate containing subject information (name, organization, country),
a validity period, and a serial number, then verifies the certificate's
own signature against its embedded public key — the same trust mechanism
used (at larger scale, with a Certificate Authority) in HTTPS/TLS.

## 6. AES-256-GCM (NIST FIPS 197 / SP 800-38D)

AES is the NIST-approved symmetric block cipher standard. This project uses
AES-256 in Galois/Counter Mode (GCM), which provides both confidentiality
and authenticity (via an authentication tag) in a single pass — the mode
recommended by NIST SP 800-38D for new designs.

## 7. Triple DES (Legacy Comparison, NIST SP 800-67)

DES (and its stronger successor, Triple DES) was the original NIST
symmetric standard before AES. It is included here only as a legacy
comparison point, since NIST formally deprecated 3DES for new use after
2023 in favor of AES. The implementation demonstrates CBC-mode
encryption/decryption for syllabus completeness.

## 8. Hybrid Encryption (Basis of TLS/HTTPS)

Asymmetric encryption is secure but slow for large data; symmetric
encryption is fast but needs a shared key. Hybrid encryption combines both:
a random AES key encrypts the actual data, and RSA (with OAEP padding)
encrypts only the small AES key. This is exactly how TLS/HTTPS secures web
traffic. The project shows the AES key being wrapped with RSA-OAEP and
correctly recovered with the RSA private key.

## 9. One-Time Pad (OTP)

The One-Time Pad XORs a message with a truly random key of equal length,
used only once. It is the only cipher proven to be information-theoretically
unbreakable, provided the key is random, secret, and never reused. This
project demonstrates the XOR encryption/decryption process.

## 10. Comparison: Symmetric vs. Asymmetric Cryptography

| Aspect | Symmetric (AES / 3DES) | Asymmetric (RSA / DH) |
|---|---|---|
| Speed | Fast, suited to bulk data | Slower, suited to small data / key exchange |
| Key management | Same key shared by both parties | Public key shared, private key kept secret |
| Typical use | Encrypting data itself | Key exchange, signatures, certificates |
| NIST standard | FIPS 197 (AES), SP 800-67 (3DES) | FIPS 186-4 (RSA), SP 800-56A (DH) |

## 11. Security Considerations

- **Key length:** RSA-2048 and AES-256 meet current NIST minimum
  recommendations for long-term security.
- **Padding:** OAEP (encryption) and PSS (signatures) are the NIST-preferred
  padding schemes for RSA, replacing the older PKCS#1 v1.5 scheme.
- **Nonce/IV reuse:** AES-GCM requires a unique nonce per encryption under
  the same key; reuse breaks both confidentiality and authenticity.
- **3DES deprecation:** Triple DES's 64-bit block size and reduced effective
  key strength led NIST to disallow it for new applications from 2023
  onward — included here purely for academic comparison with AES.

## 12. Results

All eight modules executed successfully with `PASS` results, confirming
correct key generation, encryption/decryption, signing/verification, and
certificate validation. See `terminal_output.txt` for the full captured run.

## 13. Conclusion

This project demonstrates a working, end-to-end implementation of the major
cryptographic primitives underlying NIST security standards: key exchange,
public-key and private-key encryption, digital signatures, and digital
certificates. Together these mechanisms form the foundation of secure
communication protocols such as TLS/HTTPS used throughout the internet.

## 14. References

1. NIST FIPS 197, *Advanced Encryption Standard (AES)*.
2. NIST FIPS 186-4, *Digital Signature Standard (DSS)*.
3. NIST SP 800-56A, *Recommendation for Pair-Wise Key-Establishment Schemes
   Using Discrete Logarithm Cryptography*.
4. NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation:
   Galois/Counter Mode (GCM)*.
5. NIST SP 800-67, *Recommendation for the Triple Data Encryption Algorithm
   (TDEA) Block Cipher*.
6. RFC 5280, *Internet X.509 Public Key Infrastructure Certificate and CRL
   Profile*.
7. Python `cryptography` library documentation — https://cryptography.io
8. PyCryptodome documentation — https://pycryptodome.readthedocs.io
