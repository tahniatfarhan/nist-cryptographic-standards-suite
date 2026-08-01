"""
Diffie-Hellman Key Exchange Implementation (NIST SP 800-56A)
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_dh_parameters(key_size: int = 2048) -> dh.DHParameters:
    """Generate DH domain parameters (MODP Group). Validates key_size >= 2048."""
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits per NIST SP 800-56A recommendations.")
    return dh.generate_parameters(generator=2, key_size=key_size)


def derive_shared_key(private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey, info: bytes = b"dh-demo", salt: bytes = None) -> bytes:
    """Computes DH shared secret and derives a 256-bit symmetric key using HKDF-SHA256."""
    if not isinstance(private_key, dh.DHPrivateKey) or not isinstance(peer_public_key, dh.DHPublicKey):
        raise TypeError("Invalid key types provided for DH key exchange.")
    
    shared_secret = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(shared_secret)
    return derived_key


def demo_diffie_hellman() -> bool:
    """Executes full Diffie-Hellman key exchange demonstration between Alice and Bob."""
    params = generate_dh_parameters(2048)
    
    alice_private = params.generate_private_key()
    bob_private = params.generate_private_key()
    
    alice_public = alice_private.public_key()
    bob_public = bob_private.public_key()
    
    alice_key = derive_shared_key(alice_private, bob_public)
    bob_key = derive_shared_key(bob_private, alice_public)
    
    return alice_key == bob_key
