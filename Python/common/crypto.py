import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_keypair():
    """Generate fresh x25519 keypair"""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: X25519PublicKey) -> bytes:
    """Convert a public key into 32 raw bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key(data: bytes) -> X25519PublicKey:
    if len(data) != 32:
        raise ValueError(f"Expected 32 bytes for X25519PublicKey, got {len(data)}")
    return X25519PublicKey.from_public_bytes(data)


def derive_shared_key(
        my_private: X25519PrivateKey,
        their_public: X25519PublicKey,
        info: bytes = b"p2p-chat handshake v1"
) -> bytes:
    shared_secret = my_private.exchange(their_public)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived


def encrypt(
        key: bytes,
        plaintext: bytes,
        associated_data: bytes = b""
) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256-GCM")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(
        key: bytes,
        blob: bytes,
        associated_data: bytes = b""
):
    """
    Raises cryptography.exceptions.InvalidTag if the data was tampered with.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256-GCM")
    if len(blob) < 12 + 16: #nonce + min auth tag
        raise ValueError("Ciphertext too short")
    aesgcm = AESGCM(key)
    nonce, ciphertext = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
