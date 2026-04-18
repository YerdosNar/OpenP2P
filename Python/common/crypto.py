"""
Cryptographic primitives shared by the Rendezvous protocol and the P2P protocol.

Uses X25519 for ECDH key exchange, HKDF-SHA256 for key derivation,
and AES-256-GCM for authenticated symmetric encryption.
"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------- Key generation and serialization --------

def generate_keypair():
    """Generate a fresh X25519 keypair. Returns (private_key, public_key)."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key: X25519PublicKey) -> bytes:
    """Convert a public key into 32 raw bytes suitable for sending over the wire."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key(data: bytes) -> X25519PublicKey:
    """Parse 32 raw bytes back into a public key object."""
    if len(data) != 32:
        raise ValueError(f"Expected 32 bytes for X25519 public key, got {len(data)}")
    return X25519PublicKey.from_public_bytes(data)


# -------- Shared key derivation --------

def derive_shared_key(
    my_private: X25519PrivateKey,
    their_public: X25519PublicKey,
    info: bytes = b"p2p-chat handshake v1",
) -> bytes:
    """
    Perform ECDH and derive a 32-byte symmetric key via HKDF-SHA256.

    The `info` parameter binds the derived key to a specific context;
    using different `info` values for Rendezvous vs. P2P would separate keys
    even if the same X25519 pair were somehow reused.
    """
    shared_secret = my_private.exchange(their_public)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,
        info=info,
    ).derive(shared_secret)
    return derived


# -------- Authenticated symmetric encryption --------

def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext || auth_tag
    A fresh random nonce is used for every call — NEVER reuse a (key, nonce) pair.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256-GCM")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96 bits is the standard GCM nonce size
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt a blob produced by encrypt().

    Raises cryptography.exceptions.InvalidTag if the data was tampered with.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes for AES-256-GCM")
    if len(blob) < 12 + 16:  # nonce + minimum auth tag
        raise ValueError("Ciphertext too short")
    aesgcm = AESGCM(key)
    nonce, ciphertext = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)
