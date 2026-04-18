from common.crypto import (
    generate_keypair, serialize_public_key, deserialize_public_key,
    derive_shared_key, encrypt, decrypt,
)

# Simulate two parties
alice_priv, alice_pub = generate_keypair()
bob_priv, bob_pub = generate_keypair()

# Send public keys over the wire (serialize -> deserialize)
alice_pub_wire = serialize_public_key(alice_pub)
bob_pub_wire = serialize_public_key(bob_pub)

alice_sees_bob = deserialize_public_key(bob_pub_wire)
bob_sees_alice = deserialize_public_key(alice_pub_wire)

# Each side derives the shared key
alice_key = derive_shared_key(alice_priv, alice_sees_bob)
bob_key = derive_shared_key(bob_priv, bob_sees_alice)

print("Keys match:", alice_key == bob_key)  # Must be True

# Exchange an encrypted message
ct = encrypt(alice_key, b"hello bob, it's alice")
pt = decrypt(bob_key, ct)
print("Decrypted:", pt)
