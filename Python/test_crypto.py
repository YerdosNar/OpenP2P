from common.crypto import (
    generate_keypair, serialize_public_key, deseralize_public_key,
    derive_shared_key, encrypt, decrypt,
)


# simulate two peers
alice_priv, alice_pub = generate_keypair()
bob_priv, bob_pub = generate_keypair()

# send pubkey
alice_pub_wire = serialize_public_key(alice_pub)
bob_pub_wire = serialize_public_key(bob_pub)

alice_sees_bob = deseralize_public_key(bob_pub_wire)
bob_sees_alice = deseralize_public_key(alice_pub_wire)

# each derive shared key
alice_key = derive_shared_key(alice_priv, alice_sees_bob)
bob_key = derive_shared_key(bob_priv, bob_sees_alice)

print("Key match: ", alice_key == bob_key)

# msg exchagne
ct = encrypt(alice_key, b"hello bob, it's alice")
print("Encrypt: ", ct)
pt = decrypt(bob_key, ct)
print("Decrypt: ", pt)
