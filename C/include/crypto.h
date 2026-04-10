#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <sodium.h>

/*
 * crypto.h / crypto.c
 *
 * Shared E2EE layer used by both peer and rendezvous.
 * Key exchange  : X25519  via crypto_kx_*
 * Encryption    : XChaCha20-Poly1305-IETF via crypto_aead_xchacha20poly1305_ietf_*
 *
 * Wire packet format (produced by `crypto_encrypt_send / crypto_encrypt_send_bin`,
 *                     consumed by `crypto_recv_decrypt / crypto_recv_decrypt_bin`):
 *
 *   [ nonce (NPUBBYTES=24)                   ]
 *   [ plaintext_len (4 bytes, network order) ]
 *   [ ciphertext+MAC                         ]
 *
 * The MAC (ABYTES=16) is appended by libsodium inside the ciphertext buffer.
 */

/* ── session key type ────────────────────────────────────────────────────── */

typedef struct {
        uint8_t rx[crypto_kx_SESSIONKEYBYTES];   /* decrypt incoming  */
        uint8_t tx[crypto_kx_SESSIONKEYBYTES];   /* encrypt outgoing  */
} Session;

/* Keypair generated once per peer before connecting to rendezvous. */
typedef struct {
	uint8_t pub[crypto_kx_PUBLICKEYBYTES];
	uint8_t sec[crypto_kx_SECRETKEYBYTES];
} Keypair;

/* ── public API ─────────────────────────────────────────────────────────── */

/*
 * Generate a fresh ephemeral X25519 keypair into *kp.
 */
void crypto_gen_keypair(Keypair *kp);

/*
 * Derive a Session from a local Keypair and the peer's raw public key.
 * Roles (client / server) are decided by lexicographic key comparison,
 * exactly as in crypto_do_key_exchange() so both sides converge on the
 * same rx/tx assignment without any extra negotiation.
 *
 * Returns true on success.
 */
bool crypto_derive_session(
	const Keypair  *kp,
	const uint8_t   peer_pub[crypto_kx_PUBLICKEYBYTES],
	Session        *s);

/*
 * Perform an X25519 key exchange over an already-connected fd.
 * Both sides call this; the roles (client/server) are decided
 * automatically by comparing public keys.
 *
 * On success: fills *s and returns true.
 * On failure: zeroes any derived material and returns false.
 */
bool crypto_do_key_exchange(int32_t fd, Session *s);

/*
 * Encrypt 'msg' (NUL-terminated) with s->tx, prepend a random nonce
 * and the plaintext length, then send over fd.
 *
 * Returns true on success.
 */
bool crypto_encrypt_send(int32_t fd, const char *msg, const Session *s);

/*
 * Receive one packet from fd, decrypt with s->rx, write the
 * NUL-terminated plaintext into *out_buf (caller must free).
 *
 * Returns true on success.
 */
bool crypto_recv_decrypt(int32_t fd, char **out_buf, const Session *s);

/*
 * Encrypt arbitrary bytes (not NUL-terminated) with s->tx and send.
 * Uses the same wire format as crypto_encrypt_send.
 *
 * Returns true on success.
 */
bool crypto_encrypt_send_bin(
        int32_t        fd,
        const uint8_t *data,
        uint32_t       len,
        const Session *s);

/*
 * Receive one binary packet from fd, decrypt with s->rx.
 * Allocates *out_data (caller must free), sets *out_len.
 *
 * Returns true on success.
 */
bool crypto_recv_decrypt_bin(
        int32_t        fd,
        uint8_t      **out_data,
        uint32_t      *out_len,
        const Session *s);

#endif /* CRYPTO_H */
