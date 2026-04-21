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
 *
 * Plaintext layout (INSIDE the ciphertext):
 *
 *   [ type (1 byte) ][ payload ... ]
 *
 * The type byte is authenticated by Poly1305 along with the payload.
 * See msgtype.h for defined values. The _send/_recv helpers below use
 * MSG_CHAT implicitly; use crypto_send_typed / crypto_recv_typed when
 * you need to send or inspect other message types.
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

/* typed variants */
/*
 * Encrypt and send a message with an explicit type byte.
 *
 * The type is prepended to 'data' inside the plaintext, so it is
 * authenticated by Poly1305 along with the payload.
 *
 * 'data' may be NULL if 'len' is 0 (for empty-payload types like
 * FILE_ACCEPT / FILE_REJECT / FILE_EOF).
 *
 * Returns true on success.
 */
bool crypto_send_typed(
                int32_t         fd,
                uint8_t         type,
                const uint8_t   *data,
                uint32_t        len,
                const Session *);

/*
 * Receive and decrypt one packet, returning the type byte and payload
 * separately.
 *
 * On success:
 *   *out_type is set to the type byte
 *   *out_data points to a heap-allocated payload (caller must free,
 *             even when *out_len = 0 - the buffer still carries a
 *             trailing NUL so it is safe to treat as a C string when
 *             the type is MSG_CHAT)
 *   *out_len is the payload length in bytes, NOT including the type
 *
 * Returns true on success, false on any transport or decryption error.
 */
bool crypto_recv_typed(
        int32_t        fd,
        uint8_t       *out_type,
        uint8_t      **out_data,
        uint32_t      *out_len,
        const Session *s);

#endif /* CRYPTO_H */
