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
 * Wire packet format (produced by encrypt_and_send, consumed by recv_and_decrypt):
 *
 *   [ nonce (NPUBBYTES=24) | plaintext_len (4 bytes, network order) | ciphertext+MAC ]
 *
 * The MAC (ABYTES=16) is appended by libsodium inside the ciphertext buffer.
 */

/* ── session key type ────────────────────────────────────────────────────── */

typedef struct {
        uint8_t rx[crypto_kx_SESSIONKEYBYTES];   /* decrypt incoming  */
        uint8_t tx[crypto_kx_SESSIONKEYBYTES];   /* encrypt outgoing  */
} Session;

/* ── public API ─────────────────────────────────────────────────────────── */

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

#endif /* CRYPTO_H */
