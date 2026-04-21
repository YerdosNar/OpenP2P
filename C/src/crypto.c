#include "../include/crypto.h"
#include "../include/net.h"
#include "../include/logger.h"
#include "../include/msgtype.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>   /* htonl / ntohl */

/* ── constants ──────────────────────────────────────────────────────────── */

#define NONCE_LEN   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES   /* 24 */
#define MAC_LEN     crypto_aead_xchacha20poly1305_ietf_ABYTES       /* 16 */

/* ── key exchange ───────────────────────────────────────────────────────── */

void crypto_gen_keypair(Keypair *kp)
{
	crypto_kx_keypair(kp->pub, kp->sec);
}

bool crypto_derive_session(
	const Keypair  *kp,
	const uint8_t   peer_pub[crypto_kx_PUBLICKEYBYTES],
	Session        *s)
{
	int32_t cmp = memcmp(kp->pub, peer_pub, crypto_kx_PUBLICKEYBYTES);
	if (cmp == 0) {
		err("Our public key equals peer's (loopback)?\n");
		return false;
	}

	int32_t ret;
	if (cmp < 0) {
		ret = crypto_kx_client_session_keys(
			s->rx, s->tx, kp->pub, kp->sec, peer_pub);
		info("P2P key-derivation role: " MGN "CLIENT\n" NOC);
	} else {
		ret = crypto_kx_server_session_keys(
			s->rx, s->tx, kp->pub, kp->sec, peer_pub);
		info("P2P key-derivation role: " MGN "SERVER\n" NOC);
	}

	if (ret != 0) {
		err("P2P session key derivation failed.\n");
		return false;
	}

	success("P2P session keys derived from rendezvous-distributed keys.\n");
	return true;
}

bool crypto_do_key_exchange(int32_t fd, Session *s)
{
	Keypair kp;
        crypto_gen_keypair(&kp);

        info("Generated ephemeral keypair. Exchanging public keys...\n");

        /* send our public key first */
        if (send(fd, kp.pub, sizeof(kp.pub), 0) < 0) {
                err("Failed to send public key.\n");
                goto fail;
        }
        info("Sent public key.\n");

        /* receive peer's public key */
        uint8_t peer_pub[crypto_kx_PUBLICKEYBYTES];
        if (!net_recv_all(fd, peer_pub, sizeof(peer_pub))) {
                err("Disconnected during key exchange.\n");
                goto fail;
        }
        info("Received peer public key.\n");

	bool ok = crypto_derive_session(&kp, peer_pub, s);
	sodium_memzero(kp.sec, sizeof(kp.sec));
	return ok;

fail:
        sodium_memzero(kp.sec, sizeof(kp.sec));
        return false;
}

/* ── raw AEAD layer (no type byte, no interpretation) ───────────────────── */

/*
 * Encrypt 'len' bytes from 'data' and send one packet on 'fd'.
 * 'data' is treated as an opaque blob; the caller is responsible for
 * any application-level framing (e.g. a leading type byte).
 */
static bool encrypt_send_raw(
        int32_t        fd,
        const uint8_t *data,
        uint32_t       len,
        const Session *s)
{
        uint32_t ciphertext_len = len + MAC_LEN;
        size_t   packet_size    = NONCE_LEN + sizeof(uint32_t) + ciphertext_len;

        uint8_t *packet = malloc(packet_size);
        if (!packet) {
                err("malloc failed (encrypt_send).\n");
                return false;
        }

        /* random nonce at the front */
        uint8_t *nonce = packet;
        randombytes_buf(nonce, NONCE_LEN);

        /* plaintext length in network byte order */
        uint32_t net_len = htonl(len);
        memcpy(packet + NONCE_LEN, &net_len, sizeof(uint32_t));

        /* encrypt directly into packet */
        uint8_t           *ct = packet + NONCE_LEN + sizeof(uint32_t);
        unsigned long long actual_clen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
                ct,     &actual_clen,
                data,   len,
                NULL, 0,         /* no additional data */
                NULL,            /* nsec unused */
                nonce,
                s->tx);

        bool ok = (send(fd, packet, packet_size, 0) == (ssize_t)packet_size);
        if (!ok) err("Failed to send encrypted packet.\n");

        free(packet);
        return ok;
}

/*
 * Receive one packet on 'fd' and decrypt into a freshly-allocated buffer.
 * *out_data gets (plaintext_len + 1) bytes; the extra byte is set to 0
 * so the buffer is safe to treat as a C string when the payload is text.
 */
static bool recv_decrypt_raw(
        int32_t   fd,
        uint8_t **out_data,
        uint32_t *out_len,
        const Session *s)
{
        /* read nonce */
        uint8_t nonce[NONCE_LEN];
        if (!net_recv_all(fd, nonce, sizeof(nonce))) {
                err("Disconnected reading nonce.\n");
                return false;
        }

        /* read plaintext length */
        uint32_t net_len;
        if (!net_recv_all(fd, &net_len, sizeof(net_len))) {
                err("Disconnected reading length.\n");
                return false;
        }
        uint32_t plaintext_len  = ntohl(net_len);
        uint32_t ciphertext_len = plaintext_len + MAC_LEN;

        /* read ciphertext + MAC */
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
                err("malloc failed (ciphertext).\n");
                return false;
        }
        if (!net_recv_all(fd, ciphertext, ciphertext_len)) {
                err("Disconnected reading ciphertext.\n");
                free(ciphertext);
                return false;
        }

        /* decrypt */
        uint8_t *plaintext = malloc(plaintext_len + 1);
        if (!plaintext) {
                err("malloc failed (plaintext).\n");
                free(ciphertext);
                return false;
        }

        unsigned long long actual_plen;
        int32_t rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext,      &actual_plen,
                NULL,            /* nsec unused */
                ciphertext,     ciphertext_len,
                NULL, 0,         /* no additional data */
                nonce, s->rx);

        free(ciphertext);

        if (rc != 0) {
                fprintf(stderr, "FATAL: Message authentication failed"
			" -- forged or corrupted.\n");
                sodium_memzero(plaintext, plaintext_len);
                free(plaintext);
                return false;
        }

        plaintext[actual_plen] = '\0';
        *out_data = plaintext;
        *out_len  = (uint32_t)actual_plen;
        return true;
}

/* ── typed layer: prepends/strips the 1-byte MsgType ─────────────────────── */

bool crypto_send_typed(
                int32_t         fd,
                uint8_t         type,
                const uint8_t   *data,
                uint32_t        len,
                const Session   *s)
{
        /*
         * We allocate (1 + len) bytes, write the type, then memcpy the
         * payload. The whole buffer is handed to encrypt_send_raw, which
         * encrypts and authenticates it atomically -- so the type byte
         * is covered by Poly1305 just like the payload.
         *
         * Handles len == 0 / data == NULL cleanly for empty-payload
         * messages (accept / reject / end).
         */
        uint32_t plain_len = 1 + len;
        uint8_t *plain = malloc(plain_len);
        if (!plain) {
                err("malloc failed (send_typed).\n");
                return false;
        }

        plain[0] = type;
        if (len > 0 && data != NULL) {
                memcpy(plain + 1, data, len);
        }

        bool ok = encrypt_send_raw(fd, plain, plain_len, s);

        /*
         * Best effort to avoid leaving ciphertext-adjacent data on the heap.
         * For chat/offer/chunk this isn't sensitive in the same way as keys,
         * but it's cheap and keeps habits consistent.
         */
        sodium_memzero(plain, plain_len);
        free(plain);
        return ok;
}

bool crypto_recv_typed(
                int32_t         fd,
                uint8_t         *out_type,
                uint8_t         **out_data,
                uint32_t        *out_len,
                const Session   *s)
{
        uint8_t *raw = NULL;
        uint32_t raw_len = 0;

        if (!recv_decrypt_raw(fd, &raw, &raw_len, s)) {
                return false;
        }

        /*
         * A valid plaintext must contain at least the type byte.
         * If the peer somehow sends an empty plaintext, we treat it
         * as a protocol error -- it can't have come from our own code.
         */
        if (raw_len < 1) {
                err("Received empty plaintext (missing type byte).\n");
                free(raw);
                return false;
        }

        *out_type = raw[0];

        /*
         * Rather than allocate a second buffer and copy, shift the payload
         * down by one byte inside the existing allocation. Cheaper and keeps
         * the trailing NUL that recv_decrypt_raw already appended.
         *
         * memmove (not memcpy): source and destination overlap.
         */
        uint32_t payload_len = raw_len - 1;
        memmove(raw, raw + 1, payload_len);
        raw[payload_len] = '\0';

        *out_data = raw;
        *out_len  = payload_len;
        return true;
}

/* ── legacy wrappers: always MSG_CHAT ───────────────────────────────────── */

bool crypto_encrypt_send(int32_t fd, const char *msg, const Session *s)
{
        return crypto_send_typed(fd, MSG_CHAT,
                                 (const uint8_t *)msg,
                                 (uint32_t)strlen(msg), s);
}

bool crypto_encrypt_send_bin(
                int32_t         fd,
                const uint8_t   *data,
                uint32_t        len,
                const Session   *s)
{
        return crypto_send_typed(fd, MSG_CHAT, data, len, s);
}

/*
 * Legacy recv wrappers reject any non-chat type. Rationale:
 *
 *   - rendezvous.c never exchanges anything but chat-shaped data
 *     (prompts, IP:Port strings, public-key blobs). All of it rides
 *     under MSG_CHAT in Phase 1.
 *   - peer.c uses these wrappers ONLY during the rendezvous conversation,
 *     where the same rule applies.
 *   - For the P2P chat/file channel, peer.c uses crypto_recv_typed
 *     directly and dispatches on the type byte.
 *
 * A non-chat type arriving here means either a protocol mismatch or a
 * bug -- both warrant an explicit failure rather than silent acceptance.
 */
bool crypto_recv_decrypt(int32_t fd, char **out_buf, const Session *s)
{
        uint8_t  type;
        uint8_t *data = NULL;
        uint32_t len  = 0;

        if (!crypto_recv_typed(fd, &type, &data, &len, s)) {
                return false;
        }

        if (type != MSG_CHAT) {
                err("Unexpected message type 0x%02x on chat channel.\n", type);
                free(data);
                return false;
        }

        *out_buf = (char *)data;
        return true;
}

bool crypto_recv_decrypt_bin(
        int32_t        fd,
        uint8_t      **out_data,
        uint32_t      *out_len,
        const Session *s)
{
        uint8_t type;

        if (!crypto_recv_typed(fd, &type, out_data, out_len, s)) {
                return false;
        }

        if (type != MSG_CHAT) {
                err("Unexpected message type 0x%02x on chat channel.\n", type);
                free(*out_data);
                *out_data = NULL;
                *out_len  = 0;
                return false;
        }

        return true;
}
