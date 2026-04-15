#include "../include/crypto.h"
#include "../include/net.h"
#include "../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>   /* htonl / ntohl */

/* ── constants ──────────────────────────────────────────────────────────── */

#define NONCE_LEN   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES   /* 24 */
#define MAC_LEN     crypto_aead_xchacha20poly1305_ietf_ABYTES       /* 16 */

/*
 * Use MSG_NOSIGNAL on Linux to prevent SIGPIPE from killing the process
 * when a peer disconnects mid-write.  Falls back to 0 on other platforms
 * (which should install a SIG_IGN handler for SIGPIPE instead).
 */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

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
        if (send(fd, kp.pub, sizeof(kp.pub), MSG_NOSIGNAL) < 0) {
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

/* ── encrypt and send ───────────────────────────────────────────────────── */

static bool encrypt_send_raw(
        int32_t        fd,
        const uint8_t *data,
        uint32_t       len,
        const Session *s)
{
        if (len > MAX_MSG_LEN) {
                err("Message too large to send (%u bytes, max %u).\n",
                    len, MAX_MSG_LEN);
                return false;
        }

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

        ssize_t sent = send(fd, packet, packet_size, MSG_NOSIGNAL);
        bool ok = (sent == (ssize_t)packet_size);
        if (!ok) err("Failed to send encrypted packet.\n");

        free(packet);
        return ok;
}

/* ── receive and decrypt ────────────────────────────────────────────────── */

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

        /* ── sanity-check length before allocating ── */
        if (plaintext_len > MAX_MSG_LEN) {
                err("Peer claimed plaintext_len=%u (max %u). Dropping.\n",
                    plaintext_len, MAX_MSG_LEN);
                return false;
        }

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

        plaintext[actual_plen] = '\0';   /* NUL-terminate for text callers */
        *out_data = plaintext;
        *out_len  = (uint32_t)actual_plen;
        return true;
}

bool crypto_encrypt_send(int32_t fd, const char *msg, const Session *s)
{
        return encrypt_send_raw(fd, (const uint8_t *)msg,
                                (uint32_t)strlen(msg), s);
}

bool crypto_recv_decrypt(int32_t fd, char **out_buf, const Session *s)
{
        uint8_t *data = NULL;
        uint32_t len  = 0;
        if (!recv_decrypt_raw(fd, &data, &len, s))
                return false;

        /* NUL already placed by recv_decrypt_raw */
        *out_buf = (char *)data;
        return true;
}

bool crypto_encrypt_send_bin(
        int32_t        fd,
        const uint8_t *data,
        uint32_t       len,
        const Session *s)
{
        return encrypt_send_raw(fd, data, len, s);
}

bool crypto_recv_decrypt_bin(
        int32_t        fd,
        uint8_t      **out_data,
        uint32_t      *out_len,
        const Session *s)
{
        return recv_decrypt_raw(fd, out_data, out_len, s);
}
