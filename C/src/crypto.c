#include "../include/crypto.h"
#include "../include/net.h"

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
		fprintf(stderr, "ERROR: Our public key equals peer's (loopback)?\n");
		return false;
	}

	int32_t ret;
	if (cmp < 0) {
		ret = crypto_kx_client_session_keys(
			s->rx, s->tx, kp->pub, kp->sec, peer_pub);
		printf("P2P key-derivation role: CLIENT\n");
	} else {
		ret = crypto_kx_server_session_keys(
			s->rx, s->tx, kp->pub, kp->sec, peer_pub);
		printf("P2P key-derivation role: SERVER\n");
	}

	if (ret != 0) {
		fprintf(stderr, "ERROR: P2P session key derivation failed.\n");
		return false;
	}

	printf("SUCCESS: P2P session keys derived from rendezvous-distributed keys.\n");
	return true;
}

bool crypto_do_key_exchange(int32_t fd, Session *s)
{
	Keypair kp;
        crypto_gen_keypair(&kp);

        printf("Generated ephemeral keypair. Exchanging public keys...\n");

        /* send our public key first */
        if (send(fd, kp.pub, sizeof(kp.pub), 0) < 0) {
                fprintf(stderr, "ERROR: Failed to send public key.\n");
                goto fail;
        }
        printf("Sent public key.\n");

        /* receive peer's public key */
        uint8_t peer_pub[crypto_kx_PUBLICKEYBYTES];
        if (!net_recv_all(fd, peer_pub, sizeof(peer_pub))) {
                fprintf(stderr, "ERROR: Disconnected during key exchange.\n");
                goto fail;
        }
        printf("Received peer public key.\n");

	bool ok = crypto_derive_session(&kp, peer_pub, s);
	sodium_memzero(kp.sec, sizeof(kp.sec));
	return ok;

fail:
        sodium_memzero(kp.sec, sizeof(kp.sec));
        return false;
}

/* ── encrypt and send ───────────────────────────────────────────────────── */

bool crypto_encrypt_send(int32_t fd, const char *msg, const Session *s)
{
        uint32_t plaintext_len  = (uint32_t)strlen(msg);
        uint32_t ciphertext_len = plaintext_len + MAC_LEN;

        /*
         * Packet layout:
         *   [ nonce (24) | plaintext_len (4, network order) | ciphertext+MAC ]
         */
        size_t packet_size = NONCE_LEN + sizeof(uint32_t) + ciphertext_len;

        uint8_t *packet = malloc(packet_size);
        if (!packet) {
                fprintf(stderr, "ERROR: malloc failed (encrypt_send).\n");
                return false;
        }

        /* random nonce at the front */
        uint8_t *nonce = packet;
        randombytes_buf(nonce, NONCE_LEN);

        /* plaintext length in network byte order */
        uint32_t net_len = htonl(plaintext_len);
        memcpy(packet + NONCE_LEN, &net_len, sizeof(uint32_t));

        /* encrypt directly into packet */
        uint8_t      *ciphertext = packet + NONCE_LEN + sizeof(uint32_t);
        unsigned long long actual_clen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
                ciphertext,     &actual_clen,
                (const uint8_t *)msg, plaintext_len,
                NULL, 0,         /* no additional data */
                NULL,            /* nsec unused */
                nonce,
                s->tx);

        bool ok = (send(fd, packet, packet_size, 0) == (ssize_t)packet_size);
        if (!ok) fprintf(stderr, "ERROR: Failed to send encrypted packet.\n");

        free(packet);
        return ok;
}

/* ── receive and decrypt ────────────────────────────────────────────────── */

bool crypto_recv_decrypt(int32_t fd, char **out_buf, const Session *s)
{
        /* read nonce */
        uint8_t nonce[NONCE_LEN];
        if (!net_recv_all(fd, nonce, sizeof(nonce))) {
                fprintf(stderr, "ERROR: Disconnected reading nonce.\n");
                return false;
        }

        /* read plaintext length */
        uint32_t net_len;
        if (!net_recv_all(fd, &net_len, sizeof(net_len))) {
                fprintf(stderr, "ERROR: Disconnected reading length.\n");
                return false;
        }
        uint32_t plaintext_len  = ntohl(net_len);
        uint32_t ciphertext_len = plaintext_len + MAC_LEN;

        /* read ciphertext + MAC */
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
                fprintf(stderr, "ERROR: malloc failed (ciphertext).\n");
                return false;
        }
        if (!net_recv_all(fd, ciphertext, ciphertext_len)) {
                fprintf(stderr, "ERROR: Disconnected reading ciphertext.\n");
                free(ciphertext);
                return false;
        }

        /* decrypt */
        uint8_t *plaintext = malloc(plaintext_len + 1);
        if (!plaintext) {
                fprintf(stderr, "ERROR: malloc failed (plaintext).\n");
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
        *out_buf = (char *)plaintext;
        return true;
}
