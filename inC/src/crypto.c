#include "../include/crypto.h"
#include "../include/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define NONCE_LEN       crypto_aead_xchacha20poly1305_ietf_NPUBBYTES    /* 24 */
#define MAC_LEN         crypto_aead_xchacha20poly1305_ietf_ABYTES       /* 16 */

bool crypto_do_key_exchange(int32_t fd, Session *s)
{
        uint8_t my_pub[crypto_kx_PUBLICKEYBYTES];
        uint8_t my_sec[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(my_pub, my_sec);

        printf("Generated ephemeral keypair. Exchanging public keys...\n");

        if (send(fd, my_pub, sizeof(my_pub), 0) < 0) {
                fprintf(stderr, "ERROR: Failed to send public key.\n");
                goto fail;
        }
        printf("Sent public key.\n");

        // recv peer's public key
        uint8_t peer_pub[crypto_kx_PUBLICKEYBYTES];
        if (!net_recv_all(fd, peer_pub, sizeof(peer_pub))) {
                fprintf(stderr, "ERROR: Disconnected during key exchange.\n");
                goto fail;
        }
        printf("Received peer public key.\n");

        // decide CLIENT SERVER role
        int32_t cmp = memcmp(my_pub, peer_pub, crypto_kx_PUBLICKEYBYTES);
        if (cmp == 0) {
                fprintf(stderr, "ERROR: Public keys are identical (loopback?).\n");
                goto fail;
        }

        int32_t ret;
        if (cmp < 0) {
                ret = crypto_kx_client_session_keys(
                        s->rx, s->tx, my_pub, my_sec, peer_pub);
                printf("Key-echange role: CLIENT\n");
        } else {
                ret = crypto_kx_server_session_keys(
                        s->rx, s->tx, my_pub, my_sec, peer_pub);
                printf("Key-echange role: SERVER\n");
        }

        sodium_memzero(my_sec, sizeof(my_sec));

        if (ret != 0) {
                fprintf(stderr, "ERROR: Session key derivation failed.\n");
                return false;
        }

        printf("SUCCESS: E2EE session keys derived.\n");
        return true;

fail:
        sodium_memzero(my_sec, sizeof(my_sec));
        return false;
}

bool crypto_encrypt_send(int32_t fd, const char *msg, const Session *s) {
        uint32_t plain_len = strlen(msg);
        uint32_t cipher_len = plain_len + MAC_LEN;

        size_t packet_size = NONCE_LEN + sizeof(uint32_t) + cipher_len;

        uint8_t *packet = malloc(packet_size);
        if (!packet) {
                fprintf(stderr, "ERROR: malloc() failed (crypt_encrypt_send()).\n");
                return false;
        }

        // Write nonce (in the beginning)
        uint8_t *nonce = packet;
        randombytes_buf(nonce, NONCE_LEN);

        // Write plain_len in network order
        uint32_t net_len = htonl(plain_len);
        memcpy(packet+NONCE_LEN, &net_len, sizeof(uint32_t));

        // Encrypt directly into packet
        uint8_t *cipher = packet + NONCE_LEN + sizeof(uint32_t);
        unsigned long long actual_clen;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
                cipher,
                &actual_clen,
                (const uint8_t*)msg,
                plain_len,
                NULL,
                0,
                NULL,
                nonce,
                s->tx);

        bool ok = (send(fd, packet, packet_size, 0) == (ssize_t)packet_size);
        if (!ok) fprintf(stderr, "ERROR: Failed to send encrypted packet.\n");

        free(packet);
        return ok;
}

bool crypto_recv_decrypt(int32_t fd, char **out_buf, const Session *s) {
        // Read nonce
        uint8_t nonce[NONCE_LEN];
        if (!net_recv_all(fd, nonce, sizeof(nonce))) {
                fprintf(stderr, "ERROR: Disconnected reading nonce.\n");
                return false;
        }

        // Read plain
        uint32_t net_len;
        if (!net_recv_all(fd, &net_len, sizeof(net_len))) {
                fprintf(stderr, "ERROR: Disconnected reading length.\n");
                return false;
        }
        uint32_t plain_len = ntohl(net_len);
        uint32_t cipher_len = plain_len + MAC_LEN;

        // Read cipher + MAC
        uint8_t *cipher = malloc(cipher_len);
        if (!cipher) {
                fprintf(stderr, "ERROR: malloc() failed (cipher).\n");
                return false;
        }
        if (!net_recv_all(fd, cipher, sizeof(cipher))) {
                fprintf(stderr, "ERROR: Disconnected reading cipher.\n");
                free(cipher);
                return false;
        }

        // Decrypt
        uint8_t *plain = malloc(plain_len + 1);
        if (!plain) {
                fprintf(stderr, "ERROR: malloc() failed (plain).\n");
                free(cipher);
                return false;
        }

        unsigned long long actual_plen;
        int32_t rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
                plain,
                &actual_plen,
                NULL,
                cipher,
                cipher_len,
                NULL,
                0,
                nonce,
                s->rx);

        free(cipher);

        if (rc != 0) {
                fprintf(stderr, "FATAL ERROR: Message authentication failed - forged or corrupted.\n");
                sodium_memzero(plain, plain_len);
                free(plain);
                return false;
        }

        plain[actual_plen] = '\0';
        *out_buf = (char*)plain;
        return true;
}

bool send_msg(int32_t fd, const char *msg, const Session *s)
{
        return crypto_encrypt_send(fd, msg, s);
}
