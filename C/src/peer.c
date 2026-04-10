#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "../include/crypto.h"
#include "../include/net.h"

/* ── defaults ────────────────────────────────────────────────────────────── */

#define DEFAULT_SERVER_PORT     8888
#define DEFAULT_LOCAL_PORT      50000
#define MAX_IP_LEN              16

/* ── types ───────────────────────────────────────────────────────────────── */

typedef struct {
        char     server_ip[MAX_IP_LEN];
        uint16_t server_port;
        uint16_t local_port;
} Config;

typedef struct {
        char     ip[MAX_IP_LEN];
        uint16_t port;
} PeerInfo;

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void resolve_domain(const char *domain, char *out_ip)
{
        struct hostent *h = gethostbyname(domain);
        if (h) {
                char *ip = inet_ntoa(*(struct in_addr *)h->h_addr_list[0]);
                strncpy(out_ip, ip, MAX_IP_LEN - 1);
        }
}

static void usage(const char *exe)
{
        printf("Usage: %s [options]\n\n", exe);
        printf("Options:\n");
        printf("  -s, --server-port <port>    Rendezvous server port  (default=%d)\n",
               DEFAULT_SERVER_PORT);
        printf("  -i, --ip <ip>               Rendezvous server IP    (default=127.0.0.1)\n");
        printf("  -l, --local-port <port>     Local port for P2P      (default=%d)\n",
               DEFAULT_LOCAL_PORT);
        printf("  -d, --domain-name <name>    Rendezvous server domain\n");
        printf("  -h, --help                  Show this help message\n\n");
        printf("Example:\n  %s -d example.com -s 8888\n", exe);
}

static Config parse_args(int argc, char **argv)
{
        Config cfg;
        strncpy(cfg.server_ip, "127.0.0.1", MAX_IP_LEN - 1);
        cfg.server_port = DEFAULT_SERVER_PORT;
        cfg.local_port  = DEFAULT_LOCAL_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-s", 2)
                    || !strncmp(argv[i], "--server-port", 13))
                {
                        if (i + 1 < argc)
                                cfg.server_port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strncmp(argv[i], "-i", 2)
                         || !strncmp(argv[i], "--ip", 4))
                {
                        if (i + 1 < argc)
                                strncpy(cfg.server_ip, argv[++i], MAX_IP_LEN - 1);
                }
                else if (!strncmp(argv[i], "-l", 2)
                         || !strncmp(argv[i], "--local-port", 12))
                {
                        if (i + 1 < argc)
                                cfg.local_port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strncmp(argv[i], "-d", 2)
                         || !strncmp(argv[i], "--domain-name", 13))
                {
                        if (i + 1 < argc)
                                resolve_domain(argv[++i], cfg.server_ip);
                }
                else if (!strncmp(argv[i], "-h", 2)
                         || !strncmp(argv[i], "--help", 6))
                {
                        usage(argv[0]);
                        exit(1);
                }
        }
        return cfg;
}

/* ── connect to rendezvous ───────────────────────────────────────────────── */

static int32_t connect_to_rendezvous(
        const Config            *cfg,
        const struct sockaddr_in *local_addr)
{
        int32_t fd = net_make_bound_socket(local_addr);
        if (fd == -1) return -1;

        struct sockaddr_in sa = {0};
        sa.sin_family          = AF_INET;
        sa.sin_addr.s_addr     = inet_addr(cfg->server_ip);
        sa.sin_port            = htons(cfg->server_port);

        printf("Connecting to rendezvous server %s:%d ...\n",
               cfg->server_ip, cfg->server_port);

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                fprintf(stderr, "ERROR: Connection to rendezvous server failed.\n");
                close(fd);
                return -1;
        }

        printf("Connected.\n");
        return fd;
}

/*
 * Encrypted binary send: sends raw bytes as an encrypted packet.
 * Mirrors send_binary() in rendezvous.c.
 */
static bool send_binary(
	int32_t        fd,
	const uint8_t *data,
	uint32_t       len,
	const Session *s)
{
	uint32_t cipher_len = len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
	size_t packet_size = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
				sizeof(uint32_t) +
				cipher_len;

	uint8_t *packet = malloc(packet_size);
	if (!packet) {
		fprintf(stderr, "ERROR: send_binary(): malloc(packet) failed.\n");
		return false;
	}

	uint8_t *nonce = packet;
	randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

	uint32_t net_len = htonl(len);
	memcpy(packet + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
		&net_len, sizeof(uint32_t));

	uint8_t *cipher = packet +
		crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
		sizeof(uint32_t);
	unsigned long long actual_clen;
	crypto_aead_xchacha20poly1305_ietf_encrypt(
		cipher, &actual_clen,
		data, len,
		NULL, 0, NULL,
		nonce, s->tx);

	bool ok = (send(fd, packet, packet_size, 0) == (ssize_t)packet_size);
	if (!ok) fprintf(stderr, "ERROR: send_binary(): failed.\n");

	free(packet);
	return ok;
}

/*
 * Counterpart to send_binary.  Allocates *out_data (caller must free).
 */
static bool recv_binary(
	int32_t 	fd,
	uint8_t 	**out_data,
	uint32_t 	*out_len,
	const Session 	*s)
{
	uint8_t nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
	if (!net_recv_all(fd, nonce, sizeof(nonce))) {
		fprintf(stderr, "ERROR: recv_binary(): disconnected reading nonce.\n");
		return false;
	}

	uint32_t net_len;
	if (!net_recv_all(fd, &net_len, sizeof(net_len))) {
		fprintf(stderr, "ERROR: recv_binary(): disconnected reading length.\n");
		return false;
	}
	uint32_t plain_len = ntohl(net_len);
	uint32_t cipher_len = plain_len +
				crypto_aead_xchacha20poly1305_ietf_ABYTES;

	uint8_t *cipher = malloc(cipher_len);
	if (!cipher) return false;
	if (!net_recv_all(fd, cipher, cipher_len)) {
		free(cipher);
		return false;
	}

	uint8_t *plain = malloc(plain_len);
	if (!plain) { free(cipher); return false; }

	unsigned long long actual_plen;
	int32_t rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
		plain, &actual_plen,
		NULL,
		cipher, cipher_len,
		NULL, 0,
		nonce, s->rx);

	free(cipher);

	if (rc != 0) {
		fprintf(stderr, "FATAL: recv_binary(): authentication failed.\n");
		free(plain);
		return false;
	}

	*out_data = plain;
	*out_len = (uint32_t)actual_plen;
	return true;
}

/*
 * Drive the full rendezvous conversation over the encrypted channel.
 *
 * The server sends TEXT messages (encrypted strings). We handle three kinds:
 * 	"INPUT: ..." -> read stdin, send back encrypted
 * 	"SEND_PUBKE" -> send our P2P public key as an encrypted binary blob
 *	"ERROR: ..." -> print error and return false
 *	"A.B.C.D:Pn" -> peer's IP:Port; the NEXT message will be peer's public key
 *
 * On success:
 * 	*peer 		is filled with the peer's IP and port
 * 	*peer_pub_out	points to a heap-allocated buffer of crypto_kx_PUBLICKEYBYTES
 * 			(caller must free)
 */
static bool do_rendezvous_exchange(
        int32_t         rendezvous_fd,
        const Session  *s,
	const Keypair  *my_kp,
        PeerInfo       *peer,
	uint8_t       **peer_pub_out)
{
        for (;;) {
                char *msg = NULL;
                if (!crypto_recv_decrypt(rendezvous_fd, &msg, s)) {
                        printf("\nConnection to rendezvous server closed.\n");
                        return false;
                }

                printf("%s", msg);
                fflush(stdout);

                if (strstr(msg, "ERROR")) {
                        free(msg);
                        return false;
                }

                if (strstr(msg, "INPUT: ")) {
                        /* read one line from stdin and send it back, encrypted */
                        char input[256];
                        if (fgets(input, sizeof(input), stdin) != NULL) {
                                if (!crypto_encrypt_send(rendezvous_fd, input, s)) {
                                        free(msg);
                                        return false;
                                }
                        }
                } else if (!strcmp(msg, "SEND PUBKEY")) {
			printf("\n[Sending P2P public key to rendezvous...]\n");
			if (!send_binary(rendezvous_fd,
		    			 my_kp->pub,
		    			 crypto_kx_PUBLICKEYBYTES, s))
			{
				free(msg);
				return false;
			}
		}
                /* IP:Port reply — format "A.B.C.D:PORT\n" */
                else if (sscanf(msg, "%15[^:]:%hu", peer->ip, &peer->port) == 2) {
                        printf("\n>>> Target peer: %s:%d <<<\n",
                               peer->ip, peer->port);
                        free(msg);

			uint8_t *pub  = NULL;
			uint32_t plen = 0;
			if (!recv_binary(rendezvous_fd, &pub, &plen, s)
			    || plen != crypto_kx_PUBLICKEYBYTES)
			{
				fprintf(stderr,
	    				"ERROR: Bad peer public key from rendezvous.\n");
				free(pub);
				return false;
			}

			printf("[Received peer P2P public key from rendezvous.]\n");
			*peer_pub_out = pub;
                        return true;
                }

                free(msg);
        }
}

/* ── TCP hole punch ──────────────────────────────────────────────────────── */

static int32_t do_hole_punch(
        const PeerInfo           *peer,
        const struct sockaddr_in *local_addr,
        int32_t                   max_attempts)
{
        struct sockaddr_in pa = {0};
        pa.sin_family           = AF_INET;
        pa.sin_addr.s_addr      = inet_addr(peer->ip);
        pa.sin_port             = htons(peer->port);

        printf("Initiating TCP hole punch to %s:%d...\n",
               peer->ip, peer->port);

        for (int i = 0; i < max_attempts; i++) {
                int32_t fd = net_make_bound_socket(local_addr);
                if (fd == -1) return -1;

                if (connect(fd, (struct sockaddr *)&pa, sizeof(pa)) == 0)
                        return fd;

                close(fd);
                printf("Punch attempt %d failed. Retrying in 1s...\n", i + 1);
                sleep(1);
        }

        return -1;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
        Config cfg = parse_args(argc, argv);
        printf("INFO: Rendezvous %s:%d | Local port %d\n",
               cfg.server_ip, cfg.server_port, cfg.local_port);

        if (sodium_init() < 0) {
                fprintf(stderr, "ERROR: libsodium init failed.\n");
                return 1;
        }

	Keypair my_kp;
	crypto_gen_keypair(&my_kp);
	printf("Generated P2P keypair.\n");

        struct sockaddr_in local_addr = {0};
        local_addr.sin_family          = AF_INET;
        local_addr.sin_addr.s_addr     = htonl(INADDR_ANY);
        local_addr.sin_port            = htons(cfg.local_port);

        /* ── connect & establish E2EE with rendezvous server ── */
        int32_t rendezvous_fd = connect_to_rendezvous(&cfg, &local_addr);
        if (rendezvous_fd == -1) {
		sodium_memzero(&my_kp, sizeof(my_kp));
		return 1;
	}

        Session rs = {0};   /* rendezvous session keys */
        if (!crypto_do_key_exchange(rendezvous_fd, &rs)) {
                fprintf(stderr, "ERROR: Key exchange with rendezvous failed.\n");
		sodium_memzero(&my_kp, sizeof(my_kp));
                close(rendezvous_fd);
                return 1;
        }
        printf("Secure channel with rendezvous established.\n");

        /* ── exchange room credentials over encrypted channel ── */
        PeerInfo peer    = {0};
	uint8_t *peer_pub_key = NULL;

        bool got_peer = do_rendezvous_exchange(
		rendezvous_fd, &rs, &my_kp, &peer, &peer_pub_key);

        /* zero rendezvous session keys — no longer needed */
        sodium_memzero(&rs, sizeof(rs));
        close(rendezvous_fd);

        if (!got_peer) {
		sodium_memzero(&my_kp, sizeof(my_kp));
		return 1;
	}

        /* ── TCP hole punch ── */
        int32_t p2p_fd = do_hole_punch(&peer, &local_addr, 15);
        if (p2p_fd == -1) {
                fprintf(stderr,
                        "ERROR: Hole punch failed after 15 attempts."
                        " NAT may be too strict.\n");
		free(peer_pub_key);
		sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        printf("\n=== === === === === === === === ===\n");
        printf("  SUCCESS! P2P CONNECTION ESTABLISHED!");
        printf("\n=== === === === === === === === ===\n\n");

	/*
	 * Derive the P2P session keys from our keypair and the peer's public
	 * key - no extra round-trip over the P2P connection needed.
	 */
        Session ps = {0};
	bool ok = crypto_derive_session(&my_kp, peer_pub_key, &ps);

	free(peer_pub_key);
	sodium_memzero(&my_kp, sizeof(my_kp));

        if (!ok) {
                close(p2p_fd);
                return 1;
        }

        /* ── demo: exchange names over encrypted P2P channel ── */
        char my_name[64];
        printf("Enter your name: ");
        fflush(stdout);
        if (fgets(my_name, sizeof(my_name) - 1, stdin) == NULL) {
                close(p2p_fd);
                return 1;
        }
        my_name[strcspn(my_name, "\r\n")] = 0;

        if (!crypto_encrypt_send(p2p_fd, my_name, &ps)) {
                close(p2p_fd);
                return 1;
        }

        char *peer_name = NULL;
        if (!crypto_recv_decrypt(p2p_fd, &peer_name, &ps)) {
                close(p2p_fd);
                return 1;
        }

        printf("\n=== === === === === === === === ===\n");
        printf("  Peer says their name is: %s\n", peer_name);
        printf("=== === === === === === === === ===\n");

        free(peer_name);
        sodium_memzero(&ps, sizeof(ps));
        close(p2p_fd);
        return 0;
}
