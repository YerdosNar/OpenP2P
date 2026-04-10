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

#define DEFAULT_SERVER_PORT     8888
#define DEFAULT_LOCAL_PORT      50000
#define MAX_IP_LEN              16

typedef struct {
        char     server_ip[MAX_IP_LEN];
        uint16_t server_port;
        uint16_t local_port;
} Config;

typedef struct {
        char     ip[MAX_IP_LEN];
        uint16_t port;
} PeerInfo;

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

        printf("INFO: Connecting to rendezvous server %s:%d ...\n",
               cfg->server_ip, cfg->server_port);

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                fprintf(stderr, "ERROR: Connection to rendezvous server failed.\n");
                close(fd);
                return -1;
        }

        printf("SUCCESS: Connected.\n");
        return fd;
}

/*
 * Drive the full rendezvous conversation over the encrypted channel.
 *
 * The server sends TEXT messages (encrypted strings).  We handle three kinds:
 *   "INPUT: ..."  -> read stdin, send back encrypted
 *   "SEND_PUBKEY" -> send our P2P public key as an encrypted binary blob
 *   "ERROR ..."   -> print and return false
 *   "A.B.C.D:N"  -> peer's IP:Port; the NEXT message will be peer's public key
 *
 * On success:
 *   *peer    is filled with the peer's IP and port
 *   *peer_pub_out points to a heap-allocated buffer of crypto_kx_PUBLICKEYBYTES
 *                 (caller must free)
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
                        printf("\nERROR: Connection to rendezvous server closed.\n");
                        return false;
                }

                printf("RENDEZVOUS: %s", msg);
                fflush(stdout);

                if (strstr(msg, "ERROR")) {
                        free(msg);
                        return false;
                }

                if (strstr(msg, "INPUT: ")) {
                        char input[256];
                        if (fgets(input, sizeof(input), stdin) != NULL) {
                                if (!crypto_encrypt_send(rendezvous_fd, input, s)) {
                                        free(msg);
                                        return false;
                                }
                        }
                }
                else if (strcmp(msg, "SEND_PUBKEY") == 0) {
                        /*
                         * Server is asking for our P2P public key.
                         * Send it as a raw encrypted binary blob.
                         */
                        printf("\nINFO: Sending P2P public key to rendezvous...\n");
                        if (!crypto_encrypt_send_bin(rendezvous_fd,
                                         my_kp->pub,
                                         crypto_kx_PUBLICKEYBYTES, s))
                        {
                                free(msg);
                                return false;
                        }
                }
                /* peer IP:Port — next message will be their public key */
                else if (sscanf(msg, "%15[^:]:%hu", peer->ip, &peer->port) == 2) {
                        printf("\n>>> Target peer: %s:%d <<<\n",
                               peer->ip, peer->port);
                        free(msg);

                        /* receive peer's public key */
                        uint8_t *pub  = NULL;
                        uint32_t plen = 0;
                        if (!crypto_recv_decrypt_bin(rendezvous_fd, &pub, &plen, s)
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

/* ── TCP hole punch ───────────────────────────────────────────────────────── */

static int32_t do_hole_punch(
        const PeerInfo           *peer,
        const struct sockaddr_in *local_addr,
        int32_t                   max_attempts)
{
        struct sockaddr_in pa = {0};
        pa.sin_family           = AF_INET;
        pa.sin_addr.s_addr      = inet_addr(peer->ip);
        pa.sin_port             = htons(peer->port);

        printf("INFO: Initiating TCP hole punch to %s:%d...\n",
               peer->ip, peer->port);

        for (int i = 0; i < max_attempts; i++) {
                int32_t fd = net_make_bound_socket(local_addr);
                if (fd == -1) return -1;

                if (connect(fd, (struct sockaddr *)&pa, sizeof(pa)) == 0)
                        return fd;

                close(fd);
                printf("WARNING: Punch attempt %d failed. Retrying in 1s...\n", i + 1);
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

        /*
         * Generate our P2P keypair BEFORE connecting to rendezvous.
         * We keep the secret key alive until after crypto_derive_session(),
         * then zero it immediately.
         */
        Keypair my_kp;
        crypto_gen_keypair(&my_kp);
        printf("INFO: Generated P2P keypair.\n");

        struct sockaddr_in local_addr = {0};
        local_addr.sin_family          = AF_INET;
        local_addr.sin_addr.s_addr     = htonl(INADDR_ANY);
        local_addr.sin_port            = htons(cfg.local_port);

        /* connect and establish E2EE with rendezvous */
        int32_t rendezvous_fd = connect_to_rendezvous(&cfg, &local_addr);
        if (rendezvous_fd == -1) {
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        Session rs = {0};
        if (!crypto_do_key_exchange(rendezvous_fd, &rs)) {
                fprintf(stderr, "ERROR: Key exchange with rendezvous failed.\n");
                sodium_memzero(&my_kp, sizeof(my_kp));
                close(rendezvous_fd);
                return 1;
        }
        printf("SUCCESS: Secure channel with rendezvous established.\n");

        /* run the rendezvous protocol — get peer's IP:Port and public key */
        PeerInfo peer         = {0};
        uint8_t *peer_pub_key = NULL;

        bool got_peer = do_rendezvous_exchange(
                rendezvous_fd, &rs, &my_kp, &peer, &peer_pub_key);

        sodium_memzero(&rs, sizeof(rs));
        close(rendezvous_fd);

        if (!got_peer) {
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        /* TCP hole punch */
        int32_t p2p_fd = do_hole_punch(&peer, &local_addr, 15);
        if (p2p_fd == -1) {
                fprintf(stderr,
                        "ERROR: Hole punch failed after 15 attempts."
                        " NAT may be too strict.\n");
                free(peer_pub_key);
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        printf("SUCCESS: P2P connection established!");

        /*
         * Derive the P2P session keys from our keypair and the peer's public
         * key — no extra round-trip over the P2P connection needed.
         */
        Session ps = {0};
        bool ok = crypto_derive_session(&my_kp, peer_pub_key, &ps);

        free(peer_pub_key);
        sodium_memzero(&my_kp, sizeof(my_kp));

        if (!ok) {
                close(p2p_fd);
                return 1;
        }
        printf("SUCCESS: P2P E2EE established!");

        /* demo: exchange names over the encrypted P2P channel */
        char my_name[64];
        printf("INPUT: Enter your name: ");
        fflush(stdout);
        if (fgets(my_name, sizeof(my_name) - 1, stdin) == NULL) {
                close(p2p_fd);
                return 1;
        }
        net_strip_newline(my_name);

        if (!crypto_encrypt_send(p2p_fd, my_name, &ps)) {
                fprintf(stderr, "ERROR: Could not send name.\n");
                close(p2p_fd);
                return 1;
        }
        printf("INFO: Sent my name: '%s'.\n", my_name);

        char *peer_name = NULL;
        if (!crypto_recv_decrypt(p2p_fd, &peer_name, &ps)) {
                close(p2p_fd);
                return 1;
        }
        printf("INFO: Received peer's name: '%s'.\n", peer_name);

        printf("\n======================================================\n");
        printf("  Your legendary chat with '%s' begins here!", peer_name);
        printf("\n======================================================\n");

        for (;;) {
                char message[1024];
                printf("%s: ", my_name);
                if (fgets(message, sizeof(message) - 1, stdin) == NULL) {
                        close(p2p_fd);
                        return 1;
                }
                net_strip_newline(message);

                if (!crypto_encrypt_send(p2p_fd, message, &ps)) {
                        fprintf(stderr, "ERROR: Could not send message.\n");
                        close(p2p_fd);
                        return 1;
                }

                char *peer_msg = NULL;
                if (!crypto_recv_decrypt(p2p_fd, &peer_msg, &ps)) {
                        close(p2p_fd);
                        return 1;
                }
                printf("%s: '%s'.\n", peer_name, peer_msg);
        }

        free(peer_name);
        sodium_memzero(&ps, sizeof(ps));
        close(p2p_fd);
        return 0;
}
