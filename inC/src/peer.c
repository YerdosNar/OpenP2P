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

// default values
#define DEFAULT_SERVER_PORT     8888
#define DEFAULT_LOCAL_PORT      50000
#define MAX_IP_LEN              16

// types
typedef struct {
        char            server_ip[MAX_IP_LEN];
        uint16_t        server_port;
        uint16_t        local_port;
} Config;

typedef struct {
        char            ip[MAX_IP_LEN];
        uint16_t        port;
} PeerInfo;

void resolve_dom_name(const char *domain_name, char *out_ip) {
        struct hostent *h = gethostbyname(domain_name);
        if (h) {
                char *ip = inet_ntoa(*(struct in_addr *)h->h_addr_list[0]);
                strncpy(out_ip, ip, MAX_IP_LEN - 1);
        }
}

void usage(const char *exe_file) {
        printf("Usage: %s [options]\n\n", exe_file);
        printf("Options:\n");
        printf("        -s, --server-port <port num>            Server port number      (default=%d)\n", DEFAULT_SERVER_PORT);
        printf("        -i, --ip <ip>                           Server IP address       (default=127.0.0.1)\n");
        printf("        -l, --local-port <port num>             Set local port number   (default=%d)\n", DEFAULT_LOCAL_PORT);
        printf("        -d, --domain-name <dom name>            Server domain name\n");
        printf("        -h, --help                              Show this help message\n");
        printf("\n");
        printf("Example:\n");
        printf("        %s -d example.com -s 8888\n", exe_file);
}

static Config parse_args(int argc, char **argv) {
        Config cfg;
        strncpy(cfg.server_ip, "127.0.0.1", MAX_IP_LEN - 1);
        cfg.server_port = DEFAULT_SERVER_PORT;
        cfg.local_port  = DEFAULT_LOCAL_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-s", 2)
                        || !strncmp(argv[i], "--server-port", 13))
                {
                        if (i + 1 < argc) cfg.server_port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strncmp(argv[i], "-i", 2)
                        || !strncmp(argv[i], "--ip", 4))
                {
                        if (i + 1 < argc) strncpy(cfg.server_ip, argv[++i], MAX_IP_LEN - 1);
                }
                else if (!strncmp(argv[i], "-l", 2)
                        || !strncmp(argv[i], "--local-port", 12))
                {
                        if (i + 1 < argc) cfg.local_port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strncmp(argv[i], "-d", 2)
                        || !strncmp(argv[i], "--domain-name", 13))
                {
                        if (i + 1 < argc) resolve_dom_name(argv[++i], cfg.server_ip);
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

        printf("Connecting to Rendezvous Server %s:%d...\n",
               cfg->server_ip, cfg->server_port);

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                fprintf(stderr, "ERROR: Connection to Rendezvous Server failed.\n");
                close(fd);
                return -1;
        }

        printf("Connected successfully!\n");
        return fd;
}

/*
 * All traffic with the rendezvous server is now E2EE:
 *  - server sends prompts as encrypted "INPUT: ..." strings
 *  - we decrypt, check for "INPUT: " prefix, read stdin, encrypt and send back
 *  - when we receive a non-INPUT message, it's either an error or the IP:Port
 */
static bool do_rendezvous_exchange(
        int32_t   rendezvous_fd,
        Session  *s,
        PeerInfo *peer)
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
                        char input[256];
                        if (fgets(input, sizeof(input), stdin) != NULL) {
                                if (!crypto_encrypt_send(rendezvous_fd, input, s)) {
                                        free(msg);
                                        return false;
                                }
                        }
                }

                else if (sscanf(msg, "%15[^:]:%hu", peer->ip, &peer->port) == 2) {
                        printf("\n>>> Target peer: %s:%d <<<\n",
                               peer->ip, peer->port);
                        free(msg);
                        return true;
                }

                free(msg);
        }
}

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

                if (connect(fd, (struct sockaddr *)&pa, sizeof(pa)) == 0) return fd;

                close(fd);
                printf("Punch attempt %d failed. Retrying in 1s...\n", i + 1);
                sleep(1);
        }

        return -1;
}

int main(int argc, char **argv) {
        Config cfg = parse_args(argc, argv);
        printf("INFO: Rendezvous %s:%d | Local port %d\n",
               cfg.server_ip, cfg.server_port, cfg.local_port);

        if (sodium_init() < 0) {
                fprintf(stderr, "ERROR: libsodium init failed.\n");
                return 1;
        }

        struct sockaddr_in local_addr = {0};
        local_addr.sin_family          = AF_INET;
        local_addr.sin_addr.s_addr     = htonl(INADDR_ANY);
        local_addr.sin_port            = htons(cfg.local_port);

        // connect to rendezvous and establish E2EE
        int32_t rendezvous_fd = connect_to_rendezvous(&cfg, &local_addr);
        if (rendezvous_fd == -1) return 1;

        Session rs = {0};
        if (!crypto_do_key_exchange(rendezvous_fd, &rs)) {
                fprintf(stderr, "ERROR: Key exchange with rendezvous failed.\n");
                close(rendezvous_fd);
                return 1;
        }
        printf("Secure channel with rendezvous established.\n");


        PeerInfo peer = {0};
        bool got_peer = do_rendezvous_exchange(rendezvous_fd, &rs, &peer);

        // zero rendezvous session keys
        sodium_memzero(&rs, sizeof(rs));
        close(rendezvous_fd);

        if (!got_peer) return 1;

        int32_t p2p_fd = do_hole_punch(&peer, &local_addr, 15);
        if (p2p_fd == -1) {
                fprintf(stderr,
                        "ERROR: Hole punch failed after 15 attempts."
                        " NAT may be too strict.\n");
                return 1;
        }

        printf("\n=== === === === === === === === ===\n");
        printf("SUCCESS! P2P CONNECTION ESTABLISHED!");
        printf("\n=== === === === === === === === ===\n\n");

        // Initializing E2EE with libsodium
        Session ps = {0};
        if (!crypto_do_key_exchange(p2p_fd, &ps)) {
                close(p2p_fd);
                return 1;
        }

        // Share the name
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
        printf("  Peer says their name is: %s", peer_name);
        printf("\n=== === === === === === === === ===\n\n");

        free(peer_name);
        sodium_memzero(&ps, sizeof(ps));
        close(p2p_fd);
        return 0;
}
