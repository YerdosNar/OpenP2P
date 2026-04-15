#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "../include/crypto.h"
#include "../include/net.h"
#include "../include/logger.h"

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

typedef struct {
        int32_t         fd;
        const Session   *session;
        const char      *my_name;
        const char      *peer_name;
        volatile bool  running;
} ChatCtx;

static void resolve_domain(const char *domain, char *out_ip)
{
        struct hostent *h = gethostbyname(domain);
        if (h) {
                char *ip = inet_ntoa(*(struct in_addr *)h->h_addr_list[0]);
                strncpy(out_ip, ip, MAX_IP_LEN - 1);
                out_ip[MAX_IP_LEN - 1] = '\0';
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
        printf("  -d, --domain-name <n>    Rendezvous server domain\n");
        printf("  -h, --help                  Show this help message\n\n");
        printf("Example:\n  %s -d example.com -s 8888\n", exe);
}

static Config parse_args(int argc, char **argv)
{
        Config cfg = {0};
        strncpy(cfg.server_ip, "127.0.0.1", MAX_IP_LEN - 1);
        cfg.server_ip[MAX_IP_LEN - 1] = '\0';
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
                        if (i + 1 < argc) {
                                strncpy(cfg.server_ip, argv[++i], MAX_IP_LEN - 1);
                                cfg.server_ip[MAX_IP_LEN - 1] = '\0';
                        }
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

        info("Connecting...\n");

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                err("Connection to rendezvous server failed.\n");
                close(fd);
                return -1;
        }

        success("Connected to rendezvous server "
                MGN "%s"
                NOC ":"
                CYN "%d"
                NOC "...\n",
               cfg->server_ip, cfg->server_port);
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
                        err("Connection to rendezvous server closed.\n");
                        return false;
                }

                printf(BCYN "RENDEZVOUS:" NOC " %s", msg);
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
                        printf("\n");
                        info("Sending P2P public key to rendezvous...\n");
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
                        printf("\n>>> Target peer: "
                               MGN "%s"
                               NOC ":"
                               CYN "%d"
                               NOC " <<<\n",
                               peer->ip, peer->port);
                        free(msg);

                        /* receive peer's public key */
                        uint8_t *pub  = NULL;
                        uint32_t plen = 0;
                        if (!crypto_recv_decrypt_bin(rendezvous_fd, &pub, &plen, s)
                            || plen != crypto_kx_PUBLICKEYBYTES)
                        {
                                err("Bad peer public key from rendezvous.\n");
                                free(pub);
                                return false;
                        }

                        info("Received peer P2P public key from rendezvous.\n");
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

        info("Initiating TCP hole punch to "
                               MGN "%s"
                               NOC ":"
                               CYN "%d"
                               NOC "...\n",
                               peer->ip, peer->port);

        for (int i = 0; i < max_attempts; i++) {
                int32_t fd = net_make_bound_socket(local_addr);
                if (fd == -1) return -1;

                if (connect(fd, (struct sockaddr *)&pa, sizeof(pa)) == 0)
                        return fd;

                close(fd);
                warn("Punch attempt " YEL "%d" NOC " failed. Retrying in 1s...\n", i + 1);
                sleep(1);
        }

        return -1;
}

/* ── chat threads ────────────────────────────────────────────────────────── */

static  void *recv_thread(void *arg)
{
        ChatCtx *ctx = arg;

        while (ctx->running) {
                char *peer_msg = NULL;
                if (!crypto_recv_decrypt(ctx->fd, &peer_msg, ctx->session)) {
                        if (ctx->running) {
                                ctx->running = false;
                                printf("\n[%s disconnected.]\n", ctx->peer_name);
                                shutdown(ctx->fd, SHUT_RDWR);
                        }
                        break;
                }
                /*
                 * Erase the current input prompt, print the incoming message,
                 * then reprint the prompt so the user can keep typing.
                 *
                 * \r          = move cursor to column 0
                 * \033[2K     = clear entire current line
                 */
                printf("\r\033[2K%s: %s\n%s: ",
                       ctx->peer_name, peer_msg, ctx->my_name);
                fflush(stdout);
                free(peer_msg);
        }

        return NULL;
}

static void send_loop(ChatCtx *ctx)
{
        char message[1024];

        while (ctx->running) {
                printf("%s: ", ctx->my_name);
                fflush(stdout);

                if (fgets(message, sizeof(message), stdin) == NULL) {
                        ctx->running = false;
                        printf("\n[You left the chat.]\n");
                        shutdown(ctx->fd, SHUT_RDWR);
                        break;
                }
                net_strip_newline(message);

                if (message[0] == '\0') continue;

                if (!ctx->running) break;

                if (!crypto_encrypt_send(ctx->fd, message, ctx->session)) {
                        if (ctx->running) {
                                ctx->running = false;
                                fprintf(stderr, "\n[Connection lost.]\n");
                        }
                        break;
                }
        }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
        Config cfg = parse_args(argc, argv);
        info("Rendezvous "
                MGN "%s"
                NOC ":"
                CYN "%d"
                NOC "| Local port "
                CYN "%d\n" NOC,
               cfg.server_ip, cfg.server_port, cfg.local_port);

        /* Ignore SIGPIPE so broken sends return EPIPE instead of killing us */
        signal(SIGPIPE, SIG_IGN);

        if (sodium_init() < 0) {
                err("libsodium init failed.\n");
                return 1;
        }

        /*
         * Generate our P2P keypair BEFORE connecting to rendezvous.
         * We keep the secret key alive until after crypto_derive_session(),
         * then zero it immediately.
         */
        Keypair my_kp;
        crypto_gen_keypair(&my_kp);
        info("Generated P2P keypair.\n");

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
                err("Key exchange with rendezvous failed.\n");
                sodium_memzero(&my_kp, sizeof(my_kp));
                close(rendezvous_fd);
                return 1;
        }
        success("Secure channel with rendezvous established.\n");

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
                err("Hole punch failed after 15 attempts."
                        " NAT may be too strict.\n");
                free(peer_pub_key);
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        success("P2P connection established!\n");

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
        success("P2P E2EE established!\n");

        /* exchange names over the encrypted P2P channel */
        char my_name[64];
        printf(BMGN "INPUT" NOC ": Enter your name: ");
        fflush(stdout);
        if (fgets(my_name, sizeof(my_name) - 1, stdin) == NULL) {
                close(p2p_fd);
                return 1;
        }
        net_strip_newline(my_name);

        if (!crypto_encrypt_send(p2p_fd, my_name, &ps)) {
                err("Could not send name.\n");
                close(p2p_fd);
                return 1;
        }
        info("Sent my name: '%s'.\n", my_name);

        char *peer_name = NULL;
        if (!crypto_recv_decrypt(p2p_fd, &peer_name, &ps)) {
                close(p2p_fd);
                return 1;
        }
        info("Received peer's name: '%s'.\n", peer_name);

        printf("\n======================================================\n");
        printf("  Your legendary chat with '%s' begins here!", peer_name);
        printf("\n  (type a message and press Enter - Ctrl-D to quit)");
        printf("\n======================================================\n\n");

        ChatCtx chat = {
                .fd             = p2p_fd,
                .session        = &ps,
                .my_name        = my_name,
                .peer_name      = peer_name,
                .running        = true,
        };

        pthread_t rtid;
        if (pthread_create(&rtid, NULL, recv_thread, &chat) != 0) {
                err("pthread_create() failed.\n");
                close(p2p_fd);
                free(peer_name);
                return 1;
        }

        /* sender runs on the main thread (needs stdin) */
        send_loop(&chat);

        /* wait for the receiver to finish */
        pthread_join(rtid, NULL);

        /* cleanup */
        free(peer_name);
        sodium_memzero(&ps, sizeof(ps));
        close(p2p_fd);
        return 0;
}
