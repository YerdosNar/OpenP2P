#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sodium.h>

#include "../include/crypto.h"
#include "../include/net.h"
#include "../include/room.h"
#include "../include/logger.h"

#define DEFAULT_PORT        8888
#define DEFAULT_LOG_FILE    "con.log"

typedef struct {
        int32_t     client_fd;
        char        peer_ip[MAX_IP_LEN];
        uint16_t    peer_port;
        RoomTable  *rt;
} ClientCtx;

static void usage(const char *exe)
{
        printf("Usage: %s [options]\n\n", exe);
        printf("Options:\n");
        printf("  -p, --port <port>        Listening port          (default=%d)\n",
               DEFAULT_PORT);
        printf("  -l, --log <file>         Log filename            (default=%s)\n",
               DEFAULT_LOG_FILE);
        printf("  -m, --max-rooms <n>      Max rooms in queue      (default=%d)\n",
               MAX_ROOMS);
        printf("  --debug                     Debug mode, prints all steps info\n");
        printf("  -h, --help               Show this help message\n\n");
        printf("Example:\n  %s -p 2222 -l server.log\n", exe);
        exit(1);
}

/*
 * Send an "INPUT: <prompt>" string over the encrypted channel, then
 * receive and return the client's response.
 * Returns heap-allocated string on success (caller must free), NULL on error.
 */
static char *ask_n_receive(const char *prompt, int32_t fd, const Session *s)
{
        size_t send_len = strlen(prompt) + 9;
        char  *tagged   = malloc(send_len);
        if (!tagged) return NULL;
        snprintf(tagged, send_len, "INPUT: %s ", prompt);

        if (!crypto_encrypt_send(fd, tagged, s)) {
                free(tagged);
                return NULL;
        }
        free(tagged);

        char *response = NULL;
        if (!crypto_recv_decrypt(fd, &response, s)) return NULL;

        net_strip_newline(response);
        return response;
}

static bool send_msg(int32_t fd, const char *msg, const Session *s)
{
        return crypto_encrypt_send(fd, msg, s);
}

/* ── handle_host ─────────────────────────────────────────────────────────── */

/*
 * Full host registration flow:
 *   1. Ask for room ID (retry until unique and non-empty)
 *   2. Ask for room password
 *   3. Receive host's P2P public key (binary, encrypted)
 *   4. Register room — keep fd open, waiting for a joiner
 */
static void handle_host(ClientCtx *ctx, const Session *s)
{
        int32_t    fd = ctx->client_fd;
        RoomTable *rt = ctx->rt;

        char *id = NULL;
        for (;;) {
                id = ask_n_receive("HostRoom ID (7 chars):", fd, s);
                if (!id) return;

                if (strlen(id) == 0) {
                        send_msg(fd, "INPUT: ID cannot be empty. Try again:", s);
                        free(id);
                        continue;
                }
                if (room_id_exists(rt, id)) {
                        send_msg(fd,
                                 "INPUT: That ID is already in use. Choose another:",
                                 s);
                        free(id);
                        continue;
                }
                break;
        }

        char *pw = ask_n_receive("HostRoom PW (7 chars):", fd, s);
        if (!pw) { free(id); return; }

        /* ask the host to send its P2P public key */
        send_msg(fd, "SEND_PUBKEY", s);

        uint8_t *pub_key = NULL;
        uint32_t pub_len = 0;
        if (!crypto_recv_decrypt_bin(fd, &pub_key, &pub_len, s)
            || pub_len != crypto_kx_PUBLICKEYBYTES)
        {
                err("Bad public key from host.\n");
                free(pub_key); free(id); free(pw);
                close(fd);
                return;
        }

        const char *err = NULL;
        int32_t slot = room_try_register(
                rt, id, pw,
                ctx->peer_ip, ctx->peer_port, fd,
                s, pub_key, &err);

        free(pub_key);
        free(id);
        free(pw);

        if (slot == -1) {
                send_msg(fd, err, s);
                close(fd);
                return;
        }

        printf("Host registered in slot %d  waiting for peer...  [%s:%d]\n",
               slot, ctx->peer_ip, ctx->peer_port);

        send_msg(fd, "Room created. Waiting for peer to join...\n", s);
        /* fd stays open — joiner thread will send to it later */
}

/* ── handle_joiner ───────────────────────────────────────────────────────── */

/*
 * Full joiner flow:
 *   1. Ask for room ID
 *   2. Ask for password
 *   3. Receive joiner's P2P public key (binary, encrypted)
 *   4. Send to host:   joiner IP:Port  then joiner's raw public key
 *   5. Send to joiner: host  IP:Port   then host's  raw public key
 */
static void handle_joiner(ClientCtx *ctx, const Session *s)
{
        int32_t    fd = ctx->client_fd;
        RoomTable *rt = ctx->rt;

        /* 1 - room ID */
        char *id = ask_n_receive("HostRoom ID (case sensitive):", fd, s);
        if (!id) return;

        /* 2 - password */
        char *pw = ask_n_receive("HostRoom PW (case sensitive):", fd, s);
        if (!pw) { free(id); close(fd); return; }

        /* 3 - joiner public key */
        send_msg(fd, "SEND_PUBKEY", s);

        uint8_t *joiner_pub = NULL;
        uint32_t joiner_pub_len = 0;
        if (!crypto_recv_decrypt_bin(fd, &joiner_pub, &joiner_pub_len, s)
            || joiner_pub_len != crypto_kx_PUBLICKEYBYTES)
        {
                err("Bad public key from joiner.\n");
                free(joiner_pub); free(id); free(pw);
                close(fd);
                return;
        }

        /* 4 - atomic claim: lookup + pw check + copy host info + deactivate */
        char     host_ip[MAX_IP_LEN] = {0};
        uint16_t host_port;
        int32_t  host_fd;
        Session  host_session;
        uint8_t  host_pub[crypto_kx_PUBLICKEYBYTES];
        const char *err = NULL;

        bool ok = room_claim_for_joiner(
                rt, id, pw,
                host_ip, &host_port, &host_fd, &host_session, host_pub,
                &err);

        if (!ok) {
                send_msg(fd, err, s);
                printf("Joiner rejected: %s", err);
                free(joiner_pub);
                close(fd);
                return;
        }

        info("Room claimed. Distributing peer info. [%s:%d]\n",
               ctx->peer_ip, ctx->peer_port);

        /* build IP:Port strings */
        char to_host[64], to_join[64];
        snprintf(to_host, sizeof(to_host), "%s:%d",
                 ctx->peer_ip, ctx->peer_port);
        snprintf(to_join, sizeof(to_join), "%s:%d",
                 host_ip, host_port);

        /*
         * To host:   joiner's IP:Port, then joiner's public key
         * To joiner: host's  IP:Port,  then host's  public key
         *
         * Each message is encrypted under its recipient's session keys.
         */
        crypto_encrypt_send(host_fd, to_host, &host_session);
        crypto_encrypt_send_bin(host_fd, joiner_pub,
                                crypto_kx_PUBLICKEYBYTES, &host_session);

        crypto_encrypt_send(fd, to_join, s);
        crypto_encrypt_send_bin(fd, host_pub,
                                crypto_kx_PUBLICKEYBYTES, s);

        info("Handshake complete. Tearing down rendezvous for room '%s'.\n", id);

        free(id);
        free(pw);
        free(joiner_pub);
        sodium_memzero(&host_session, sizeof(host_session));
        close(host_fd);
        close(fd);
}

/* client thread */

static void *client_thread(void *arg)
{
        ClientCtx *ctx = arg;

        printf("\n--- [thread %lu] Connection from %s:%d ---\n",
               (unsigned long)pthread_self(),
               ctx->peer_ip, ctx->peer_port);

        room_expire_stale(ctx->rt);

        Session s = {0};
        if (!crypto_do_key_exchange(ctx->client_fd, &s)) {
                warn("Key exchange failed with %s:%d.\n",
                        ctx->peer_ip, ctx->peer_port);
                close(ctx->client_fd);
                goto done;
        }
        success("Secure channel established with %s:%d.\n",
               ctx->peer_ip, ctx->peer_port);

        char *choice = ask_n_receive(
                "Are you [H]ost or [J]oin? [h/j]:",
                ctx->client_fd, &s);
        if (!choice) {
                warn("Peer disconnected before answering.\n");
                close(ctx->client_fd);
                goto done;
        }

        if (choice[0] == 'H' || choice[0] == 'h') {
                handle_host(ctx, &s);
        }
        else if (choice[0] == 'J' || choice[0] == 'j') {
                handle_joiner(ctx, &s);
        }
        else {
                err("Invalid selection.\n", &s);
                close(ctx->client_fd);
        }

        free(choice);
        room_print_stats(ctx->rt);

done:
        sodium_memzero(&s, sizeof(s));
        free(ctx);
        return NULL;
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
        uint16_t  listen_port  = DEFAULT_PORT;
        char     *log_filename = DEFAULT_LOG_FILE;
        uint32_t  max_rooms    = MAX_ROOMS;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-p", 2)
                    || !strncmp(argv[i], "--port", 6))
                {
                        if (i + 1 < argc) listen_port = (uint16_t)atoi(argv[++i]);
                        else warn("No port provided. Default: '%d'\n",
                                    DEFAULT_PORT);
                }
                else if (!strncmp(argv[i], "-l", 2)
                         || !strncmp(argv[i], "--log", 5))
                {
                        if (i + 1 < argc) log_filename = argv[++i];
                        else warn("No filename provided. Default: '%s'\n",
                                    DEFAULT_LOG_FILE);
                }
                else if (!strncmp(argv[i], "-m", 2)
                         || !strncmp(argv[i], "--max-rooms", 11))
                {
                        if (i + 1 < argc) max_rooms = (uint32_t)atoi(argv[++i]);
                        else warn("No number provided. Default: %d\n",
                                    MAX_ROOMS);
                }
                else if (!strncmp(argv[i], "--debug", 7)) logger_set_debug(true);
                else if (!strncmp(argv[i], "-h", 2)
                         || !strncmp(argv[i], "--help", 6))
                {
                        usage(argv[0]);
                }
        }

        info("Port=%d  Log=%s  MaxRooms=%u\n",
               listen_port, log_filename, max_rooms);

        if (sodium_init() < 0) {
                err("libsodium init failed.\n");
                return 1;
        }

        int32_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1) {
                err("socket() failed.\n");
                return 1;
        }

        int32_t opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                       &opt, sizeof(opt)) == -1) {
                err("setsockopt() failed.\n");
                return 1;
        }

        struct sockaddr_in sa = {0};
        sa.sin_family          = AF_INET;
        sa.sin_addr.s_addr     = INADDR_ANY;
        sa.sin_port            = htons(listen_port);

        if (bind(server_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                err("bind() failed.\n");
                return 1;
        }
        if (listen(server_fd, 128) == -1) {
                err("listen() failed.\n");
                return 1;
        }

        info("Rendezvous server listening on port %d...\n", listen_port);

        RoomTable rt;
        if (!room_table_init(&rt, max_rooms)) {
                err("room_table_init() failed.\n");
                close(server_fd);
                return 1;
        }

        for (;;) {
                struct sockaddr_in ca;
                socklen_t ca_len = sizeof(ca);

                int32_t client_fd = accept(server_fd,
                                           (struct sockaddr *)&ca, &ca_len);
                if (client_fd == -1) {
                        warn("accept() failed, skipping.\n");
                        continue;
                }

                ClientCtx *ctx = malloc(sizeof(*ctx));
                if (!ctx) {
                        err("malloc failed for ClientCtx.\n");
                        close(client_fd);
                        continue;
                }
                ctx->client_fd = client_fd;
                ctx->peer_port = ntohs(ca.sin_port);
                ctx->rt        = &rt;
                strncpy(ctx->peer_ip, inet_ntoa(ca.sin_addr), MAX_IP_LEN - 1);
                ctx->peer_ip[MAX_IP_LEN - 1] = '\0';

                pthread_t tid;
                if (pthread_create(&tid, NULL, client_thread, ctx) != 0) {
                        err("pthread_create failed.\n");
                        close(client_fd);
                        free(ctx);
                        continue;
                }
                pthread_detach(tid);
        }

        room_table_destroy(&rt);
        close(server_fd);
        return 0;
}
