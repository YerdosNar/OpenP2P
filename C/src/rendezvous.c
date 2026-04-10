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
#include "../include/room.h"

#define DEFAULT_PORT        8888
#define DEFAULT_LOG_FILE    "con.log"

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
static void handle_host(
        int32_t          client_fd,
        const char      *peer_ip,
        uint16_t         peer_port,
        Room             rooms[],
        uint32_t         max_rooms,
        const Session   *s)
{
        char *id = NULL;
        for (;;) {
                id = ask_n_receive("HostRoom ID (7 chars): ", client_fd, s);
                if (!id) return;

                if (strlen(id) == 0) {
                        send_msg(client_fd,
                                 "INPUT: ID cannot be empty. Try again: ", s);
                        free(id);
                        continue;
                }
                if (room_id_exists(rooms, max_rooms, id)) {
                        send_msg(client_fd,
                                 "INPUT: That ID is already in use. Choose another: ",
                                 s);
                        free(id);
                        continue;
                }
                break;
        }

        char *pw = ask_n_receive("HostRoom password (7 chars): ", client_fd, s);
        if (!pw) { free(id); return; }

        /* ask the host to send its P2P public key */
        send_msg(client_fd, "SEND_PUBKEY", s);

        uint8_t *pub_key = NULL;
        uint32_t pub_len = 0;
        if (!crypto_recv_decrypt_bin(client_fd, &pub_key, &pub_len, s)
            || pub_len != crypto_kx_PUBLICKEYBYTES)
        {
                fprintf(stderr, "ERROR: Bad public key from host.\n");
                free(pub_key);
                free(id);
                free(pw);
                close(client_fd);
                return;
        }

        int32_t slot = room_find_free_slot(rooms, max_rooms);
        if (slot == -1) {
                send_msg(client_fd,
                         "ERROR: Server is at maximum room capacity.\n", s);
                free(pub_key); free(id); free(pw);
                close(client_fd);
                return;
        }

        Room *room = &rooms[slot];
        strncpy(room->room_id,       id,      MAX_ID_LEN - 1);
        strncpy(room->room_password, pw,      MAX_PW_LEN - 1);
        strncpy(room->host_ip,       peer_ip, MAX_IP_LEN - 1);
        memcpy(room->host_pub_key, pub_key, crypto_kx_PUBLICKEYBYTES);
        room->host_port      = peer_port;
        room->host_fd        = client_fd;
        room->host_session   = *s;
        room->creation_time  = time(NULL);
        room->is_active      = true;

        free(pub_key);
        free(id);
        free(pw);

        printf("Host registered in slot %d  room='%s'  waiting for peer...\n",
               slot, room->room_id);

        send_msg(client_fd, "Room created. Waiting for peer to join...\n", s);
        /* fd stays open — we push joiner info when they arrive */
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
static void handle_joiner(
        int32_t          client_fd,
        const char      *peer_ip,
        uint16_t         peer_port,
        Room             rooms[],
        uint32_t         max_rooms,
        const Session   *s)
{
        char *id = ask_n_receive("HostRoom ID (case sensitive): ", client_fd, s);
        if (!id) return;

        Room *room = room_find_by_id(rooms, max_rooms, id);
        free(id);

        if (!room) {
                send_msg(client_fd, "ERROR: Room ID not found.\n", s);
                printf("Joiner requested non-existent room.\n");
                close(client_fd);
                return;
        }

        char *pw = ask_n_receive("HostRoom password (case sensitive): ", client_fd, s);
        if (!pw) { close(client_fd); return; }

        if (strncmp(pw, room->room_password, MAX_PW_LEN) != 0) {
                send_msg(client_fd, "ERROR: Invalid password.\n", s);
                printf("Joiner provided wrong password for room '%s'.\n",
                       room->room_id);
                free(pw);
                close(client_fd);
                return;
        }
        free(pw);

        /* ask the joiner to send its P2P public key */
        send_msg(client_fd, "SEND_PUBKEY", s);

        uint8_t *joiner_pub = NULL;
        uint32_t joiner_pub_len = 0;
        if (!crypto_recv_decrypt_bin(client_fd, &joiner_pub, &joiner_pub_len, s)
            || joiner_pub_len != crypto_kx_PUBLICKEYBYTES)
        {
                fprintf(stderr, "ERROR: Bad public key from joiner.\n");
                free(joiner_pub);
                close(client_fd);
                return;
        }

        printf("Credentials + keys matched for room '%s'. Distributing info.\n",
               room->room_id);

        /* build IP:Port strings */
        char to_host[64], to_join[64];
        snprintf(to_host, sizeof(to_host), "%s:%d", peer_ip,       peer_port);
        snprintf(to_join, sizeof(to_join), "%s:%d", room->host_ip, room->host_port);

        /*
         * To host:   joiner's IP:Port, then joiner's public key
         * To joiner: host's  IP:Port,  then host's  public key
         *
         * Each message is encrypted under its recipient's session keys.
         */
        crypto_encrypt_send(room->host_fd, to_host, &room->host_session);
        crypto_encrypt_send_bin(room->host_fd, joiner_pub,
                                crypto_kx_PUBLICKEYBYTES,
                                &room->host_session);

        crypto_encrypt_send(client_fd, to_join, s);
        crypto_encrypt_send_bin(client_fd, room->host_pub_key,
                                crypto_kx_PUBLICKEYBYTES, s);

        printf("Handshake complete. Tearing down rendezvous for room '%s'.\n",
               room->room_id);

        free(joiner_pub);
        close(room->host_fd);
        close(client_fd);
        room->is_active = false;
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
                        else { fprintf(stderr, "ERROR: Missing port.\n"); return 1; }
                }
                else if (!strncmp(argv[i], "-l", 2)
                         || !strncmp(argv[i], "--log", 5))
                {
                        if (i + 1 < argc) log_filename = argv[++i];
                        else printf("No filename provided. Default: '%s'\n",
                                    DEFAULT_LOG_FILE);
                }
                else if (!strncmp(argv[i], "-m", 2)
                         || !strncmp(argv[i], "--max-rooms", 11))
                {
                        if (i + 1 < argc) max_rooms = (uint32_t)atoi(argv[++i]);
                        else printf("No number provided. Default: %d\n", MAX_ROOMS);
                }
                else if (!strncmp(argv[i], "-h", 2)
                         || !strncmp(argv[i], "--help", 6))
                {
                        usage(argv[0]);
                }
        }

        printf("INFO: Port=%d  Log=%s  MaxRooms=%u\n",
               listen_port, log_filename, max_rooms);

        if (sodium_init() < 0) {
                fprintf(stderr, "ERROR: libsodium init failed.\n");
                return 1;
        }

        int32_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1) {
                fprintf(stderr, "ERROR: socket() failed.\n");
                return 1;
        }

        int32_t opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR,
                       &opt, sizeof(opt)) == -1) {
                fprintf(stderr, "ERROR: setsockopt() failed.\n");
                return 1;
        }

        struct sockaddr_in sa = {0};
        sa.sin_family          = AF_INET;
        sa.sin_addr.s_addr     = INADDR_ANY;
        sa.sin_port            = htons(listen_port);

        if (bind(server_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
                fprintf(stderr, "ERROR: bind() failed.\n");
                return 1;
        }
        if (listen(server_fd, 5) == -1) {
                fprintf(stderr, "ERROR: listen() failed.\n");
                return 1;
        }

        printf("Rendezvous server listening on port %d...\n", listen_port);

        Room *rooms = calloc(max_rooms, sizeof(Room));
        if (!rooms) {
                fprintf(stderr, "ERROR: calloc() failed for room table.\n");
                close(server_fd);
                return 1;
        }

        for (;;) {
                struct sockaddr_in ca;
                socklen_t ca_len = sizeof(ca);

                int32_t client_fd = accept(server_fd,
                                           (struct sockaddr *)&ca, &ca_len);
                if (client_fd == -1) {
                        fprintf(stderr, "WARNING: accept() failed, skipping.\n");
                        continue;
                }

                char    *peer_ip   = inet_ntoa(ca.sin_addr);
                uint16_t peer_port = ntohs(ca.sin_port);
                printf("\n--- New connection from %s:%d ---\n",
                       peer_ip, peer_port);

                room_expire_stale(rooms, max_rooms);

                Session s = {0};
                if (!crypto_do_key_exchange(client_fd, &s)) {
                        fprintf(stderr, "WARNING: Key exchange failed with"
                                " %s:%d. Dropping.\n", peer_ip, peer_port);
                        close(client_fd);
                        continue;
                }
                printf("Secure channel established with %s:%d.\n",
                       peer_ip, peer_port);

                char *choice = ask_n_receive(
                        "Are you [H]ost or [J]oin? [h/j]: ",
                        client_fd, &s);
                if (!choice) {
                        fprintf(stderr, "WARNING: Peer disconnected before"
                                " answering.\n");
                        close(client_fd);
                        continue;
                }

                if (choice[0] == 'H' || choice[0] == 'h') {
                        if (room_find_free_slot(rooms, max_rooms) == -1) {
                                send_msg(client_fd,
                                         "ERROR: Server is at maximum room"
                                         " capacity.\n", &s);
                                close(client_fd);
                        } else {
                                handle_host(client_fd, peer_ip, peer_port,
                                            rooms, max_rooms, &s);
                        }
                }
                else if (choice[0] == 'J' || choice[0] == 'j') {
                        handle_joiner(client_fd, peer_ip, peer_port,
                                      rooms, max_rooms, &s);
                }
                else {
                        send_msg(client_fd, "ERROR: Invalid selection.\n", &s);
                        close(client_fd);
                }

                free(choice);
                room_print_stats(rooms, max_rooms);
        }

        free(rooms);
        close(server_fd);
        return 0;
}
