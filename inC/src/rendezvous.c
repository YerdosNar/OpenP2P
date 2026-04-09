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
#include "../include/room.h"

/* ── defaults ────────────────────────────────────────────────────────────── */

#define DEFAULT_PORT        8888
#define DEFAULT_LOG_FILE    "con.log"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static void strip_newline(char *str)
{
        str[strcspn(str, "\r\n")] = 0;
}

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
 * Send a prompt to the client over an encrypted session, then receive
 * the response.  The "INPUT: " prefix tells peer.c to read from stdin.
 *
 * Returns a heap-allocated, NUL-terminated string on success.
 * Returns NULL on disconnect or error.  Caller must free().
 */
static char *ask_n_receive(const char *prompt, int32_t fd, const Session *s)
{
        /* build "INPUT: <prompt>" */
        size_t send_len = strlen(prompt) + 9;   /* "INPUT: " + space + NUL */
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

        strip_newline(response);
        return response;
}

/*
 * Send a plain status/error message to the client over the encrypted channel.
 */
static bool send_msg(int32_t fd, const char *msg, const Session *s)
{
        return crypto_encrypt_send(fd, msg, s);
}

/* ── handle_host ─────────────────────────────────────────────────────────── */

static void handle_host(
        int32_t          client_fd,
        const char      *peer_ip,
        uint16_t         peer_port,
        Room             rooms[],
        uint32_t         max_rooms,
        const Session   *s)
{
        /* Ask for a unique, non-empty room ID */
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
                                 "INPUT: That ID is already in use. Choose another: ", s);
                        free(id);
                        continue;
                }

                break;
        }

        char *pw = ask_n_receive("HostRoom password (7 chars): ", client_fd, s);
        if (!pw) { free(id); return; }

        int32_t slot = room_find_free_slot(rooms, max_rooms);
        if (slot == -1) {
                /* shouldn't happen — checked before calling — but guard anyway */
                send_msg(client_fd,
                         "ERROR: Server is at maximum room capacity.\n", s);
                free(id); free(pw);
                close(client_fd);
                return;
        }

        Room *room = &rooms[slot];
        strncpy(room->room_id,       id,      MAX_ID_LEN - 1);
        strncpy(room->room_password, pw,      MAX_PW_LEN - 1);
        strncpy(room->host_ip,       peer_ip, MAX_IP_LEN - 1);
        room->host_port      = peer_port;
        room->host_fd        = client_fd;
        room->host_session   = *s;           /* save E2EE keys for later */
        room->creation_time  = time(NULL);
        room->is_active      = true;

        free(id);
        free(pw);

        printf("Host registered in slot %d  room='%s'  waiting for peer...\n",
               slot, room->room_id);

        send_msg(client_fd, "Room created. Waiting for peer to join...\n", s);
        /*
         * We intentionally do NOT close client_fd here.
         * The fd stays open so we can push the joiner's IP:Port
         * to the host once someone joins.
         */
}

/* ── handle_joiner ───────────────────────────────────────────────────────── */

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

        printf("Credentials matched for room '%s'. Exchanging IP:Port.\n",
               room->room_id);

        /*
         * Build IP:Port strings and send them encrypted to each side.
         * The host session key was stored when the room was created.
         */
        char to_host[64], to_join[64];
        snprintf(to_host, sizeof(to_host), "%s:%d\n", peer_ip,       peer_port);
        snprintf(to_join, sizeof(to_join), "%s:%d\n", room->host_ip, room->host_port);

        /*
         * NOTE: Both the host and the joiner have already completed their own
         * independent key exchanges (stored in room->host_session and s),
         * so we encrypt each message with the correct session.
         */
        crypto_encrypt_send(room->host_fd, to_host, &room->host_session);
        crypto_encrypt_send(client_fd,     to_join, s);

        printf("Handshake complete. Tearing down rendezvous for room '%s'.\n",
               room->room_id);

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

        /* init libsodium — must happen before any crypto call */
        if (sodium_init() < 0) {
                fprintf(stderr, "ERROR: libsodium init failed.\n");
                return 1;
        }

        /* set up listening socket */
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

                /* expire stale rooms on every new connection */
                room_expire_stale(rooms, max_rooms);

                /* ── E2EE handshake with this client ── */
                Session s = {0};
                if (!crypto_do_key_exchange(client_fd, &s)) {
                        fprintf(stderr, "WARNING: Key exchange failed with %s:%d."
                                " Dropping.\n", peer_ip, peer_port);
                        close(client_fd);
                        continue;
                }
                printf("Secure channel established with %s:%d.\n",
                       peer_ip, peer_port);

                /* now everything goes over the encrypted channel */
                char *choice = ask_n_receive(
                        "Are you [H]ost or [J]oin? [h/j]: ",
                        client_fd, &s);
                if (!choice) {
                        fprintf(stderr, "WARNING: Peer disconnected before"
                                " answering, skipping.\n");
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
