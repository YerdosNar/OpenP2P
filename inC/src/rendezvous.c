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

#define DEFAULT_PORT            8888
#define DEFAULT_LOG_FILE        "con.log"

static void strip_newline(char *str)
{
        str[strcspn(str, "\r\n")] = 0;
}

static void usage(const char *exe_file)
{
        printf("Usage: %s [options]\n\n", exe_file);
        printf("Options:\n");
        printf("        -p, --port <port num>           Set port number to listen (default=%d)\n",
               DEFAULT_PORT);
        printf("        -l, --log <filename>            Set logging filename     (default='%s')\n",
               DEFAULT_LOG_FILE);
        printf("        -m, --max-rooms <number>        Set max rooms in queue   (default=%d)\n",
               MAX_ROOMS);
        printf("        -h, --help                      Show this help message\n\n");
        printf("Example:\n");
        printf("        %s -p 2222 -l server.log\n", exe_file);
        exit(0);
}

/*
 * Send a prompt to the client over an encrypted session, then receive
 * the response. The "INPUT: " prefix tells peer.c to read from stdin.
 *
 * Returns a heap-allocated, NULL-terminated string on success.
 * Returns NULL on disconnect or error. Caller must free().
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

        strip_newline(response);
        return response;
}
static void handle_host(
        int32_t         client_fd,
        const char      *peer_ip,
        uint16_t        peer_port,
        Room            rooms[],
        uint32_t        max_rooms,
        const Session   *s)
{
        // Ask for room ID - retry until a non-duplicate is given
        char *id = NULL;
        for (;;) {
                id = ask_n_receive("HostRoom ID (7 chars): ", client_fd, s);
                if (!id) return; // peer disconnected

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
                // shouldn't happen (checked before calling), but guard anyway
                send_msg(client_fd,
                         "ERROR: Server is at maximum room capacity.\n", s);
                free(id); free(pw);
                close(client_fd);
                return;
        }

        Room *room = &rooms[slot];
        strncpy(room->id,       id,     MAX_ID_LEN - 1);
        strncpy(room->password, pw,     MAX_PW_LEN - 1);
        strncpy(room->host_ip,  peer_ip,MAX_IP_LEN - 1);
        room->port              = peer_port;
        room->fd                = client_fd;
        room->session           = *s;
        room->creation_time     = time(NULL);
        room->is_active         = true;

        free(id);
        free(pw);

        printf("Host registered in slot %d room='%s' waiting for peer...\n",
               slot, room->id);

        send_msg(client_fd, "Room created. Waiting for peer to join...\n", s);
}

static void handle_joiner(
        int32_t         client_fd,
        const char      *peer_ip,
        uint16_t        peer_port,
        Room            rooms[],
        uint32_t        max_rooms,
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

        if (strncmp(pw, room->password, MAX_PW_LEN) != 0) {
                send_msg(client_fd, "ERROR: Invalid password.\n", s);
                printf("Joiner provided wrong password for room '%s'.\n",
                       room->id);
                free(pw);
                close(client_fd);
                return;
        }
        free(pw);

        printf("Credentials matched for room '%s'. Exchanging IP:Port.\n",
               room->id);

        char to_host[64], to_join[64];
        snprintf(to_host, sizeof(to_host), "%s:%d\n", peer_ip,       peer_port);
        snprintf(to_join, sizeof(to_join), "%s:%d\n", room->host_ip, room->port);

        crypto_encrypt_send(room->fd, to_host, &room->session);
        crypto_encrypt_send(client_fd, to_join, s);

        printf("Handshake complete! Tearing down rendezvous for room '%s'.\n", room->id);

        close(room->fd);
        close(client_fd);
        room->is_active = false;
}

int main(int argc, char **argv)
{
        uint16_t listen_port  = DEFAULT_PORT;
        char    *log_filename = DEFAULT_LOG_FILE;
        uint32_t max_rooms    = MAX_ROOMS;

        // cmd arg parsing
        if (argc >= 2) {
                uint8_t i;
                for (i = 1; i < argc; i++) {
                        if (!strncmp(argv[i], "-p", 2) || !strncmp(argv[i], "--port", 6)) {
                                if (i + 1 < argc) {
                                        listen_port = atoi(argv[++i]);
                                }
                                else {
                                        fprintf(stderr, "ERROR: Missing port number after '%s' flag\n", argv[i]);
                                        return 1;
                                }
                        }
                        else if (!strncmp(argv[i], "-l", 2) || !strncmp(argv[i], "--log", 5)) {
                                if (i + 1 < argc) log_filename = argv[++i];
                                else printf("No filename provided. Default: 'con.log'\n");
                        }
                        else if (!strncmp(argv[i], "-m", 2) || !strncmp(argv[i], "--max-rooms", 11)) {
                                if (i + 1 < argc) max_rooms = atoi(argv[++i]);
                                else printf("No number provided. Default: 5000\n");
                        }
                        else if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
                                usage(argv[0]);
                        }
                }
        }
        printf("INFO: Port: %d, Logfile: %s, Max rooms: %u\n",
               listen_port, log_filename, max_rooms);

        // Setup server socket
        int32_t server_fd;
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                fprintf(stderr, "ERROR: Socket creation failed\n");
                return 1;
        }

        // We should allow port reuse So we don't get "Address already in use" error
        int32_t opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
                fprintf(stderr, "ERROR: setsockopt() failed\n");
                return 1;
        }

        // Configure the server address tructure
        struct sockaddr_in server_addr;
        server_addr.sin_family          = AF_INET;
        server_addr.sin_addr.s_addr     = INADDR_ANY;
        server_addr.sin_port            = htons(listen_port);

        // Bind the socket to the port
        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
                fprintf(stderr, "ERROR: bind() failed\n");
                return 1;
        }

        // let's listen
        if (listen(server_fd, 5) == -1) {
                fprintf(stderr, "ERROR: listen() failed\n");
                return 1;
        }

        printf("Server listening on port %d...\n", listen_port);

        Room *rooms = calloc(max_rooms, sizeof(Room));
        if (!rooms) {
                fprintf(stderr, "ERROR: Failed to calloc() room table (%u rooms)\n", max_rooms);
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
                        continue; // We will not crash, we just skip
                }

                // Extract peer's IP:Port
                char *peer_ip           = inet_ntoa(ca.sin_addr);
                uint16_t peer_port      = ntohs(ca.sin_port);
                printf("\n--- New connection from %s:%d ---\n",
                       peer_ip, peer_port);

                // expire stale rooms on every new connection
                room_expire_stale(rooms, max_rooms);

                Session s = {0};
                if (!crypto_do_key_exchange(client_fd, &s)) {
                        fprintf(stderr, "WARNING: Key exchange failed with %s:%d."
                                " Dropping.\n", peer_ip, peer_port);
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
