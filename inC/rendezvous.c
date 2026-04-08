#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// buffer lengths
#define MAX_ID_LEN              8
#define MAX_PW_LEN              8
#define MAX_IP_LEN              16
#define MAX_ROOMS               5000

// room expires after 3 minutes of waiting
#define ROOM_TTL_SECONDS        180

// default vals
#define DEFAULT_PORT            8888
#define DEFAULT_LOG_FILE        "con.log"

typedef struct {
        char            host_ip[MAX_IP_LEN];
        char            room_password[MAX_PW_LEN];
        char            room_id[MAX_ID_LEN];
        time_t          creation_time;
        int32_t         host_fd;
        uint16_t        host_port;
        bool            is_active;
} Room;

void strip_newline(char *str) {
        str[strcspn(str, "\r\n")] = 0;
}

void usage(const char *exe_file) {
        printf("Usage: %s [options]\n\n", exe_file);
        printf("Options:\n");
        printf("        -p, --port <port num>           Set port number to listen (default=8888)\n");
        printf("        -l, --log <filename>            Set logging filename     (default='con.log')\n");
        printf("        -m, --max-rooms <number>        Set max rooms in queue   (default=5000)\n");
        printf("        -h, --help                      Show this help message\n\n");
        printf("Example:\n");
        printf("        %s -p 2222 -l server.log\n", exe_file);
        exit(1);
}

// Ask and receive info from peer.
// Returns heap-allocated string on success, NULL on disconnect.
// Caller must free() the returned pointer.
char *ask_n_receive(const char *prompt, int32_t client_fd) {
        char *buffer = calloc(0xff, sizeof(char));
        if (!buffer) return NULL;

        // "INPUT: " prefix tells peer.c to read stdin
        char send_prompt[strlen(prompt) + 9];
        snprintf(send_prompt, sizeof(send_prompt), "INPUT: %s ", prompt);

        send(client_fd, send_prompt, strlen(send_prompt), 0);

        int32_t bytes_received = recv(client_fd, buffer, 0xff - 1, 0);
        if (bytes_received <= 0) {
                fprintf(stderr, "ERROR: Disconnected during '%s' input.\n", prompt);
                free(buffer);
                return NULL;
        }

        strip_newline(buffer);
        return buffer;
}

// Returns the first free (inactive) slot index, or -1 if full.
int32_t find_free_slot(Room rooms[], uint32_t max_rooms) {
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) return (int32_t)i;
        }
        return -1;
}

// Returns pointer to an active room matching id, or NULL if not found.
Room *find_room_by_id(Room rooms[], uint32_t max_rooms, const char *id) {
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) continue;
                // stored id length used to guard against prefix matches
                if (!strncmp(rooms[i].room_id, id, MAX_ID_LEN)) return &rooms[i];
        }
        return NULL;
}

// Returns true if id is already taken by an active room.
bool room_id_exists(Room rooms[], uint32_t max_rooms, const char *id) {
        return find_room_by_id(rooms, max_rooms, id) != NULL;
}

// Scans all slots and expires any room older than ROOM_TTL_SECONDS.
// Closes the waiting host's fd so they get a clean disconnect.
void expire_stale_rooms(Room rooms[], uint32_t max_rooms) {
        time_t now = time(NULL);
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) continue; // No need to touch inactive rooms
                if (difftime(now, rooms[i].creation_time) > ROOM_TTL_SECONDS) {
                        printf("NOTICE: Room '%s' expired (>%ds). Closing host fd.\n",
                               rooms[i].room_id, ROOM_TTL_SECONDS);
                        const char *msg = "ERROR: Room expired. No peer joined in time.\n";
                        send(rooms[i].host_fd, msg, strlen(msg), 0);
                        close(rooms[i].host_fd);
                        rooms[i].is_active = false;
                }
        }
}

void print_room_stats(Room rooms[], uint32_t max_rooms) {
        uint32_t active = 0;
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (rooms[i].is_active) active++;
        }
        printf("INFO: Active rooms: %u / %u\n", active, max_rooms);
}

void handle_host(
        int32_t         client_fd,
        const char      *peer_ip,
        uint16_t        peer_port,
        Room            rooms[],
        uint32_t        max_rooms
) {
        // Ask for room ID - retry until a non-duplicate is given
        char *id = NULL;
        for (;;) {
                id = ask_n_receive("HostRoom ID (7 chars): ", client_fd);
                if (!id) return; // peer disconnected

                if (strlen(id) == 0) {
                        const char *msg = "INPUT: ID cannot be empty. Try again: ";
                        send(client_fd, msg, strlen(msg), 0);
                        free(id);
                        continue;
                }

                if (room_id_exists(rooms, max_rooms, id)) {
                        const char *msg = "INPUT: That ID is already in use. Choose another: ";
                        send(client_fd, msg, strlen(msg), 0);
                        free(id);
                        continue;
                }

                break; // Unique non-empty ID found
        }

        char *pw = ask_n_receive("HostRoom password (7 chars): ", client_fd);
        if (!pw) {
                free(id);
                return;
        }

        int32_t slot = find_free_slot(rooms, max_rooms);
        if (slot == -1) {
                // shouldn't happen (checked before calling), but guard anyway
                const char *msg = "ERROR: Server is at maximum room capacity.\n";
                send(client_fd, msg, strlen(msg), 0);
                free(id);
                free(pw);
                close(client_fd);
                return;
        }

        Room *room = &rooms[slot];
        strncpy(room->room_id,          id,     MAX_ID_LEN - 1);
        strncpy(room->room_password,    pw,     MAX_PW_LEN - 1);
        strncpy(room->host_ip,          peer_ip,MAX_IP_LEN - 1);
        room->host_port         = peer_port;
        room->host_fd           = client_fd;
        room->creation_time     = time(NULL);
        room->is_active         = true;

        free(id);
        free(pw);

        printf("Host registered in slot %d. Room ID: '%s'. Waiting for peer...\n",
               slot, room->room_id);

        const char *ok_msg = "Room created. Waiting for peer to join...\n";
        send(client_fd, ok_msg, strlen(ok_msg), 0);
}

void handle_joiner(
        int32_t         client_fd,
        const char      *peer_ip,
        uint16_t        peer_port,
        Room            rooms[],
        uint32_t        max_rooms
) {
        // ask for ID to verify
        char *id = ask_n_receive("HostRoom ID (case sensitive): ", client_fd);
        if (!id) return;

        Room *room = find_room_by_id(rooms, max_rooms, id);
        free(id);

        if (!room) {
                const char *msg = "ERROR: Room ID not found.\n";
                send(client_fd, msg, strlen(msg), 0);
                printf("Joiner requested non-existent room.\n");
                close(client_fd);
                return;
        }

        // Ask for password
        char *pw = ask_n_receive("HostRoom password (case sensitive): ", client_fd);
        if (!pw) {
                close(client_fd);
                return;
        }

        if (strncmp(pw, room->room_password, MAX_PW_LEN)) {
                const char *msg = "ERROR: Invalid password.\n";
                send(client_fd, msg, strlen(msg), 0);
                printf("Joiner provided wrong password for room '%s'.\n", room->room_id);
                free(pw);
                close(client_fd);
                return;
        }
        free(pw);

        printf("Credentials matched! Exchanging IP:Port for room '%s'.\n", room->room_id);

        char msg_to_host[0xff];
        char msg_to_join[0xff];
        snprintf(msg_to_host, sizeof(msg_to_host), "%s:%d\n", peer_ip, peer_port);
        snprintf(msg_to_join, sizeof(msg_to_join), "%s:%d\n", room->host_ip, room->host_port);

        send(room->host_fd, msg_to_host, strlen(msg_to_host), 0);
        send(client_fd,     msg_to_join, strlen(msg_to_join), 0);

        printf("Handshake complete! Tearing down rendezvous for room '%s'.\n", room->room_id);

        close(room->host_fd);
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
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);

                int32_t client_fd = accept(
                        server_fd,
                        (struct sockaddr *)&client_addr,
                        &client_len);
                if (client_fd == -1) {
                        fprintf(stderr, "WARNING: accept() failed, skipping.\n");
                        continue; // We will not crash, we just skip
                }

                // Extract peer's IP:Port
                char *peer_ip           = inet_ntoa(client_addr.sin_addr);
                uint16_t peer_port      = ntohs(client_addr.sin_port);
                printf("\n--- New Connection from %s:%d ---\n", peer_ip, peer_port);

                // expire stale rooms on every new connection
                expire_stale_rooms(rooms, max_rooms);

                char *choice = ask_n_receive("Are you [H]ost or [J]oin? [h/j]: ", client_fd);
                if (!choice) {
                        fprintf(stderr, "WARNING: Peer disconnected before answering, skipping...\n");
                        continue;
                }

                if (!strncmp(choice, "H", 1) || !strncmp(choice, "h", 1)) {
                        if (find_free_slot(rooms, max_rooms) == -1) {
                                const char *msg = "ERROR: Server is at maximum room capacity.\n";
                                send(client_fd, msg, strlen(msg), 0);
                                close(client_fd);
                        }
                        else {
                                handle_host(client_fd, peer_ip, peer_port, rooms, max_rooms);
                        }
                }
                else if (!strncmp(choice, "J", 1) || !strncmp(choice, "j", 1)) {
                        handle_joiner(client_fd, peer_ip, peer_port, rooms, max_rooms);
                }
                else {
                        const char *msg = "ERROR: Invalid selection.\n";
                        send(client_fd, msg, strlen(msg), 0);
                        close(client_fd);
                }

                free(choice);
                print_room_stats(rooms, max_rooms);
        }

        free(rooms);
        close(server_fd);
        return 0;
}
