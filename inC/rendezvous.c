/*
 * OpenP2P
 *
 * take one peer1's IP:Port
 * peer1 becomes the host
 * peer1 sets a password and ID
 * ID -> to find if the host exist
 * Password -> to join the hosted room
 *
 * set a timer for 3 minutes
 * if (host_expired()) {
 *      delete_room();
 * }
 * else {
 *      wait_for_peer2();
 * }
 *
 * take peer2's IP:Port
 * ask for ID
 * if (input_id == host_id) {
 *      ask for password
 *      if (input_pw == host_pw) {
 *              sendIPs();
 *      }
 * }
 *
 * supported flag:
 *      -p, --port [num]        port to listen for peers
 *      -l, --log [filename]   to log connections (default filename: "con.log")
 *
 *
 * FURTHER IMPROVEMENTS:
 *      Add threads, there will be threads for each
 */

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
#define MAX_ID_LEN 64
#define MAX_PW_LEN 64
#define MAX_IP_LEN 16

// default vals
#define DEFAULT_PORT            8888
#define DEFAULT_LOG_FILE        "con.log"

typedef struct {
        char            host_ip[MAX_IP_LEN];
        uint16_t        host_port;
        char            room_id[MAX_ID_LEN];
        char            room_password[MAX_PW_LEN];
        time_t          creation_time;
        bool            is_active;
        int32_t         host_fd;
} Room;

void strip_newline(char *str) {
        str[strcspn(str, "\r\n")] = 0;
}

// Ask and receive info from peer
void ask_n_receive(
        Room            *room,
        const char      *prompt,
        int32_t         client_fd
) {
        char            buffer[0xff];
        uint32_t        bytes_received;

        char send_prompt[20];
        snprintf(send_prompt, sizeof(send_prompt), "Enter HostRoom %s: ", prompt);
        send(
                client_fd,
                send_prompt,
                strlen(send_prompt),
                0);
        memset(buffer, 0, sizeof(buffer));
        bytes_received = recv(
                        client_fd,
                        buffer,
                        sizeof(buffer) - 1,
                        0);

        if (bytes_received <= 0) {
                fprintf(stderr,
                        "ERROR: Disconnected during %s input.\n",
                        prompt);
                close(client_fd);
                return;
        }
        strip_newline(buffer);

        if (!strncmp(prompt, "ID", 2)) {
                strncpy(room->room_id, buffer, MAX_ID_LEN - 1);
        }
        else if (!strncmp(prompt, "PW", 2)) {
                strncpy(room->room_password, buffer, MAX_ID_LEN - 1);
        }
        else {
                fprintf(stderr, "ERROR: Unknown prompt: %s\n", prompt);
                return;
        }
}

void handle_host(
        int             client_fd,
        const char   *peer_ip,
        uint16_t        peer_port,
        Room            *room
) {
        // Ask for and receive room ID
        ask_n_receive(room, "ID", client_fd);
        // Ask and recv password;
        ask_n_receive(room, "PW", client_fd);

        strncpy(room->host_ip, peer_ip, MAX_IP_LEN - 1);
        room->host_port         = peer_port;
        room->host_fd           = client_fd;
        room->creation_time     = time(NULL);
        room->is_active         = true;

        printf("Host successfully registered. Room ID: '%s'. Waiting for Peer2...\n", room->room_id);

        const char *success_msg = "Room created successfully. Waiting for peer to join...\n";
        send(client_fd, success_msg, strlen(success_msg), 0);
}

int main(int argc, char **argv)
{
        uint16_t listen_port = DEFAULT_PORT;
        char *log_filename = DEFAULT_LOG_FILE;

        // cmd arg parsing
        if (argc >= 2) {
                char i;
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
                                if (i + 1 < argc) {
                                        log_filename = argv[++i];
                                }
                                else {
                                        printf("No filename provided. Default: 'con.log'\n");
                                }
                        }
                }
        }
        printf("INFO: Port: %d, Logfile: %s\n", listen_port, log_filename);

        Room hosted_room;
        hosted_room.is_active = false;

        // Setup server socket
        int32_t server_fd;
        struct sockaddr_in server_addr;

        // Create socket (IPv4, TCP)
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                fprintf(stderr, "ERROR: Socket creation failed\n");
                return 1;
        }

        // We should allow port reuse
        // So we don't get "Address already in use" error
        int32_t opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
                fprintf(stderr, "ERROR: setsockopt() failed\n");
                return 1;
        }

        // Configure the server address tructure
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

        printf("Server successfully started and listening on port %d...\n", listen_port);

        // loop
        for (;;) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);

                int32_t client_fd = accept(
                                server_fd,
                                (struct sockaddr *)&client_addr,
                                &client_len);
                if (client_fd == -1) {
                        fprintf(stderr, "ERROR: Warning: Accept failed\n");
                        continue; // We will not crash, we just skip this one
                }

                // Extract peer's IP:Port
                char *peer_ip           = inet_ntoa(client_addr.sin_addr);
                uint16_t peer_port      = ntohs(client_addr.sin_port);
                printf("\n--- New Connection ---\n");
                printf("Peer connected from %s:%d\n", peer_ip, peer_port);

                // Check for room expiration
                if (hosted_room.is_active) {
                        time_t current_time = time(NULL);
                        if (difftime(current_time, hosted_room.creation_time) > 180.0) {
                                printf("NOTICE: Existing room has expired (exceeded 3 minutes). Deleting room...\n");
                                hosted_room.is_active = false;
                        }
                }

                if (!hosted_room.is_active) {
                        printf("ACTION: No active room. Setting up Peer 1 as Host...\n");
                        handle_host(client_fd, peer_ip, peer_port, &hosted_room);
                }
                else {
                        printf("ACTION: Room is active. Processing Peer2 as Joiner...\n");
                        // TODO: handle_joiner();
                        close(client_fd);
                }

                close(client_fd);
        }

        close(server_fd);
        return 0;
}
