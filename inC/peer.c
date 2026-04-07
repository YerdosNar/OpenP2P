#include <asm-generic/socket.h>
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

#define DEFAULT_SERVER_PORT     8888
#define DEFAULT_LOCAL_PORT      50000

// buffer lengths
#define MAX_ID_LEN              64
#define MAX_PW_LEN              64
#define MAX_IP_LEN              16

void resolve_dom_name(const char *domain_name, char *server_ip) {
        struct hostent *ghbn = gethostbyname(domain_name);
        if (ghbn) {
                char *ip = inet_ntoa(*(struct in_addr *)ghbn->h_addr_list[0]);
                strncpy(server_ip, ip, strlen(ip));
        }
}

int main(int argc, char **argv) {
        char server_ip[MAX_IP_LEN] = "127.0.0.1";
        uint16_t server_port = DEFAULT_SERVER_PORT;
        uint16_t local_port = DEFAULT_LOCAL_PORT;

        if (argc >= 2) {
                for (int i = 0; i < argc; i++) {
                        if (!strncmp(argv[i], "-s", 2)
                                || !strncmp(argv[i], "--server-port", 13)
                        ) {
                                if (i + 1 < argc) {
                                        server_port = atoi(argv[++i]);
                                }
                        }
                        else if(!strncmp(argv[i], "-i", 2)
                                || !strncmp(argv[i], "--ip", 4)
                        ) {
                                if (i + 1 < argc) {
                                        strncpy(server_ip, argv[++i], strlen(argv[i]));
                                }
                        }
                        else if(!strncmp(argv[i], "-l", 2)
                                || !strncmp(argv[i], "--local-port", 12)
                        ) {
                                if (i + 1 < argc) {
                                        local_port = atoi(argv[++i]);
                                }
                        }
                        else if(!strncmp(argv[i], "-d", 2)
                                || !strncmp(argv[i], "--domain-name", 13)
                        ) {
                                if (i + 1 < argc) {
                                        resolve_dom_name(argv[++i], server_ip);
                                }
                        }
                }
        }

        printf("INFO: Rendezvous server %s:%d | Local Port %d\n", server_ip, server_port, local_port);

        // socket create
        int32_t sock_fd;
        if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                fprintf(stderr, "ERROR: Socket creation failed.\n");
                return 1;
        }

        // set socket option for TCP hole punch
        int32_t opt = 1;
        if (setsockopt(
                sock_fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                &opt,
                sizeof(opt)) < 0
        ) {
                fprintf(stderr, "ERROR: setsockopt(SO_REUSEADDR) failed\n");
                return 1;
        }
        if (setsockopt(
                sock_fd,
                SOL_SOCKET,
                SO_REUSEPORT,
                &opt,
                sizeof(opt)) < 0
        ) {
                fprintf(stderr, "ERROR: setsockopt(SO_REUSEPORT) failed\n");
                return 1;
        }

        // bind to specific local Port
        struct sockaddr_in local_addr = {0};
        local_addr.sin_family           = AF_INET;
        local_addr.sin_addr.s_addr      = htonl(INADDR_ANY);
        local_addr.sin_port             = htons(local_port);

        if (bind(
                sock_fd,
                (struct sockaddr*)&local_addr,
                sizeof(local_addr)) < 0
        ) {
                fprintf(stderr, "ERROR: bind() failed.\n");
                return 1;
        }

        // Connect to Rendezvous
        struct sockaddr_in server_addr = {0};
        server_addr.sin_family          = AF_INET;
        server_addr.sin_addr.s_addr     = inet_addr(server_ip);
        server_addr.sin_port            = htons(server_port);

        printf("Connecting to Rendezvous server...\n");
        if (connect(
                sock_fd,
                (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0
        ) {
                fprintf(stderr, "ERROR: Connection to Rendezvous Server failed\n");
                return 1;
        }

        printf("Connected successfully!\n");

        char target_ip[MAX_IP_LEN] = {0};
        uint16_t target_port = 0;

        // handle communication
        char buffer[1024];
        for (;;) {
                memset(buffer, 0, sizeof(buffer));
                int32_t bytes_received;
                if ((bytes_received = recv(
                        sock_fd,
                        buffer,
                        sizeof(buffer) - 1,
                        0)) <= 0
                ) {
                        printf("\nConnection to Rendezvous Server closed.\n");
                        break;
                }

                // print server message
                printf("%s", buffer);
                fflush(stdout); // It should print before input

                // server ERROR
                if (strstr(buffer, "ERROR")) {
                        close(sock_fd);
                        return 1;
                }

                // if it asking for input
                if (strstr(buffer, "Enter HostRoom")) {
                        char input[0xff];
                        // get input
                        if (fgets(input, sizeof(input), stdin) != NULL) {
                                send(sock_fd, input, strlen(input), 0);
                        }
                }

                // if server sent Peer IP:Port
                // FORMAT ("IP:Port\n")
                else if (sscanf(buffer, "%15[^:]:%hu", target_ip, &target_port) == 2) {
                        printf("\n>>> Target Peer Acquired: %s:%d <<<\n", target_ip, target_port);
                        break;
                }
        }
        // Disconnect from Rendezvous
        close(sock_fd);

        // Let's wait until Rendezvous connection is closed
        int32_t p2p_fd;
        bool connected = false;
        struct sockaddr_in peer_addr = {0};
        peer_addr.sin_family            = AF_INET;
        peer_addr.sin_addr.s_addr       = inet_addr(target_ip);
        peer_addr.sin_port              = htons(target_port);

        printf("Initiating TCP Hole Punch to %s:%d...\n", target_ip, target_port);

        // let's try 15 times
        for (int i = 0; i < 15; i++) {
                p2p_fd = socket(AF_INET, SOCK_STREAM, 0);

                setsockopt(p2p_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
                setsockopt(p2p_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

                if (bind(
                        p2p_fd,
                        (struct sockaddr*)&local_addr,
                        sizeof(local_addr)) < 0
                ) {
                        fprintf(stderr, "ERROR: P2P Bind failed.\n");
                        close(p2p_fd);
                        return 1;
                }

                if (connect(
                        p2p_fd,
                        (struct sockaddr*)&peer_addr,
                        sizeof(peer_addr)) == 0
                ) {
                        connected = true;
                        break;
                }

                close(p2p_fd);
                printf("Punch attempt %d failed. Retrying in ...\n", i+1);
        }

        if (!connected) {
                printf("\nERROR: TCP Hole Punch failed after 15 attempts. The NATs might be too strict.\n");
                return 1;
        }

        printf("\n=== === === === === === === === ===\n");
        printf("SUCCESS! P2P CONNECTION ESTABLISHED!");
        printf("\n=== === === === === === === === ===\n");

        char test_msg[64];
        printf("Please enter your name: ");
        fgets(test_msg, sizeof(test_msg)-1, stdin);
        test_msg[strcspn(test_msg, "\r\n")] = 0;
        send(p2p_fd, test_msg, strlen(test_msg), 0);

        char p2p_buffer[0xff] = {0};
        recv(p2p_fd, p2p_buffer, sizeof(p2p_buffer) - 1, 0);
        printf("Message from peer: %s\n", p2p_buffer);

        close(p2p_fd);
        return 0;
}
