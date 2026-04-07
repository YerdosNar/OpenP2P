#include <netdb.h>
#include <sodium/crypto_kx.h>
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

// default values
#define DEFAULT_SERVER_PORT     8888
#define DEFAULT_LOCAL_PORT      50000
// buffer lengths
#define MAX_ID_LEN              64
#define MAX_PW_LEN              64
#define MAX_IP_LEN              16

typedef struct {
        char            server_ip[MAX_IP_LEN];
        uint16_t        server_port;
        uint16_t        local_port;
} Config;

typedef struct {
        char            ip[MAX_IP_LEN];
        uint16_t        port;
} PeerInfo;

void resolve_dom_name(const char *domain_name, char *server_ip) {
        struct hostent *ghbn = gethostbyname(domain_name);
        if (ghbn) {
                char *ip = inet_ntoa(*(struct in_addr *)ghbn->h_addr_list[0]);
                strncpy(server_ip, ip, MAX_IP_LEN - 1);
        }
}

Config parse_args(int argc, char **argv) {
        Config cfg;
        strncpy(cfg.server_ip, "127.0.0.1", MAX_IP_LEN - 1);
        cfg.server_port = DEFAULT_SERVER_PORT;
        cfg.local_port  = DEFAULT_LOCAL_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-s", 2)
                        || !strncmp(argv[i], "--server-port", 13))
                {
                        if (i + 1 < argc) {
                                cfg.server_port = atoi(argv[++i]);
                        }
                }
                else if (!strncmp(argv[i], "-i", 2)
                        || !strncmp(argv[i], "--ip", 4))
                {
                        if (i + 1 < argc) {
                                strncpy(cfg.server_ip, argv[++i], MAX_IP_LEN - 1);
                        }
                }
                else if (!strncmp(argv[i], "-l", 2)
                        || !strncmp(argv[i], "--local-port", 12))
                {
                        if (i + 1 < argc) {
                                cfg.local_port = atoi(argv[++i]);
                        }
                }
                else if (!strncmp(argv[i], "-d", 2)
                        || !strncmp(argv[i], "--domain-name", 13))
                {
                        if (i + 1 < argc) {
                                resolve_dom_name(argv[++i], cfg.server_ip);
                        }
                }
        }
        return cfg;
}

// Procedure for TCP Hole Punch
void set_sockopt(int32_t sock_fd) {
        int32_t opt = 1;
        if (setsockopt(
                sock_fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                &opt,
                sizeof(opt)) < 0
        ) {
                fprintf(stderr, "ERROR: setsockopt(SO_REUSEADDR) failed\n");
                exit(1);
        }

        if (setsockopt(
                sock_fd,
                SOL_SOCKET,
                SO_REUSEPORT,
                &opt,
                sizeof(opt)) < 0
        ) {
                fprintf(stderr, "ERROR: setsockopt(SO_REUSEPORT) failed\n");
                exit(1);
        }
}

int32_t make_bound_socket(const struct sockaddr_in *local_addr) {
        int32_t fd;
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                fprintf(stderr, "ERROR: Socket creation failed.\n");
                return -1;
        }

        set_sockopt(fd);

        if (bind(
                fd,
                (const struct sockaddr*)local_addr,
                sizeof(*local_addr)) < 0)
        {
                fprintf(stderr, "ERROR: bind() failed.\n");
                return -1;
        }

        return fd;
}

int32_t connect_to_rendezvous(
        const Config            *cfg,
        const struct sockaddr_in *local_addr)
{
        int32_t fd;
        if ((fd = make_bound_socket(local_addr)) == -1) {
                return -1;
        }

        struct sockaddr_in server_addr = {0};
        server_addr.sin_family          = AF_INET;
        server_addr.sin_addr.s_addr     = inet_addr(cfg->server_ip);
        server_addr.sin_port            = htons(cfg->server_port);

        printf("Connecting to Rendezvous Server...\n");
        if (connect(
                fd,
                (struct sockaddr*)&server_addr,
                sizeof(server_addr)) < 0)
        {
                fprintf(stderr, "ERROR: Connection to Rendezvous Server failed.\n");
                close(fd);
                return -1;
        }

        printf("Connected successfully!\n");
        return fd;
}

bool do_rendezvous_exchange(int32_t rendezvous_fd, PeerInfo *peer) {
        char buffer[1024];

        for (;;) {
                memset(buffer, 0, sizeof(buffer));
                int32_t bytes_received = recv(
                                rendezvous_fd,
                                buffer,
                                sizeof(buffer),
                                0);
                if (bytes_received <= 0) {
                        printf("\nConnection to Rendezvous Server closed.\n");
                        return false;
                }

                // print server message
                printf("%s", buffer);
                fflush(stdout); // It should print before input

                // server ERROR
                if (strstr(buffer, "ERROR")) {
                        close(rendezvous_fd);
                        return false;
                }

                // if it asking for input
                if (strstr(buffer, "Enter HostRoom")) {
                        char input[0xff];
                        // get input
                        if (fgets(input, sizeof(input), stdin) != NULL) {
                                send(rendezvous_fd, input, strlen(input), 0);
                        }
                }

                // if server sent Peer IP:Port
                // FORMAT ("IP:Port\n")
                else if (sscanf(buffer, "%15[^:]:%hu", peer->ip, &peer->port) == 2) {
                        printf("\n>>> Target Peer Acquired: %s:%d <<<\n",
                               peer->ip, peer->port);
                        return true;
                }
        }
}

int32_t do_hole_punch(
        const PeerInfo           *peer,
        const struct sockaddr_in *local_addr,
        int32_t                  max_attempts)
{
        struct sockaddr_in peer_addr = {0};
        peer_addr.sin_family            = AF_INET;
        peer_addr.sin_addr.s_addr       = inet_addr(peer->ip);
        peer_addr.sin_port              = htons(peer->port);

        printf("Initiating TCP Hole Punch to %s:%d...\n",
               peer->ip, peer->port);

        for (uint8_t i = 0; i < max_attempts; i++) {
                int32_t fd = make_bound_socket(local_addr);
                if (fd == -1) return -1;

                if (connect(
                        fd,
                        (struct sockaddr*)&peer_addr,
                        sizeof(peer_addr)) == 0)
                {
                        return fd;
                }

                close(fd);
                printf("Punch attempt %d failed. Retrying in ...\n", i + 1);
        }

        return -1;
}

int main(int argc, char **argv) {
        Config cfg = parse_args(argc, argv);
        printf("INFO: Rendezvous server %s:%d | Local Port %d\n",
               cfg.server_ip, cfg.server_port, cfg.local_port);

        // bind to specific local Port
        struct sockaddr_in local_addr = {0};
        local_addr.sin_family           = AF_INET;
        local_addr.sin_addr.s_addr      = htonl(INADDR_ANY);
        local_addr.sin_port             = htons(cfg.local_port);

        int32_t rendezvous_fd = connect_to_rendezvous(&cfg, &local_addr);
        if (rendezvous_fd == -1) {
                return 1;
        }

        PeerInfo peer = {0};
        bool get_peer = do_rendezvous_exchange(rendezvous_fd, &peer);
        close(rendezvous_fd);

        if (!get_peer) {
                return 1;
        }

        // Let's wait until Rendezvous connection is closed
        int32_t p2p_fd = do_hole_punch(&peer, &local_addr, 15);
        if (p2p_fd == -1) {
                printf("\nERROR: TCP Hole Punch failed after 15 attempts. The NATs might be too strict.\n");
                return 1;
        }

        printf("\n=== === === === === === === === ===\n");
        printf("SUCCESS! P2P CONNECTION ESTABLISHED!");
        printf("\n=== === === === === === === === ===\n");

        // Initializing E2EE with libsodium
        if (sodium_init() < 0) {
                fprintf(stderr, "ERROR: libsodium couldn't be initialized. Is it installed?\n");
                close(p2p_fd);
                return 1;
        }

        uint8_t my_pub_key[crypto_kx_PUBLICKEYBYTES];
        uint8_t my_sec_key[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(my_pub_key, my_sec_key);

        printf("Generated local encryption keys. Trading public keys with peer...\n");

        // Exchange public keys
        uint8_t peer_pub_key[crypto_kx_PUBLICKEYBYTES];

        if (send(
                p2p_fd,
                my_pub_key,
                crypto_kx_PUBLICKEYBYTES,
                0) < 0)
        {
                fprintf(stderr, "ERROR: Failed to send public key.\n");
                close(p2p_fd);
                return 1;
        }
        printf("Sent public key to %s:%d\n", target_ip, target_port);

        int32_t bytes_read = 0;
        while (bytes_read < crypto_kx_PUBLICKEYBYTES) {
                int32_t r = 0;
                if ((r = recv(
                        p2p_fd,
                        peer_pub_key + bytes_read,
                        crypto_kx_PUBLICKEYBYTES - bytes_read,
                        0)) <= 0)
                {
                        fprintf(stderr, "ERROR: Disconnected during key exchange.\n");
                        close(p2p_fd);
                        return 1;
                }
                bytes_read += r;
        }
        printf("Received public key from %s:%d\n", target_ip, target_port);

        // Deciding who is "client", who "server"
        uint8_t rx_key[crypto_kx_SECRETKEYBYTES];
        uint8_t tx_key[crypto_kx_SECRETKEYBYTES];

        int32_t cmp = memcmp(my_pub_key, peer_pub_key, crypto_kx_PUBLICKEYBYTES);
        if (cmp == 0) {
                fprintf(stderr, "ERROR: Public keys are identical (someone connected to themselves?)\n");
                close(p2p_fd);
                return 1;
        }
        else if (cmp < 0) {
                if (crypto_kx_client_session_keys(
                        rx_key,
                        tx_key,
                        my_pub_key,
                        my_sec_key,
                        peer_pub_key) != 0)
                {
                        fprintf(stderr, "ERROR: Client session key derivation failed.\n");
                        return 1;
                }
                printf("Acting as Client for Key Derivation.\n");
        }
        else {
                if (crypto_kx_server_session_keys(
                        rx_key,
                        tx_key,
                        my_pub_key,
                        my_sec_key,
                        peer_pub_key) != 0)
                {
                        fprintf(stderr, "ERROR: Server session key derivation failed.\n");
                        return 1;
                }
                printf("Acting as Server for Key Derivation.\n");
        }

        printf("SUCESS: E2EE Session Keys generated.\n");
        sodium_memzero(my_sec_key, sizeof(my_sec_key));

        char my_name[64];
        printf("Please enter your name: ");
        fgets(my_name, sizeof(my_name)-1, stdin);
        my_name[strcspn(my_name, "\r\n")] = 0;
        uint32_t msg_len = strlen(my_name);
        uint32_t cipher_text_len = msg_len + crypto_secretbox_MACBYTES;

        // Alocating space for entire packet
        size_t packet_size =
                crypto_secretbox_NONCEBYTES +
                sizeof(uint32_t)            +
                cipher_text_len;
        uint8_t *packet = malloc(packet_size);

        // generate nonce into the start
        uint8_t *nonce = packet;
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

        // convert length to network order and send
        uint32_t net_len = htonl(msg_len);
        memcpy(packet +
               crypto_secretbox_NONCEBYTES,
               &net_len, sizeof(uint32_t));

        // encrypt
        uint8_t *ciphertext = packet +
                crypto_secretbox_NONCEBYTES +
                sizeof(uint32_t);
        crypto_secretbox_easy(
                ciphertext,
                (const uint8_t*)my_name,
                msg_len,
                nonce,
                tx_key);

        // blast secure packet across p2p socket
        if (send(
                p2p_fd,
                packet,
                packet_size,
                0) < 0)
        {
                fprintf(stderr, "ERROR: Failed to send encrypted message.\n");
        }
        else {
                printf("Sent encrypted message: '%s'\n", my_name);
        }
        free(packet);

        // receive and decrypt now
        uint8_t recv_nonce[crypto_secretbox_NONCEBYTES];
        uint32_t recv_net_len;

        printf("Waiting for peer's encrypted message...\n");

        // read nonce
        recv(
                p2p_fd,
                recv_nonce,
                sizeof(recv_nonce),
                0
        );

        // read the message
        recv(
                p2p_fd,
                &recv_net_len,
                sizeof(recv_net_len),
                0
        );
        uint32_t recv_msg_len = ntohl(recv_net_len);
        uint32_t recv_ciphertext_len = recv_msg_len + crypto_secretbox_MACBYTES;

        // Read the actual text now
        uint8_t *recv_ciphertext = malloc(recv_ciphertext_len);
        int32_t c_bytes = recv(
                p2p_fd,
                recv_ciphertext,
                recv_ciphertext_len,
                0
        );

        if (c_bytes > 0) {
                // Decrypt
                uint8_t *decrypted_msg = malloc(recv_msg_len + 1);

                if (crypto_secretbox_open_easy(
                        decrypted_msg,
                        recv_ciphertext,
                        recv_ciphertext_len,
                        recv_nonce,
                        rx_key) != 0)
                {
                        fprintf(stderr, "FATAL ERROR: Message was forged or corrupted.\n");
                }
                else {
                        decrypted_msg[recv_msg_len] = '\0';
                        printf("\n=== === === === === === === === ===\n");
                        printf("SECURE MSG RX: %s", decrypted_msg);
                        printf("\n=== === === === === === === === ===\n");
                }
                free(decrypted_msg);
        }

        free(recv_ciphertext);
        close(p2p_fd);
        return 0;
}
