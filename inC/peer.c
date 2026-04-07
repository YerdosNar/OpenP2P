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

bool recv_all(int32_t fd, void *buf, size_t len) {
        size_t total = 0;
        while (total < len) {
                int32_t r = recv(fd, (uint8_t*)buf + total, len - total, 0);
                if (r <= 0) return false;
                total += r;
        }
        return true;
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
        int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
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
                close(fd);
                return -1;
        }

        return fd;
}

int32_t connect_to_rendezvous(
        const Config            *cfg,
        const struct sockaddr_in *local_addr)
{
        int32_t fd = make_bound_socket(local_addr);
        if (fd == -1) return -1;

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

                // if server ERROR
                if (strstr(buffer, "ERROR")) {
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
                printf("Punch attempt %d failed. Retrying...\n", i + 1);
        }

        return -1;
}

bool do_key_exchange(
        int32_t         p2p_fd,
        uint8_t         rx_key[crypto_kx_SESSIONKEYBYTES],
        uint8_t         tx_key[crypto_kx_SESSIONKEYBYTES])
{
        uint8_t my_pub_key[crypto_kx_PUBLICKEYBYTES];
        uint8_t my_sec_key[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(my_pub_key, my_sec_key);

        printf("Generated local encryption keys. Trading public keys with peer...\n");

        // Send our public key
        if (send(p2p_fd, my_pub_key, crypto_kx_PUBLICKEYBYTES, 0) < 0)
        {
                fprintf(stderr, "ERROR: Failed to send public key.\n");
                sodium_memzero(my_sec_key, sizeof(my_sec_key));
                return false;
        }

        printf("Sent public key.\n");

        uint8_t peer_pub_key[crypto_kx_PUBLICKEYBYTES];
        if (!recv_all(p2p_fd, peer_pub_key, crypto_kx_PUBLICKEYBYTES))
        {
                fprintf(stderr, "ERROR: Disconnected during key exchange.\n");
                sodium_memzero(my_sec_key, sizeof(my_sec_key));
                return false;
        }
        printf("Received public key from peer.\n");

        // Decide vlient vs server role by comparing public keys
        int32_t cmp = memcmp(my_pub_key, peer_pub_key, crypto_kx_PUBLICKEYBYTES);
        if (cmp == 0) {
                fprintf(stderr, "ERROR: Public keys are identical (connected to self?)");
                sodium_memzero(my_sec_key, sizeof(my_sec_key));
                return false;
        }

        uint32_t ret;
        if (cmp < 0) {
                // lower key -> client role
                ret = crypto_kx_client_session_keys(
                        rx_key, tx_key,
                        my_pub_key, my_sec_key,
                        peer_pub_key);
                printf("Acting as Client for Key Derivation.\n");
        }
        else {
                // higher key -> server role
                ret = crypto_kx_server_session_keys(
                        rx_key, tx_key,
                        my_pub_key, my_sec_key,
                        peer_pub_key);
                printf("Acting as Server for Key Derivation.\n");
        }

        sodium_memzero(my_sec_key, sizeof(my_sec_key));

        if (ret != 0) {
                fprintf(stderr, "ERROR: Session keys derivation failed.\n");
                return false;
        }

        printf("SUCCESS: E2EE Session Keys generated.\n");
        return true;
}

/*
* Encrypts 'msg' first with 'tx_key' and sends over 'fd'
* Structure [nonce | net_len | ciphertext]
*
* RETURN true on success
*/
bool encrypt_and_send(
        int32_t         fd,
        const char      *msg,
        const uint8_t   tx_key[crypto_kx_SESSIONKEYBYTES])
{
        uint32_t msg_len        = strlen(msg);
        uint32_t ciphertext_len = msg_len + crypto_secretbox_MACBYTES;
     size_t   packet_size    = crypto_secretbox_NONCEBYTES   +
                                        sizeof(uint32_t)        +
                                        ciphertext_len;

        uint8_t *packet = malloc(packet_size);
        if (!packet) {
                fprintf(stderr, "ERROR: malloc() failed for send packet.\n");
                return false;
        }

        // Write none at the front
        uint8_t *nonce = packet;
        randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

        // Write length in network byte order
        uint32_t net_len = htonl(msg_len);
        memcpy(packet + crypto_secretbox_NONCEBYTES,
               &net_len, sizeof(uint32_t));

        // Encrypt into the rest of the packet
        uint8_t *ciphertext = packet + crypto_secretbox_NONCEBYTES +
                sizeof(uint32_t);
        crypto_secretbox_easy(
                ciphertext,
                (const uint8_t*)msg,
                msg_len, nonce, tx_key);

        bool ok = (send(fd, packet, packet_size, 0) >= 0);
        if (!ok) {
                fprintf(stderr, "ERROR: Failed to send encrypted message.\n");
        }
        else {
                printf("Sent encrypted message: '%s'\n", msg);
        }

        free(packet);
        return ok;
}

/*
 * receives [nonce | net_len | ciphertext]
 * decrypts with rx_key, and prints
 *
 * RETURN true on success
 */
bool recv_and_decrypt(
        int32_t         fd,
        const uint8_t   rx_key[crypto_kx_SESSIONKEYBYTES])
{
        printf("Waiting for peer's encrypted message...\n");

        // Read nonce
        uint8_t nonce[crypto_secretbox_NONCEBYTES];
        if (!recv_all(fd, nonce, sizeof(nonce))) {
                fprintf(stderr, "ERROR: Disconnected reading nonce.\n");
                return false;
        }

        // Read message length
        uint32_t net_len;
        if (!recv_all(fd, &net_len, sizeof(net_len))) {
                fprintf(stderr, "ERROR: Disconnected reading message length.\n");
                return false;
        }

        uint32_t msg_len        = ntohl(net_len);
        uint32_t ciphertext_len = msg_len + crypto_secretbox_MACBYTES;

        // Read ciphertext
        uint8_t *ciphertext = malloc(ciphertext_len);
        if (!ciphertext) {
                fprintf(stderr, "ERROR: malloc() failed for recv ciphertext.\n");
                free(ciphertext);
                return false;
        }
        if (!recv_all(fd, ciphertext, ciphertext_len)) {
                fprintf(stderr, "ERROR: Disconnected reading ciphertext.\n");
                free(ciphertext);
                return false;
        }

        // Decrypt
        uint8_t *plaintext = malloc(msg_len + 1);
        if (!plaintext) {
                fprintf(stderr, "ERROR: malloc() failed for plaintext\n");
                free(ciphertext);
                return false;
        }

        bool ok = false;
        if (crypto_secretbox_open_easy(
                plaintext,
                ciphertext,
                ciphertext_len,
                nonce,
                rx_key) != 0)
        {
                fprintf(stderr, "FATAL ERROR: Message was forged or corrupted.\n");
        }
        else {
                plaintext[msg_len] = '\0';
                printf("\n=== === === === === === === === ===\n");
                printf("SECURE MSG RX: %s", plaintext);
                printf("\n=== === === === === === === === ===\n");
                ok = true;
        }

        free(plaintext);
        free(ciphertext);
        return ok;
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
        if (rendezvous_fd == -1) return 1;

        PeerInfo peer = {0};
        bool got_peer = do_rendezvous_exchange(rendezvous_fd, &peer);
        close(rendezvous_fd);

        if (!got_peer) {
                return 1;
        }

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

        uint8_t rx_key[crypto_kx_SESSIONKEYBYTES];
        uint8_t tx_key[crypto_kx_SESSIONKEYBYTES];

        if (!do_key_exchange(p2p_fd, rx_key, tx_key))
        {
                close(p2p_fd);
                return 1;
        }

        // Share the name
        char my_name[64];
        printf("Please enter your name: ");
        fgets(my_name, sizeof(my_name)-1, stdin);
        my_name[strcspn(my_name, "\r\n")] = 0;

        if (!encrypt_and_send(p2p_fd, my_name, tx_key)) {
                close(p2p_fd);
                return 1;
        }

        if (!recv_and_decrypt(p2p_fd, rx_key)) {
                close(p2p_fd);
                return 1;
        }

        close(p2p_fd);
        return 0;
}
