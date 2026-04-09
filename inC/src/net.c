#define _GNU_SOURCE
#include "../include/net.h"

#include <stdio.h>
#include <unistd.h>

bool net_recv_all(int32_t fd, void *buf, size_t len) {
        size_t total = 0;
        while (total < len) {
                int32_t r = recv(fd, (uint8_t *)buf + total, len - total, 0);
                if (r <= 0) return false;
                total += (size_t)r;
        }
        return true;
}

// make bound socket
int32_t net_make_bound_socket(const struct sockaddr_in *local_addr) {
        int32_t fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
                fprintf(stderr, "ERROR: socket() failed.\n");
                return -1;
        }

        int32_t opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                fprintf(stderr, "ERROR: setsockopt(SO_REUSEADDR) failed.\n");
                close(fd);
                return -1;
        }
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
                fprintf(stderr, "ERROR: setsockopt(SO_REUSEPORT) failed.\n");
                close(fd);
                return -1;
        }

        if (bind(fd, (const struct sockaddr *)local_addr, sizeof(*local_addr)) < 0) {
                fprintf(stderr, "ERROR: bind() failed.\n");
                close(fd);
                return -1;
        }

        return fd;
}
