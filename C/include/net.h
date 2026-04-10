#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * net.h / net.c
 *
 * Low-level socket helpers shared by peer and rendezvous.
 */

/*
 * Receive exactly 'len' bytes into 'buf', looping until done.
 * Returns false on disconnect or error.
 */
bool net_recv_all(int32_t fd, void *buf, size_t len);

/*
 * Create a TCP socket bound to *local_addr with SO_REUSEADDR + SO_REUSEPORT.
 * Returns the fd on success, or -1 on failure.
 */
int32_t net_make_bound_socket(const struct sockaddr_in *local_addr);

/*
 * Replace the first '\r' or '\n' in str with '\0'.
 */
void net_strip_newline(char *str);

#endif /* NET_H */
