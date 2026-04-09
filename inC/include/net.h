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
 * socket helper shared by peer and rendezvous.
 */

/*
 * Receive exactly 'len' bytes into 'buf', looping until done.
 *
 * Returns false on disconnec or error.
 */
bool net_recv_all(int32_t fd, void *buf, size_t len);

/*
 * Create a TCP socket bound to *local_addr*
 * with SO_REUSEADDR + SO_REUSPORT.
 *
 * Returns the fd on success, or -1 on failure
 */
int32_t net_make_bound_socket(const struct sockaddr_in *local_addr);

#endif
