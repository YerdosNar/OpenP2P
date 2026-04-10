#ifndef ROOM_H
#define ROOM_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "crypto.h"

/*
 * room.h / room.c
 *
 * Thread-safe room table management for the rendezvous server.
 *
 * All public functions that touch the room array lock the embedded mutex
 * internally, so callers never need to manage the lock themselves.
 */

/* ── limits ─────────────────────────────────────────────────────────────── */

#define MAX_ID_LEN          8
#define MAX_PW_LEN          8
#define MAX_IP_LEN          16
#define MAX_ROOMS           5000
#define ROOM_TTL_SECONDS    180

/* ── types ──────────────────────────────────────────────────────────────── */

typedef struct {
        char     host_ip[MAX_IP_LEN];
        char     room_password[MAX_PW_LEN];
        char     room_id[MAX_ID_LEN];
        time_t   creation_time;
        Session  host_session;   /* E2EE keys for the waiting host */
	uint8_t  host_pub_key[crypto_kx_PUBLICKEYBYTES];
        int32_t  host_fd;
        uint16_t host_port;
        bool     is_active;
} Room;

/*
 * The room table: rooms array + its size + a mutex that protects it.
 * Allocated once in main(), passed by pointer to every thread.
 */
typedef struct {
        Room            *rooms;
        uint32_t         max_rooms;
        pthread_mutex_t  lock;
} RoomTable;

/* ── API ─────────────────────────────────────────────────────────────────── */

/*
 * Initialise a RoomTable.  Allocates the rooms array and inits the mutex.
 * Returns true on success.
 */
bool room_table_init(RoomTable *rt, uint32_t max_rooms);

/* Free the rooms array and destroy the mutex. */
void room_table_destroy(RoomTable *rt);

/* Returns true if an active room with the given id already exists. */
bool room_id_exists(RoomTable *rt, const char *id);

/*
 * Atomically check that 'id' is unique AND reserve a slot.
 *
 * On success: fills the slot with initial data (id, password, host info,
 *             public key, session, fd) and marks it active.
 *             Returns the slot index (>= 0).
 * On failure: returns -1 (either id already taken or table full).
 *             Sets *err_msg to a static string describing the problem.
 */
int32_t room_try_register(
        RoomTable      *rt,
        const char     *id,
        const char     *password,
        const char     *host_ip,
        uint16_t        host_port,
        int32_t         host_fd,
        const Session  *host_session,
        const uint8_t   host_pub_key[crypto_kx_PUBLICKEYBYTES],
        const char    **err_msg);

/*
 * Look up a room by id and password.  If matched, copies all the fields
 * the joiner needs into the output parameters and deactivates the room
 * (the handoff is complete).
 *
 * Returns true on success.  Sets *err_msg on failure.
 */
bool room_claim_for_joiner(
        RoomTable  *rt,
        const char *id,
        const char *password,
        /* outputs - filled on success */
        char       *out_host_ip,
        uint16_t   *out_host_port,
        int32_t    *out_host_fd,
        Session    *out_host_session,
        uint8_t     out_host_pub_key[crypto_kx_PUBLICKEYBYTES],
        const char **err_msg);

/*
 * Closes and deactivates any room older than ROOM_TTL_SECONDS.
 * Sends an error message to the waiting host fd before closing it.
 */
void room_expire_stale(RoomTable *rt);

/* Prints a one-line active/total room count. */
void room_print_stats(RoomTable *rt);

#endif /* ROOM_H */
