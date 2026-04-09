#ifndef ROOM_H
#define ROOM_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "crypto.h"

/*
 * room.h / room.c
 *
 * Room table management for the rendezvous server.
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
        int32_t  host_fd;
        uint16_t host_port;
        bool     is_active;
} Room;

/* ── API ─────────────────────────────────────────────────────────────────── */

/* Returns the index of the first free (inactive) slot, or -1 if full. */
int32_t room_find_free_slot(Room rooms[], uint32_t max_rooms);

/* Returns a pointer to the active room with the given id, or NULL. */
Room *room_find_by_id(Room rooms[], uint32_t max_rooms, const char *id);

/* Returns true if an active room with the given id already exists. */
bool room_id_exists(Room rooms[], uint32_t max_rooms, const char *id);

/*
 * Closes and deactivates any room older than ROOM_TTL_SECONDS.
 * Sends an error message to the waiting host fd before closing it.
 */
void room_expire_stale(Room rooms[], uint32_t max_rooms);

/* Prints a one-line active/total room count. */
void room_print_stats(Room rooms[], uint32_t max_rooms);

#endif /* ROOM_H */
