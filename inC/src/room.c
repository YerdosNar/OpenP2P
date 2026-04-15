#include "../include/room.h"
#include "../include/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── helpers (must be called with rt->lock held) ─────────────────────────── */

static int32_t find_free_slot_unlocked(Room rooms[], uint32_t max_rooms)
{
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) return (int32_t)i;
        }
        return -1;
}

static Room *find_by_id_unlocked(Room rooms[], uint32_t max_rooms, const char *id)
{
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) continue;
                /* MAX_ID_LEN guards against prefix matches */
                if (strncmp(rooms[i].room_id, id, MAX_ID_LEN) == 0)
                        return &rooms[i];
        }
        return NULL;
}

/* ── init / destroy ──────────────────────────────────────────────────────── */

bool room_table_init(RoomTable *rt, uint32_t max_rooms)
{
        rt->rooms = calloc(max_rooms, sizeof(Room));
        if (!rt->rooms) return false;

        rt->max_rooms = max_rooms;

        if (pthread_mutex_init(&rt->lock, NULL) != 0) {
                free(rt->rooms);
                rt->rooms = NULL;
                return false;
        }
        return true;
}

void room_table_destroy(RoomTable *rt)
{
        if (rt->rooms) {
                free(rt->rooms);
                rt->rooms = NULL;
        }
        pthread_mutex_destroy(&rt->lock);
}

/* ── id_exists ───────────────────────────────────────────────────────────── */

bool room_id_exists(RoomTable *rt, const char *id)
{
        pthread_mutex_lock(&rt->lock);
        bool exists = (find_by_id_unlocked(rt->rooms, rt->max_rooms, id) != NULL);
        pthread_mutex_unlock(&rt->lock);
        return exists;
}

/* ── try_register ────────────────────────────────────────────────────────── */

int32_t room_try_register(
        RoomTable      *rt,
        const char     *id,
        const char     *password,
        const char     *host_ip,
        uint16_t        host_port,
        int32_t         host_fd,
        const Session  *host_session,
        const uint8_t   host_pub_key[crypto_kx_PUBLICKEYBYTES],
        const char    **err_msg)
{
        pthread_mutex_lock(&rt->lock);

        /* check uniqueness */
        if (find_by_id_unlocked(rt->rooms, rt->max_rooms, id)) {
                pthread_mutex_unlock(&rt->lock);
                *err_msg = "ERROR: That ID is already in use.\n";
                return -1;
        }

        /* find a slot */
        int32_t slot = find_free_slot_unlocked(rt->rooms, rt->max_rooms);
        if (slot == -1) {
                pthread_mutex_unlock(&rt->lock);
                *err_msg = "ERROR: Server is at maximum room capacity.\n";
                return -1;
        }

        Room *room = &rt->rooms[slot];

        /*
         * Zero the slot first so no stale data from a previous occupant
         * can leak (especially important for strncpy'd fields).
         */
        memset(room, 0, sizeof(*room));

        strncpy(room->room_id,       id,       MAX_ID_LEN - 1);
        room->room_id[MAX_ID_LEN - 1] = '\0';

        strncpy(room->room_password, password, MAX_PW_LEN - 1);
        room->room_password[MAX_PW_LEN - 1] = '\0';

        strncpy(room->host_ip,       host_ip,  MAX_IP_LEN - 1);
        room->host_ip[MAX_IP_LEN - 1] = '\0';

        memcpy(room->host_pub_key, host_pub_key, crypto_kx_PUBLICKEYBYTES);
        room->host_port         = host_port;
        room->host_fd           = host_fd;
        room->host_session      = *host_session;
        room->creation_time     = time(NULL);
        room->is_active         = true;

        pthread_mutex_unlock(&rt->lock);
        return slot;
}

/* ── claim_for_joiner ────────────────────────────────────────────────────── */

bool room_claim_for_joiner(
        RoomTable       *rt,
        const char      *id,
        const char      *password,
        char            *out_host_ip,
        uint16_t        *out_host_port,
        int32_t         *out_host_fd,
        Session         *out_host_session,
        uint8_t          out_host_pub_key[crypto_kx_PUBLICKEYBYTES],
        const char     **err_msg)
{
        pthread_mutex_lock(&rt->lock);

        Room *room = find_by_id_unlocked(rt->rooms, rt->max_rooms, id);
        if (!room) {
                pthread_mutex_unlock(&rt->lock);
                *err_msg = "ERROR: Invalid ID/Password.\n";
                return false;
        }

        if (strncmp(password, room->room_password, MAX_PW_LEN) != 0) {
                pthread_mutex_unlock(&rt->lock);
                *err_msg = "ERROR: Invalid ID/Password.\n";
                return false;
        }

        /* copy everything the joiner needs */
        strncpy(out_host_ip, room->host_ip, MAX_IP_LEN - 1);
        out_host_ip[MAX_IP_LEN - 1] = '\0';
        *out_host_port    = room->host_port;
        *out_host_fd      = room->host_fd;
        *out_host_session = room->host_session;
        memcpy(out_host_pub_key, room->host_pub_key, crypto_kx_PUBLICKEYBYTES);

        /* Zero sensitive material before deactivating */
        sodium_memzero(&room->host_session, sizeof(room->host_session));
        room->is_active = false;

        pthread_mutex_unlock(&rt->lock);
        return true;
}

/* ── expire_stale ────────────────────────────────────────────────────────── */

void room_expire_stale(RoomTable *rt)
{
        /*
         * Dynamically-sized collection so we aren't limited to 64
         * stale rooms per sweep when max_rooms can be 5000+.
         */
        uint32_t  cap       = 64;
        uint32_t  n_stale   = 0;
        int32_t  *stale_fds = malloc(cap * sizeof(*stale_fds));
        if (!stale_fds) return;

        pthread_mutex_lock(&rt->lock);
        time_t now = time(NULL);

        for (uint32_t i = 0; i < rt->max_rooms; i++) {
                if (!rt->rooms[i].is_active) continue;
                if (difftime(now, rt->rooms[i].creation_time) > ROOM_TTL_SECONDS) {
                        printf("NOTICE: Room '%s' expired (>%ds).\n",
                               rt->rooms[i].room_id, ROOM_TTL_SECONDS);
                        const char *msg =
                                "ERROR: Room expired. No peer joined in time.\n";
                        send(rt->rooms[i].host_fd, msg, strlen(msg), MSG_NOSIGNAL);

                        /* grow if needed */
                        if (n_stale == cap) {
                                cap *= 2;
                                int32_t *tmp = realloc(stale_fds,
                                                       cap * sizeof(*stale_fds));
                                if (!tmp) break;   /* best-effort */
                                stale_fds = tmp;
                        }
                        stale_fds[n_stale++] = rt->rooms[i].host_fd;

                        sodium_memzero(&rt->rooms[i].host_session,
                                       sizeof(rt->rooms[i].host_session));
                        rt->rooms[i].is_active = false;
                }
        }
        pthread_mutex_unlock(&rt->lock);

        for (uint32_t i = 0; i < n_stale; i++) {
                close(stale_fds[i]);
        }
        free(stale_fds);
}

/* ── print_stats ─────────────────────────────────────────────────────────── */

void room_print_stats(RoomTable *rt)
{
        pthread_mutex_lock(&rt->lock);
        uint32_t active = 0;
        for (uint32_t i = 0; i < rt->max_rooms; i++) {
                if (rt->rooms[i].is_active) active++;
        }
        info("Active rooms: %u / %u\n", active, rt->max_rooms);
        pthread_mutex_unlock(&rt->lock);
}
