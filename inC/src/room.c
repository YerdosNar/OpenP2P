#include "../include/room.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int32_t room_find_free_slot(Room rooms[], uint32_t max_rooms)
{
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) return (int32_t)i;
        }
        return -1;
}

Room *room_find_by_id(Room rooms[], uint32_t max_rooms, const char *id)
{
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) continue;
                if (!strncmp(rooms[i].id, id, MAX_ID_LEN)) {
                        return &rooms[i];
                }
        }
        return NULL;
}

bool room_id_exists(Room rooms[], uint32_t max_rooms, const char *id)
{
        return room_find_by_id(rooms, max_rooms, id) != NULL;
}

void room_expire_stale(Room rooms[], uint32_t max_rooms)
{
        time_t now = time(NULL);
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (!rooms[i].is_active) continue;
                if (difftime(now, rooms[i].creation_time) > ROOM_TTL_SECONDS) {
                        printf("NOTICE: Room '%s' expired (>%ds).\n",
                               rooms[i].id, ROOM_TTL_SECONDS);
                        const char *msg =
                                "ERROR: Room expired. No peer joined in time.\n";
                        send_msg(rooms[i].fd, msg, &rooms[i].session);
                        close(rooms[i].fd);
                        rooms[i].is_active = false;
                }
        }
}

void room_print_stats(Room rooms[], uint32_t max_rooms)
{
        uint32_t active = 0;
        for (uint32_t i = 0; i < max_rooms; i++) {
                if (rooms[i].is_active) active++;
        }
        printf("INFO: Active rooms: %u / %u\n", active, max_rooms);
}
