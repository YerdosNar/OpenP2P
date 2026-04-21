#include "../include/fileproto.h"
#include "../include/msgtype.h"
#include "../include/logger.h"

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static void hton64_pack(uint64_t host, uint8_t out[8])
{
        uint32_t hi = htonl((uint32_t)(host >> 32));
        uint32_t lo = htonl((uint32_t)(host & 0xFFFFFFFFu));
        memcpy(out,     &hi, 4);
        memcpy(out + 4, &lo, 4);
}

static uint64_t ntoh64_unpack(const uint8_t in[8])
{
        uint32_t hi, lo;
        memcpy(&hi, in,     4);
        memcpy(&lo, in + 4, 4);
        return ((uint64_t)ntohl(hi) << 32) | (uint64_t)ntohl(lo);
}

bool fileproto_send_offer(
                int32_t         fd,
                const char      *filename,
                uint64_t        filesize,
                const Session   *s)
{
        if (filename == NULL) {
                err("fileproto_send_offer: filename is NULL.\n");
                return false;
        }

        size_t name_len = strlen(filename);
        if (name_len == 0) {
                err("fileproto_send_offer: filename is empty.\n");
                return false;
        }
        if (name_len > FILEPROTO_NAME_MAX) {
                err("fileproto_send_offer: filename too long (%zu > %u).\n",
                                name_len, FILEPROTO_NAME_MAX);
                return false;
        }

        /*
         * Build payload = [ size(8 big-endian) ][ filename bytes (no NUL) ].
         * The outer crypto layer adds the 1-byte type tag; we don't touch it
         * here. Length is encoded outside the plaintext so no inner length
         * field is needed.
         */
        uint32_t payload_len = 8u + (uint32_t)name_len;
        uint8_t *payload = malloc(payload_len);
        if (!payload) {
                err("fileproto_send_offer: malloc failed.\n");
                return false;
        }

        hton64_pack(filesize, payload);
        memcpy(payload + 8, filename, name_len);

        bool ok = crypto_send_typed(fd, FILE_OFFER,
                        payload, payload_len, s);

        free(payload);
        return ok;
}

bool fileproto_send_accept(int32_t fd, const Session *s)
{
        return crypto_send_typed(fd, FILE_ACCEPT, NULL, 0, s);
}

bool fileproto_send_reject(int32_t fd, const Session *s)
{
        return crypto_send_typed(fd, FILE_REJECT, NULL, 0, s);
}

bool fileproto_send_chunk(
                int32_t         fd,
                const uint8_t   *data,
                uint32_t        len,
                const Session   *s)
{
        if (len == 0) {
                err("fileproto_send_chunk: empty chunk not allowed.\n");
                return false;
        }
        if (len > FILEPROTO_CHUNK_MAX) {
                err("fileproto_send_chunk: chunk too large (%u > %u).\n",
                                len, FILEPROTO_CHUNK_MAX);
                return false;
        }
        return crypto_send_typed(fd, FILE_CHUNK, data, len, s);
}

bool fileproto_send_end(int32_t fd, const Session *s)
{
        return crypto_send_typed(fd, FILE_EOF, NULL, 0, s);
}

bool fileproto_parse_offer(
                const uint8_t   *payload,
                uint32_t        len,
                char            *out_filename,
                size_t          out_filename_cap,
                uint64_t        *out_filesize)
{
        if (payload == NULL || out_filename == NULL || out_filesize == NULL) {
                err("fileproto_parse_offer: NULL argument.\n");
                return false;
        }
        if (out_filename_cap < 2) {
                err("fileproto_parse_offer: out_filename_cap too small.\n");
                return false;
        }

        /*
         * Minimum legal payload: 8 bytes of size + at least 1 byte of name.
         * An offer with a 0-byte filename is malformed -- treat it as a
         * protocol error rather than silently saving to "".
         */
        if (len < 9) {
                err("fileproto_parse_offer: payload too short (%u).\n", len);
                return false;
        }

        uint32_t name_len = len - 8u;
        if (name_len > FILEPROTO_NAME_MAX) {
                err("fileproto_parse_offer: filename too long (%u > %u).\n",
                                name_len, FILEPROTO_NAME_MAX);
                return false;
        }
        if (name_len >= out_filename_cap) {
                /*
                 * Caller gave us a buffer too small to hold the name plus NUL.
                 * Refuse rather than silently truncate -- a truncated filename
                 * on disk is a nasty surprise.
                 */
                err("fileproto_parse_offer: name_len %u doesn't fit in cap %zu.\n",
                                name_len, out_filename_cap);
                return false;
        }

        *out_filesize = ntoh64_unpack(payload);
        memcpy(out_filename, payload + 8, name_len);
        out_filename[name_len] = '\0';
        return true;
}
