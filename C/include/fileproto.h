#ifndef FILEPROTO_H
#define FILEPROTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "crypto.h"

/*
 * fileproto.h / fileproto.c
 *
 * File-transfer protocol, Phase 1 (AEAD).
 *
 * Sits ON TOP of the typed crypto layer (crypto_send_typed /
 * crypto_recv_typed) and turns the abstract message types from
 * msgtype.h into concrete send/parse operations.
 *
 * Wire layouts (all INSIDE the encrypted plaintext, after the 1-byte
 * type tag added by the crypto layer):
 *
 *   FILE_OFFER : [ filesize (8, network order) ][ filename bytes ]
 *                filename is NOT NUL-terminated; its length is
 *                (payload_len - 8) as reported by crypto_recv_typed.
 *
 *   FILE_ACCEPT : (empty)
 *   FILE_REJECT : (empty)
 *   FILE_CHUNK  : [ raw file bytes ]
 *   FILE_EOF    : (empty)
 */

/*
 * Default size of each FILE_CHUNK payload, in bytes.
 *
 * Tuning guidance:
 *   - Larger chunks = fewer syscalls and less framing overhead per MB,
 *     but higher memory use (one buffer per in-flight chunk) and
 *     more head-of-line blocking on slow links.
 *   - Smaller chunks = smoother progress bar, less memory, but more
 *     syscalls and more framing overhead.
 *   - 16 KiB is a good middle ground for LAN/WAN TCP; 64 KiB is often
 *     a better fit on high-bandwidth links.
 *   - Must be <= FILEPROTO_CHUNK_MAX (the receiver's rejection limit).
 */
#define FILEPROTO_CHUNK_SIZE   (16U * 1024U)    /* 16 KiB */

/*
 * Hard upper bound on any accepted FILE_CHUNK payload, used by the
 * receiver as a sanity check. A peer that sends more than this is
 * either buggy or malicious and the transfer is aborted.
 *
 * Set to 1 MiB -- big enough to absorb future tuning of CHUNK_SIZE
 * without a protocol break, small enough to prevent pathological
 * allocations.
 */
#define FILEPROTO_CHUNK_MAX    (1U * 1024U * 1024U)    /* 1 MiB */

/* Largest filename we will accept or send (bytes, no NUL). */
#define FILEPROTO_NAME_MAX     255U

/*
 * Send a FILE_OFFER. The receiver will get a filesize and a
 * filename; no path components.
 *
 * 'filename' must be NUL-terminated on input, non-empty, and at most
 * FILEPROTO_NAME_MAX bytes (NUL excluded).
 *
 * Returns false if the arguments are invalid or the send fails.
 */
bool fileproto_send_offer(
        int32_t        fd,
        const char    *filename,
        uint64_t       filesize,
        const Session *s);

/*
 * Send a FILE_ACCEPT. No payload.
 */
bool fileproto_send_accept(int32_t fd, const Session *s);

/*
 * Send a FILE_REJECT. No payload.
 */
bool fileproto_send_reject(int32_t fd, const Session *s);

/*
 * Send one FILE_CHUNK carrying 'len' bytes of raw file data.
 *
 * 'len' must be > 0 and <= FILEPROTO_CHUNK_MAX.
 */
bool fileproto_send_chunk(
        int32_t        fd,
        const uint8_t *data,
        uint32_t       len,
        const Session *s);

/*
 * Send a FILE_EOF. No payload.
 * Marks the end of a transfer that was already accepted.
 */
bool fileproto_send_end(int32_t fd, const Session *s);

/*
 * Parse a FILE_OFFER payload (the buffer returned by
 * crypto_recv_typed, NOT the type byte).
 *
 *   payload, len        : as handed back by crypto_recv_typed
 *   out_filename        : caller-owned buffer, NUL-terminated on success
 *   out_filename_cap    : capacity of out_filename (must be >= 2)
 *   out_filesize        : parsed size (decoded from network order)
 *
 * Returns false if the payload is malformed (too short, oversized
 * filename, empty filename). Does not do any path sanitization --
 * that is a receiver-side policy decision, not a parsing concern.
 */
bool fileproto_parse_offer(
        const uint8_t   *payload,
        uint32_t        len,
        char            *out_filename,
        size_t          out_filename_cap,
        uint64_t        *out_filesize);

#endif
