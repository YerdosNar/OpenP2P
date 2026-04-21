/*
 * Force 64-bit off_t even on 32-bit platforms. Must come before any
 * system headers are pulled in, otherwise stat(2)'s st_size field may
 * be a 32-bit value and silently truncate at 2 GiB.
 */
#define _FILE_OFFSET_BITS 64

#include <netdb.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <sodium.h>

#include "../include/crypto.h"
#include "../include/net.h"
#include "../include/logger.h"
#include "../include/msgtype.h"
#include "../include/fileproto.h"

#define DEFAULT_SERVER_PORT     8888
#define DEFAULT_LOCAL_PORT      50000
#define MAX_IP_LEN              16

typedef struct {
        char     server_ip[MAX_IP_LEN];
        uint16_t server_port;
        uint16_t local_port;
} Config;

typedef struct {
        char     ip[MAX_IP_LEN];
        uint16_t port;
} PeerInfo;

/*
 * State machine for the peer.
 *
 * A single peer is always simultaneously a potential sender AND a
 * potential receiver. Because we serialize transfers in Phase 1,
 * only one of these situations can be true at a time -- so a single
 * enum covers all the cases.
 *
 *   CHAT             - nothing in flight; chat flows both ways normally.
 *   AWAITING_ACCEPT  - I sent an offer; waiting for peer's y/n.
 *                      My chat input is suspended.
 *   OFFERED          - Peer sent me an offer; I owe them a y/n.
 *                      My chat input is replaced with accept/reject prompt.
 *   SENDING          - (Step 6) I'm streaming chunks to the peer.
 *   RECEIVING        - (Step 6) I'm consuming chunks from the peer.
 *
 * Transitions:
 *
 *   CHAT --/sendfile--> AWAITING_ACCEPT --accept--> SENDING  --END--> CHAT
 *                                       --reject--> CHAT
 *
 *   CHAT --peer offer--> OFFERED --y--> RECEIVING --END--> CHAT
 *                                --n--> CHAT
 *
 * The field is _Atomic because both threads read and write it.
 */
typedef enum {
        CHAT_STATE_CHAT            = 0,
        CHAT_STATE_AWAITING_ACCEPT = 1,
        CHAT_STATE_OFFERED         = 2,
        CHAT_STATE_SENDING         = 3,
        CHAT_STATE_RECEIVING       = 4,
} ChatState;

/*
 * Metadata stashed by recv_thread when a MSG_FILE_OFFER arrives,
 * and later read by send_loop when it prompts the user y/n.
 *
 * Synchronised with 'state' via release/acquire on that atomic.
 */
typedef struct {
        char     filename[FILEPROTO_NAME_MAX + 1];
        uint64_t filesize;
} PendingOffer;

/*
 * Sender-side bookkeeping: the path to reopen once the peer accepts,
 * and the size we promised them (so the chunk loop can stop precisely
 * at the size we declared in the offer).
 *
 * Populated by try_handle_sendfile_command right before it transitions
 * state to AWAITING_ACCEPT. Read by do_send_file_chunks.
 */
typedef struct {
        char     path[1024];
        char     basename[FILEPROTO_NAME_MAX + 1];
        uint64_t filesize;
} SendingState;

/*
 * Receiver-side bookkeeping for an in-progress file write.
 * Opened by the y-branch of prompt_while_offered, written by
 * handle_recv_file_chunk, closed by handle_recv_file_end.
 */
typedef struct {
        FILE    *fp;                        /* NULL when no transfer active  */
        char     final_path[1024];          /* where we're actually writing  */
        uint64_t expected_size;             /* as promised in the offer      */
        uint64_t received;                  /* running total, <= expected    */
} RecvFileState;

typedef struct {
        int32_t             fd;
        const Session      *session;
        const char         *my_name;
        const char         *peer_name;
        volatile bool       running;
        _Atomic ChatState   state;
        PendingOffer        pending;
        SendingState        sending;
        RecvFileState       recv_file;
} ChatCtx;

static void resolve_domain(const char *domain, char *out_ip)
{
        struct hostent *h = gethostbyname(domain);
        if (h) {
                char *ip = inet_ntoa(*(struct in_addr *)h->h_addr_list[0]);
                strncpy(out_ip, ip, MAX_IP_LEN - 1);
        }
}

static void usage(const char *exe)
{
        printf("Usage: %s [options]\n\n", exe);
        printf("Options:\n");
        printf("  -s, --server-port <port>    Rendezvous server port  (default=%d)\n",
               DEFAULT_SERVER_PORT);
        printf("  -i, --ip <ip>               Rendezvous server IP    (default=127.0.0.1)\n");
        printf("  -l, --local-port <port>     Local port for P2P      (default=%d)\n",
               DEFAULT_LOCAL_PORT);
        printf("  -d, --domain-name <name>    Rendezvous server domain\n");
        printf("  -h, --help                  Show this help message\n\n");
        printf("Example:\n  %s -d example.com -s 8888\n", exe);
}

static Config parse_args(int argc, char **argv)
{
        Config cfg;
        strncpy(cfg.server_ip, "127.0.0.1", MAX_IP_LEN - 1);
        cfg.server_port = DEFAULT_SERVER_PORT;
        cfg.local_port  = DEFAULT_LOCAL_PORT;

        for (int i = 1; i < argc; i++) {
                if (!strncmp(argv[i], "-s", 2)
                    || !strncmp(argv[i], "--server-port", 13))
                {
                        if (i + 1 < argc)
                                cfg.server_port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strncmp(argv[i], "-i", 2)
                         || !strncmp(argv[i], "--ip", 4))
                {
                        if (i + 1 < argc)
                                strncpy(cfg.server_ip, argv[++i], MAX_IP_LEN - 1);
                }
                else if (!strncmp(argv[i], "-l", 2)
                         || !strncmp(argv[i], "--local-port", 12))
                {
                        if (i + 1 < argc)
                                cfg.local_port = (uint16_t)atoi(argv[++i]);
                }
                else if (!strncmp(argv[i], "-d", 2)
                         || !strncmp(argv[i], "--domain-name", 13))
                {
                        if (i + 1 < argc)
                                resolve_domain(argv[++i], cfg.server_ip);
                }
                else if (!strncmp(argv[i], "-h", 2)
                         || !strncmp(argv[i], "--help", 6))
                {
                        usage(argv[0]);
                        exit(1);
                }
        }
        return cfg;
}

static int32_t connect_to_rendezvous(
        const Config            *cfg,
        const struct sockaddr_in *local_addr)
{
        int32_t fd = net_make_bound_socket(local_addr);
        if (fd == -1) return -1;

        struct sockaddr_in sa = {0};
        sa.sin_family          = AF_INET;
        sa.sin_addr.s_addr     = inet_addr(cfg->server_ip);
        sa.sin_port            = htons(cfg->server_port);

        info("Connecting...\n");

        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                err("Connection to rendezvous server failed.\n");
                close(fd);
                return -1;
        }

        success("Connected to rendezvous server "
                MGN "%s"
                NOC ":"
                CYN "%d"
                NOC "...\n",
               cfg->server_ip, cfg->server_port);
        return fd;
}

/*
 * Drive the full rendezvous conversation over the encrypted channel.
 *
 * The server sends TEXT messages (encrypted strings).  We handle three kinds:
 *   "INPUT: ..."  -> read stdin, send back encrypted
 *   "SEND_PUBKEY" -> send our P2P public key as an encrypted binary blob
 *   "ERROR ..."   -> print and return false
 *   "A.B.C.D:N"  -> peer's IP:Port; the NEXT message will be peer's public key
 *
 * On success:
 *   *peer    is filled with the peer's IP and port
 *   *peer_pub_out points to a heap-allocated buffer of crypto_kx_PUBLICKEYBYTES
 *                 (caller must free)
 */
static bool do_rendezvous_exchange(
        int32_t         rendezvous_fd,
        const Session  *s,
        const Keypair  *my_kp,
        PeerInfo       *peer,
        uint8_t       **peer_pub_out)
{
        for (;;) {
                char *msg = NULL;
                if (!crypto_recv_decrypt(rendezvous_fd, &msg, s)) {
                        err("Connection to rendezvous server closed.\n");
                        return false;
                }

                printf(BCYN "RENDEZVOUS:" NOC " %s", msg);
                fflush(stdout);

                if (strstr(msg, "ERROR")) {
                        free(msg);
                        return false;
                }

                if (strstr(msg, "INPUT: ")) {
                        char input[256];
                        if (fgets(input, sizeof(input), stdin) != NULL) {
                                if (!crypto_encrypt_send(rendezvous_fd, input, s)) {
                                        free(msg);
                                        return false;
                                }
                        }
                }
                else if (strcmp(msg, "SEND_PUBKEY") == 0) {
                        /*
                         * Server is asking for our P2P public key.
                         * Send it as a raw encrypted binary blob.
                         */
                        printf("\n");
                        info("Sending P2P public key to rendezvous...\n");
                        if (!crypto_encrypt_send_bin(rendezvous_fd,
                                         my_kp->pub,
                                         crypto_kx_PUBLICKEYBYTES, s))
                        {
                                free(msg);
                                return false;
                        }
                }
                /* peer IP:Port — next message will be their public key */
                else if (sscanf(msg, "%15[^:]:%hu", peer->ip, &peer->port) == 2) {
                        printf("\n>>> Target peer: "
                               MGN "%s"
                               NOC ":"
                               CYN "%d"
                               NOC " <<<\n",
                               peer->ip, peer->port);
                        free(msg);

                        /* receive peer's public key */
                        uint8_t *pub  = NULL;
                        uint32_t plen = 0;
                        if (!crypto_recv_decrypt_bin(rendezvous_fd, &pub, &plen, s)
                            || plen != crypto_kx_PUBLICKEYBYTES)
                        {
                                err("Bad peer public key from rendezvous.\n");
                                free(pub);
                                return false;
                        }

                        info("Received peer P2P public key from rendezvous.]\n");
                        *peer_pub_out = pub;
                        return true;
                }

                free(msg);
        }
}

/* ── TCP hole punch ───────────────────────────────────────────────────────── */

static int32_t do_hole_punch(
        const PeerInfo           *peer,
        const struct sockaddr_in *local_addr,
        int32_t                   max_attempts)
{
        struct sockaddr_in pa = {0};
        pa.sin_family           = AF_INET;
        pa.sin_addr.s_addr      = inet_addr(peer->ip);
        pa.sin_port             = htons(peer->port);

        info("Initiating TCP hole punch to "
                               MGN "%s"
                               NOC ":"
                               CYN "%d"
                               NOC "...\n",
                               peer->ip, peer->port);

        for (int i = 0; i < max_attempts; i++) {
                int32_t fd = net_make_bound_socket(local_addr);
                if (fd == -1) return -1;

                if (connect(fd, (struct sockaddr *)&pa, sizeof(pa)) == 0)
                        return fd;

                close(fd);
                warn("Punch attempt " YEL "%d" NOC " failed. Retrying in 1s...\n", i + 1);
                sleep(1);
        }

        return -1;
}

/* ── helpers for recv_thread ──────────────────────────────────────────────
 *
 * Print a full-line notice from recv_thread without stomping the
 * active send_loop prompt. Same trick the chat printer already uses:
 *   \r          move to column 0
 *   \033[2K     clear the line
 *
 * We do NOT reprint the send_loop prompt here, because after a file
 * event the prompt that send_loop wants to show depends on the new
 * state (it might be "Accept? [y/n]: " now, not "<name>: "). So we
 * just end with "\n" and let send_loop redraw on its next iteration.
 */
static void recv_print_notice(const char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
        printf("\r\033[2K");
        vprintf(fmt, ap);
        va_end(ap);
        fflush(stdout);
}

/*
 * Handle FILE_OFFER. Parses the payload, stashes the metadata
 * in ctx->pending, and transitions state CHAT -> OFFERED.
 *
 * If we're not in CHAT (e.g. we have our own offer outstanding),
 * we auto-reject and stay where we are. This prevents offer collisions.
 */
static void handle_recv_file_offer(ChatCtx *ctx,
                                   const uint8_t *payload, uint32_t len)
{
        char     name[FILEPROTO_NAME_MAX + 1];
        uint64_t size;
        if (!fileproto_parse_offer(payload, len, name, sizeof(name), &size)) {
                recv_print_notice(BRED "[x]" NOC
                                  " Malformed file offer from peer.\n");
                return;
        }

        /*
         * Guard against collisions: we only accept offers while in CHAT.
         * If we're busy (our own AWAITING_ACCEPT, or already OFFERED),
         * we auto-reject the incoming offer so the peer doesn't hang.
         */
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s != CHAT_STATE_CHAT) {
                recv_print_notice(BYEL "[!]" NOC
                                  " Auto-rejecting '%s' (busy with another transfer).\n",
                                  name);
                fileproto_send_reject(ctx->fd, ctx->session);
                return;
        }

        /*
         * Populate pending BEFORE publishing the state change. The
         * release-store on state pairs with the acquire-load in
         * send_loop, so once send_loop sees OFFERED it is guaranteed
         * to see these writes too.
         */
        strncpy(ctx->pending.filename, name, sizeof(ctx->pending.filename) - 1);
        ctx->pending.filename[sizeof(ctx->pending.filename) - 1] = '\0';
        ctx->pending.filesize = size;

        atomic_store_explicit(&ctx->state, CHAT_STATE_OFFERED,
                              memory_order_release);

        recv_print_notice(BMGN "[offer]" NOC
                          " %s wants to send '%s' (%" PRIu64 " bytes).\n",
                          ctx->peer_name, name, size);
}

/*
 * Handle FILE_ACCEPT from the peer.
 * Valid only when we were AWAITING_ACCEPT. In Step 5 this just
 * transitions back to CHAT; Step 6 will transition to SENDING and
 * trigger the chunk loop.
 */
static void handle_recv_file_accept(ChatCtx *ctx)
{
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s != CHAT_STATE_AWAITING_ACCEPT) {
                recv_print_notice(BYEL "[!]" NOC
                                  " Unexpected ACCEPT in state %d; ignoring.\n",
                                  (int)s);
                return;
        }
        /*
         * Transition to SENDING. The main thread's prompt_while_awaiting_accept
         * will notice this on its next stdin wakeup (when the user hits Enter)
         * and dispatch to do_send_file_chunks. This stdin-wakeup dependency
         * is documented; a self-pipe wakeup is Step 8 territory.
         */
        atomic_store_explicit(&ctx->state, CHAT_STATE_SENDING,
                              memory_order_release);
        recv_print_notice(BGRN "[ok]" NOC
                          " Peer accepted. Press Enter to start sending.\n");
}

static void handle_recv_file_reject(ChatCtx *ctx)
{
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s != CHAT_STATE_AWAITING_ACCEPT) {
                recv_print_notice(BYEL "[!]" NOC
                                  " Unexpected REJECT in state %d; ignoring.\n",
                                  (int)s);
                return;
        }
        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                              memory_order_release);
        recv_print_notice(BYEL "[!]" NOC " Peer rejected the offer.\n");
}

/* ── safe filename helpers (receiver side) ────────────────────────────────
 *
 * Defence-in-depth: even though the sender promised to basename() the
 * filename before sending the offer, we re-validate on receive. A
 * compromised or buggy peer must not be able to make us write
 * anywhere except the current directory.
 *
 * Returns true if name is safe (no directory components, no traversal).
 */
static bool filename_is_safe(const char *name)
{
        if (name == NULL || name[0] == '\0') return false;
        if (strcmp(name, ".")  == 0)         return false;
        if (strcmp(name, "..") == 0)         return false;
        if (strchr(name, '/'))               return false;
        if (strchr(name, '\\'))              return false;
        /* Leading dot is allowed (many legit files start with one) but a
         * bare "." / ".." we already caught above. */
        return true;
}

/*
 * Resolve a filename collision by appending " (N)" before the extension.
 * "report.pdf" -> "report (1).pdf" -> "report (2).pdf" ...
 * "notes"      -> "notes (1)"      -> "notes (2)" ...
 *
 * Writes the chosen (non-existing) path into out / out_cap. Returns
 * true on success, false if we ran out of attempts or out_cap is too
 * small.
 */
static bool resolve_output_path(const char *name,
                                char *out, size_t out_cap)
{
        /* First try: name itself. */
        if ((size_t)snprintf(out, out_cap, "./%s", name) >= out_cap)
                return false;
        if (access(out, F_OK) != 0) return true;

        /* Find the last '.' to split basename/extension (both optional). */
        const char *dot = strrchr(name, '.');
        size_t stem_len = dot ? (size_t)(dot - name) : strlen(name);
        const char *ext  = dot ? dot : "";

        for (int i = 1; i < 1000; i++) {
                int n = snprintf(out, out_cap, "./%.*s (%d)%s",
                                 (int)stem_len, name, i, ext);
                if (n < 0 || (size_t)n >= out_cap) return false;
                if (access(out, F_OK) != 0) return true;
        }
        return false;
}

/* ── sender-side chunk loop ───────────────────────────────────────────────
 *
 * Called from prompt_while_awaiting_accept AFTER state has become
 * SENDING (which recv_thread transitions to when it gets ACCEPT).
 *
 * Reads ctx->sending.path in chunks of FILEPROTO_CHUNK_SIZE, encrypts
 * each one via fileproto_send_chunk, and ends with fileproto_send_end.
 *
 * On completion (success OR failure) state goes back to CHAT.
 * Returns true if the caller should continue the send_loop, false if
 * the connection should be torn down.
 */
static bool do_send_file_chunks(ChatCtx *ctx)
{
        const char *path = ctx->sending.path;
        uint64_t    size = ctx->sending.filesize;

        FILE *fp = fopen(path, "rb");
        if (!fp) {
                err("Cannot reopen '%s' for sending.\n", path);
                atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                                      memory_order_release);
                /* Send an END anyway so the peer doesn't hang waiting. */
                fileproto_send_end(ctx->fd, ctx->session);
                return true;
        }

        info("Sending '%s' (%" PRIu64 " bytes)...\n",
             ctx->sending.basename, size);

        uint8_t  buf[FILEPROTO_CHUNK_SIZE];
        uint64_t sent = 0;
        bool     ok   = true;
        time_t   t0   = time(NULL);

        while (sent < size) {
                /*
                 * Read at most min(CHUNK_SIZE, size-sent) bytes. The
                 * size cap matters on the final chunk: if the file on
                 * disk grew or shrank between stat() and now, we stick
                 * to the size we promised in the offer. Mismatch is
                 * handled as a truncated read below.
                 */
                size_t want = FILEPROTO_CHUNK_SIZE;
                uint64_t remaining = size - sent;
                if (remaining < want) want = (size_t)remaining;

                size_t got = fread(buf, 1, want, fp);
                if (got == 0) {
                        err("Short read on '%s' at offset %" PRIu64
                            " (file shrank?).\n", path, sent);
                        ok = false;
                        break;
                }

                if (!fileproto_send_chunk(ctx->fd, buf, (uint32_t)got,
                                          ctx->session)) {
                        err("Failed to send chunk at offset %" PRIu64 ".\n", sent);
                        ok = false;
                        break;
                }

                sent += got;
        }

        fclose(fp);

        /*
         * Always send END -- on success to signal normal completion, on
         * failure so the peer doesn't hang forever waiting for more
         * chunks. (In Phase 2's secretstream, TAG_FINAL replaces this.)
         */
        fileproto_send_end(ctx->fd, ctx->session);

        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                              memory_order_release);

        if (ok) {
                time_t dt = time(NULL) - t0;
                if (dt < 1) dt = 1;
                double mbps = ((double)sent / (1024.0 * 1024.0)) / (double)dt;
                success("Sent '%s' (%" PRIu64 " bytes) in %lds (~%.1f MB/s).\n",
                        ctx->sending.basename, sent, (long)dt, mbps);
        } else {
                err("Transfer of '%s' aborted after %" PRIu64 " bytes.\n",
                    ctx->sending.basename, sent);
        }
        return true;
}

/* ── receiver-side chunk/end handlers ─────────────────────────────────────
 *
 * Called from recv_thread's dispatch on MSG_FILE_CHUNK / MSG_FILE_END.
 * handle_recv_file_chunk writes to ctx->recv_file.fp and bumps the
 * received counter, enforcing received <= expected_size.
 * handle_recv_file_end closes the file and validates totals.
 */
static void abort_recv_file(ChatCtx *ctx, const char *why)
{
        if (ctx->recv_file.fp) {
                fclose(ctx->recv_file.fp);
                ctx->recv_file.fp = NULL;
                /* Leave the partial file on disk so the user can inspect
                 * it; naming it ".part" is Step 8 territory. */
        }
        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                              memory_order_release);
        recv_print_notice(BRED "[x]" NOC " File receive aborted: %s\n", why);
}

static void handle_recv_file_chunk(ChatCtx *ctx,
                                   const uint8_t *payload, uint32_t len)
{
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s != CHAT_STATE_RECEIVING || ctx->recv_file.fp == NULL) {
                recv_print_notice(BYEL "[!]" NOC
                                  " Unexpected CHUNK in state %d; dropping.\n",
                                  (int)s);
                return;
        }
        if (len == 0 || len > FILEPROTO_CHUNK_MAX) {
                abort_recv_file(ctx, "chunk size out of range");
                return;
        }

        /* Invariant: received + len <= expected_size. Protects against
         * a misbehaving peer sending more than promised. */
        if ((uint64_t)len > ctx->recv_file.expected_size - ctx->recv_file.received) {
                abort_recv_file(ctx, "peer sent more data than declared");
                return;
        }

        size_t written = fwrite(payload, 1, len, ctx->recv_file.fp);
        if (written != (size_t)len) {
                abort_recv_file(ctx, "disk write failed");
                return;
        }
        ctx->recv_file.received += len;
}

static void handle_recv_file_end(ChatCtx *ctx)
{
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s != CHAT_STATE_RECEIVING) {
                recv_print_notice(BYEL "[!]" NOC
                                  " Unexpected END in state %d; ignoring.\n",
                                  (int)s);
                return;
        }
        if (ctx->recv_file.fp == NULL) {
                atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                                      memory_order_release);
                return;
        }

        fclose(ctx->recv_file.fp);
        ctx->recv_file.fp = NULL;

        uint64_t got  = ctx->recv_file.received;
        uint64_t want = ctx->recv_file.expected_size;

        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                              memory_order_release);

        if (got == want) {
                recv_print_notice(BGRN "[ok]" NOC
                                  " Received '%s' (%" PRIu64 " bytes).\n",
                                  ctx->recv_file.final_path, got);
        } else {
                recv_print_notice(BRED "[x]" NOC
                                  " Truncated receive of '%s': %" PRIu64
                                  " / %" PRIu64 " bytes on disk.\n",
                                  ctx->recv_file.final_path, got, want);
        }
}

static  void *recv_thread(void *arg)
{
        ChatCtx *ctx = arg;

        while (ctx->running) {
                uint8_t  type = 0;
                uint8_t *payload = NULL;
                uint32_t len = 0;

                if (!crypto_recv_typed(ctx->fd, &type, &payload, &len, ctx->session)) {
                        if (ctx->running) {
                                ctx->running = false;
                                printf("\n[%s disconnected.]\n", ctx->peer_name);
                                shutdown(ctx->fd, SHUT_RDWR);
                        }
                        free(payload);
                        break;
                }

                switch (type) {
                case MSG_CHAT:
                        /* Preserve the existing chat-printing UX:
                         * erase current input, print message, reprint
                         * the user's prompt so they can keep typing. */
                        printf("\r\033[2K%s: %s\n%s: ",
                               ctx->peer_name, (const char *)payload,
                               ctx->my_name);
                        fflush(stdout);
                        break;

                case FILE_OFFER:
                        handle_recv_file_offer(ctx, payload, len);
                        break;

                case FILE_ACCEPT:
                        handle_recv_file_accept(ctx);
                        break;

                case FILE_REJECT:
                        handle_recv_file_reject(ctx);
                        break;

                case FILE_CHUNK:
                        handle_recv_file_chunk(ctx, payload, len);
                        break;

                case FILE_EOF:
                        handle_recv_file_end(ctx);
                        break;

                default:
                        err("Unknown message type 0x%02x from peer.\n", type);
                        ctx->running = false;
                        shutdown(ctx->fd, SHUT_RDWR);
                        break;
                }

                free(payload);
        }

        return NULL;
}

/* ── /sendfile command ────────────────────────────────────────────────────
 *
 * Returns true if 'line' is the /sendfile command (whether or not the
 * subsequent send succeeded). The caller should 'continue' the send
 * loop in that case, because the line is not a chat message.
 *
 * On successful offer send, the state transitions to AWAITING_ACCEPT.
 * On any failure (bad path, not a regular file, send error) the state
 * stays at CHAT and the user can try again.
 *
 * NOTE (Step 4): The actual input blocking while in AWAITING_ACCEPT
 * is deferred to Step 5, along with receiver-side offer handling and
 * the accept/reject path. This function just sends the offer.
 */
static bool try_handle_sendfile_command(const char *line, ChatCtx *ctx)
{
        /* Accept exactly "/sendfile" or "/sendfile " (room for a path later). */
        if (strcmp(line, "/sendfile") != 0
            && strncmp(line, "/sendfile ", 10) != 0) {
                return false;
        }

        /*
         * Offers are only legal from CHAT state. If we already have
         * an offer outstanding (either direction), refuse and tell the
         * user.
         */
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s != CHAT_STATE_CHAT) {
                warn("Cannot start /sendfile now -- another transfer is in progress.\n");
                return true;
        }

        /* Prompt for a path on the next line. */
        char path[1024];
        printf(BMGN "INPUT" NOC ": Path to file: ");
        fflush(stdout);
        if (fgets(path, sizeof(path), stdin) == NULL) {
                /* EOF on stdin while prompting - treat as "cancelled". */
                printf("\n");
                return true;
        }
        net_strip_newline(path);

        if (path[0] == '\0') {
                warn("No path given; /sendfile cancelled.\n");
                return true;
        }

        /* Stat it. We want to know it exists, is accessible, and is a
         * regular file (not a directory, FIFO, or device). */
        struct stat st;
        if (stat(path, &st) != 0) {
                err("Cannot access '%s'.\n", path);
                return true;
        }
        if (!S_ISREG(st.st_mode)) {
                err("'%s' is not a regular file.\n", path);
                return true;
        }

        /*
         * Extract the basename. basename() may modify its argument and
         * may return a pointer INTO that argument, so we work on a
         * mutable copy and copy the result out before the copy goes
         * out of scope.
         */
        char path_copy[1024];
        strncpy(path_copy, path, sizeof(path_copy) - 1);
        path_copy[sizeof(path_copy) - 1] = '\0';

        char *base = basename(path_copy);

        /*
         * Reject degenerate basenames. basename("/") returns "/",
         * basename(".") returns ".", basename("..") returns "..".
         * None of these are legitimate filenames to send.
         */
        if (base == NULL
            || base[0] == '\0'
            || strcmp(base, ".")  == 0
            || strcmp(base, "..") == 0
            || strcmp(base, "/")  == 0)
        {
                err("Could not derive a valid filename from '%s'.\n", path);
                return true;
        }

        /*
         * fileproto_send_offer will also enforce FILEPROTO_NAME_MAX,
         * but we can give a friendlier message by checking here too.
         */
        size_t base_len = strlen(base);
        if (base_len > FILEPROTO_NAME_MAX) {
                err("Filename '%s' is too long (%zu > %u).\n",
                    base, base_len, FILEPROTO_NAME_MAX);
                return true;
        }

        uint64_t filesize = (uint64_t)st.st_size;

        info("Offering '%s' (%" PRIu64 " bytes) to peer...\n",
             base, filesize);

        /*
         * Populate ctx->sending BEFORE publishing the state change,
         * so the release-store on state synchronises both the path
         * and the new state with the recv_thread.
         */
        strncpy(ctx->sending.path, path, sizeof(ctx->sending.path) - 1);
        ctx->sending.path[sizeof(ctx->sending.path) - 1] = '\0';
        strncpy(ctx->sending.basename, base, sizeof(ctx->sending.basename) - 1);
        ctx->sending.basename[sizeof(ctx->sending.basename) - 1] = '\0';
        ctx->sending.filesize = filesize;

        if (!fileproto_send_offer(ctx->fd, base, filesize, ctx->session)) {
                err("Failed to send file offer.\n");
                return true;
        }

        atomic_store_explicit(&ctx->state, CHAT_STATE_AWAITING_ACCEPT,
                              memory_order_release);
        success("Offer sent. Waiting for peer's response...\n");
        return true;
}


/* ── state-aware prompts for send_loop ────────────────────────────────────
 *
 * These helpers are called from the top of send_loop when state is not
 * CHAT. They each read one line from stdin and return:
 *   true  -- a state transition happened (or the user just pressed Enter);
 *            send_loop should 'continue' its outer loop.
 *   false -- EOF on stdin; send_loop should shut down.
 */

/*
 * AWAITING_ACCEPT prompt: we sent an offer and are waiting for the
 * peer's decision. We still want to accept stdin (otherwise the user's
 * terminal feels frozen) but we silently discard whatever they type.
 * A bare Enter just redraws the prompt.
 */
static bool prompt_while_awaiting_accept(ChatCtx *ctx)
{
        char buf[256];
        printf(BYEL "[waiting for peer]" NOC ": ");
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
                ctx->running = false;
                printf("\n[You left the chat.]\n");
                shutdown(ctx->fd, SHUT_RDWR);
                return false;
        }
        /*
         * While we were blocked on fgets, recv_thread may have received
         * ACCEPT (state -> SENDING) or REJECT (state -> CHAT). If we're
         * now in SENDING, drive the chunk loop from this thread.
         */
        ChatState s = atomic_load_explicit(&ctx->state, memory_order_acquire);
        if (s == CHAT_STATE_SENDING) {
                return do_send_file_chunks(ctx);
        }
        /* Otherwise: discard. State will change when recv_thread processes
         * ACCEPT or REJECT. */
        return true;
}

/*
 * OFFERED prompt: peer sent us an offer and we owe them a decision.
 * Read y/Y/yes or n/N/no; anything else just reprompts.
 * On decision, send ACCEPT or REJECT and transition back to CHAT.
 * (Step 6 will transition ACCEPT -> RECEIVING instead.)
 */
static bool prompt_while_offered(ChatCtx *ctx)
{
        char buf[64];
        printf(BMGN "[offer]" NOC " Accept '%s' (%" PRIu64 " bytes)? [y/n]: ",
               ctx->pending.filename, ctx->pending.filesize);
        fflush(stdout);

        if (fgets(buf, sizeof(buf), stdin) == NULL) {
                ctx->running = false;
                printf("\n[You left the chat.]\n");
                shutdown(ctx->fd, SHUT_RDWR);
                return false;
        }
        net_strip_newline(buf);

        if (buf[0] == 'y' || buf[0] == 'Y') {
                /*
                 * Defence-in-depth: re-validate the filename before we
                 * touch the filesystem. The sender already basename()'d it,
                 * but we never trust the wire.
                 */
                const char *safe_name = ctx->pending.filename;
                if (!filename_is_safe(safe_name)) {
                        warn("Peer-supplied filename '%s' looks unsafe;"
                             " falling back to 'received.bin'.\n", safe_name);
                        safe_name = "received.bin";
                }

                char out_path[1024];
                if (!resolve_output_path(safe_name, out_path, sizeof(out_path))) {
                        err("Could not pick a non-colliding output path for '%s'.\n",
                            safe_name);
                        fileproto_send_reject(ctx->fd, ctx->session);
                        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                                              memory_order_release);
                        return true;
                }

                FILE *fp = fopen(out_path, "wb");
                if (!fp) {
                        err("Cannot open '%s' for writing.\n", out_path);
                        fileproto_send_reject(ctx->fd, ctx->session);
                        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                                              memory_order_release);
                        return true;
                }

                /* Prime recv_file BEFORE publishing RECEIVING, so the next
                 * CHUNK that arrives on recv_thread can find fp != NULL. */
                ctx->recv_file.fp            = fp;
                ctx->recv_file.expected_size = ctx->pending.filesize;
                ctx->recv_file.received      = 0;
                strncpy(ctx->recv_file.final_path, out_path,
                        sizeof(ctx->recv_file.final_path) - 1);
                ctx->recv_file.final_path[sizeof(ctx->recv_file.final_path) - 1] = '\0';

                if (!fileproto_send_accept(ctx->fd, ctx->session)) {
                        err("Failed to send accept.\n");
                        fclose(fp);
                        ctx->recv_file.fp = NULL;
                        atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                                              memory_order_release);
                        return true;
                }

                atomic_store_explicit(&ctx->state, CHAT_STATE_RECEIVING,
                                      memory_order_release);
                success("Offer accepted. Saving to '%s'. Receiving...\n",
                        out_path);
                return true;
        }

        if (buf[0] == 'n' || buf[0] == 'N') {
                if (!fileproto_send_reject(ctx->fd, ctx->session)) {
                        err("Failed to send reject.\n");
                        return true;
                }
                atomic_store_explicit(&ctx->state, CHAT_STATE_CHAT,
                                      memory_order_release);
                warn("Offer rejected.\n");
                return true;
        }

        /* Anything else -- just reprompt on the next iteration. */
        return true;
}

static void send_loop(ChatCtx *ctx)
{
        char message[1024];

        while (ctx->running) {
                /*
                 * Branch on our current state. Chat is the common case;
                 * the non-chat states are handled by dedicated prompt
                 * helpers so the chat path stays readable.
                 */
                ChatState s = atomic_load_explicit(&ctx->state,
                                                   memory_order_acquire);

                if (s == CHAT_STATE_AWAITING_ACCEPT) {
                        if (!prompt_while_awaiting_accept(ctx)) break;
                        continue;
                }
                if (s == CHAT_STATE_OFFERED) {
                        if (!prompt_while_offered(ctx)) break;
                        continue;
                }
                if (s == CHAT_STATE_RECEIVING) {
                        /*
                         * recv_thread is busy writing chunks to disk.
                         * Block chat input with a quiet prompt until
                         * the transfer finishes and state returns to CHAT.
                         */
                        char buf[256];
                        printf(BYEL "[receiving file]" NOC ": ");
                        fflush(stdout);
                        if (fgets(buf, sizeof(buf), stdin) == NULL) {
                                ctx->running = false;
                                printf("\n[You left the chat.]\n");
                                shutdown(ctx->fd, SHUT_RDWR);
                                break;
                        }
                        continue;
                }
                if (s == CHAT_STATE_SENDING) {
                        /*
                         * This should not normally be reached -- the main
                         * thread enters SENDING from prompt_while_awaiting_accept
                         * and does not return here until state is CHAT again.
                         * Included as a defensive no-op fallthrough.
                         */
                        continue;
                }
                /* CHAT path below. */

                printf("%s: ", ctx->my_name);
                fflush(stdout);

                if (fgets(message, sizeof(message), stdin) == NULL) {
                        ctx->running = false;
                        printf("\n[You left the chat.]\n");
                        shutdown(ctx->fd, SHUT_RDWR);
                        break;
                }
                net_strip_newline(message);

                if (message[0] == '\0') continue;

                /*
                 * Commands beginning with '/' are intercepted here.
                 * /sendfile enters the file-transfer flow instead of
                 * being sent as a chat message.
                 */
                if (try_handle_sendfile_command(message, ctx)) continue;

                if (!ctx->running) break;

                if (!crypto_encrypt_send(ctx->fd, message, ctx->session)) {
                        if (ctx->running) {
                                ctx->running = false;
                                fprintf(stderr, "\n[Connection lost.]\n");
                        }
                        break;
                }
        }
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
        Config cfg = parse_args(argc, argv);
        info("Rendezvous "
                MGN "%s"
                NOC ":"
                CYN "%d"
                NOC "| Local port "
                CYN "%d\n" NOC,
               cfg.server_ip, cfg.server_port, cfg.local_port);

        if (sodium_init() < 0) {
                err("libsodium init failed.\n");
                return 1;
        }

        /*
         * Generate our P2P keypair BEFORE connecting to rendezvous.
         * We keep the secret key alive until after crypto_derive_session(),
         * then zero it immediately.
         */
        Keypair my_kp;
        crypto_gen_keypair(&my_kp);
        info("Generated P2P keypair.\n");

        struct sockaddr_in local_addr = {0};
        local_addr.sin_family          = AF_INET;
        local_addr.sin_addr.s_addr     = htonl(INADDR_ANY);
        local_addr.sin_port            = htons(cfg.local_port);

        /* connect and establish E2EE with rendezvous */
        int32_t rendezvous_fd = connect_to_rendezvous(&cfg, &local_addr);
        if (rendezvous_fd == -1) {
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        Session rs = {0};
        if (!crypto_do_key_exchange(rendezvous_fd, &rs)) {
                err("Key exchange with rendezvous failed.\n");
                sodium_memzero(&my_kp, sizeof(my_kp));
                close(rendezvous_fd);
                return 1;
        }
        success("Secure channel with rendezvous established.\n");

        /* run the rendezvous protocol — get peer's IP:Port and public key */
        PeerInfo peer         = {0};
        uint8_t *peer_pub_key = NULL;

        bool got_peer = do_rendezvous_exchange(
                rendezvous_fd, &rs, &my_kp, &peer, &peer_pub_key);

        sodium_memzero(&rs, sizeof(rs));
        close(rendezvous_fd);

        if (!got_peer) {
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        /* TCP hole punch */
        int32_t p2p_fd = do_hole_punch(&peer, &local_addr, 15);
        if (p2p_fd == -1) {
                err("ROR: Hole punch failed after 15 attempts."
                        " NAT may be too strict.\n");
                free(peer_pub_key);
                sodium_memzero(&my_kp, sizeof(my_kp));
                return 1;
        }

        success("P2P connection established!\n");

        /*
         * Derive the P2P session keys from our keypair and the peer's public
         * key — no extra round-trip over the P2P connection needed.
         */
        Session ps = {0};
        bool ok = crypto_derive_session(&my_kp, peer_pub_key, &ps);

        free(peer_pub_key);
        sodium_memzero(&my_kp, sizeof(my_kp));

        if (!ok) {
                close(p2p_fd);
                return 1;
        }
        success("P2P E2EE established!\n");

        /* exchange names over the encrypted P2P channel */
        char my_name[64];
        printf(BMGN "INPUT" NOC ": Enter your name: ");
        fflush(stdout);
        if (fgets(my_name, sizeof(my_name) - 1, stdin) == NULL) {
                close(p2p_fd);
                return 1;
        }
        net_strip_newline(my_name);

        if (!crypto_encrypt_send(p2p_fd, my_name, &ps)) {
                err("Could not send name.\n");
                close(p2p_fd);
                return 1;
        }
        info("Sent my name: '%s'.\n", my_name);

        char *peer_name = NULL;
        if (!crypto_recv_decrypt(p2p_fd, &peer_name, &ps)) {
                close(p2p_fd);
                return 1;
        }
        info("Received peer's name: '%s'.\n", peer_name);

        printf("\n======================================================\n");
        printf("  Your legendary chat with '%s' begins here!", peer_name);
        printf("\n  (type a message and press Enter - Ctrl-D to quit)");
        printf("\n======================================================\n\n");

        ChatCtx chat = {
                .fd             = p2p_fd,
                .session        = &ps,
                .my_name        = my_name,
                .peer_name      = peer_name,
                .running        = true,
                .state          = CHAT_STATE_CHAT,
                /* .pending, .sending, .recv_file are zero-initialised by
                 * C's designated-init rule: all unmentioned fields get 0. */
        };

        pthread_t rtid;
        if (pthread_create(&rtid, NULL, recv_thread, &chat) != 0) {
                err("pthread_create() failed.\n");
                close(p2p_fd);
                free(peer_name);
                return 1;
        }

        /* sender runs on the main thread (needs stdin) */
        send_loop(&chat);

        /* wait for the receiver to finish */
        pthread_join(rtid, NULL);

        /* cleanup */
        free(peer_name);
        sodium_memzero(&ps, sizeof(ps));
        close(p2p_fd);
        return 0;
}
