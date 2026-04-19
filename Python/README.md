# P2P Chat + File Transfer

Two peers connect through a rendezvous server that only helps them find
each other. After UDP hole-punching, the peers talk directly over QUIC
— end-to-end encrypted, with mutual HMAC authentication derived from
X25519 keys exchanged through the rendezvous.

## Install

```bash
pip install -r requirements.txt
```

## Run

### 1. Start the rendezvous server (on a publicly reachable host)

```bash
python run_rendezvous.py
```

It listens on TCP+UDP port 8888 by default. Override with
`--host 0.0.0.0 --port 8888`.

### 2. Peer 1 — host

```bash
python run_peer.py --host <rendezvous-ip> --port 8888
```

Pick `h` when prompted, then enter a room ID and password of your
choice. The host waits up to 3 minutes for a joiner.

### 3. Peer 2 — joiner (within 3 minutes)

```bash
python run_peer.py --host <rendezvous-ip> --port 8888
```

Pick `j`, then enter the same room ID + password as the host.

### 4. Chat

Both sides see `> `. Type a line and hit Enter to send.

Commands in chat:

- `/send <path>`  — offer a file to the peer. No size limit.
- `/accept`        — accept a pending file offer from the peer.
- `/reject`        — reject a pending file offer from the peer.
- `/quit`          — say BYE and disconnect.

Received files land in `./downloads/` next to wherever you ran
`run_peer.py`.

## Security model

- The rendezvous server learns each peer's public UDP endpoint
  (IP + port) and each peer's *ephemeral* X25519 public key. That's it.
- The P2P link uses QUIC (built-in TLS 1.3). The TLS cert is a throwaway
  — identity is enforced by a separate mutual HMAC challenge over the
  X25519-derived shared key, performed before any chat data is exchanged.
- Everything the rendezvous sees is also authenticated-encrypted
  (X25519 + AES-256-GCM) so a passive attacker on that TCP link can't
  tamper.

## Files

```
common/
  crypto.py         X25519 / HKDF / AES-GCM
  protocol.py       Message types, length-prefixed frames
  channel.py        Encrypted TCP framing (peer <-> rendezvous)
  socket_utils.py   UDP helpers, NAT keepalive

rendezvous/
  server.py         Matchmaking server
  room.py           Room registry with 3-minute TTL
  udp_observer.py   Learns each peer's public UDP endpoint via a nonce

peer/
  client.py         Interactive entry point
  p2p.py            UDP hole-punch + QUIC transport
  session.py        Mutual HMAC auth, chat, file transfer

run_rendezvous.py
run_peer.py
```

## No size limit on file transfer

The `FILE_OFFER` intentionally omits the file hash so a terabyte-scale
file doesn't need a pre-send SHA-256 pass. The hash is computed streaming
as chunks are sent and delivered in `FILE_DONE` for the receiver to
verify. Chunk sequence numbers are 64-bit.
