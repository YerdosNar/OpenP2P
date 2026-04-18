"""
Wire protocol for the Rendezvous and P2P phases.

Frame format on the wire:
    [ 4 bytes: big-endian length N ][ N bytes: payload ]

Payload format (after any outer decryption):
    [ 1 byte: message type ][ body bytes ]

Body format depends on the message type — either UTF-8 JSON or a type-specific
binary layout. See the per-type helpers below.
"""

import json
import struct
from enum import IntEnum


# -------- Message types --------

class MsgType(IntEnum):
    # Handshake (unencrypted, only used for initial key exchange)
    HELLO = 0x01

    # Rendezvous control (encrypted with Peer <-> Rendezvous shared key)
    ROLE_SELECT   = 0x10
    ROOM_CREATE   = 0x11
    ROOM_JOIN     = 0x12
    ROOM_RESULT   = 0x13
    PEER_INFO     = 0x14
    ERROR         = 0x15
    KEEPALIVE     = 0x16

    # Add inside MsgType, in the 0x10 Rendezvous control block
    OBSERVE_REQUEST  = 0x17   # server → peer: "send a UDP probe with this nonce"
    OBSERVED_ADDR    = 0x18   # server → peer: "I saw you at this IP:port"

    # P2P application messages (encrypted by QUIC/TLS 1.3)
    CHAT          = 0x20
    FILE_OFFER    = 0x21
    FILE_ACCEPT   = 0x22
    FILE_REJECT   = 0x23
    FILE_CHUNK    = 0x24
    FILE_DONE     = 0x25
    BYE           = 0x2F


# -------- Framing (length-prefix) --------

LENGTH_PREFIX = struct.Struct("!I")   # 4-byte big-endian unsigned int
MAX_FRAME_SIZE = 16 * 1024 * 1024     # 16 MiB safety cap — reject anything larger


def frame(payload: bytes) -> bytes:
    """Wrap a payload with a 4-byte big-endian length prefix."""
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError(f"Payload too large: {len(payload)} bytes")
    return LENGTH_PREFIX.pack(len(payload)) + payload


async def read_frame(reader) -> bytes:
    """
    Read one framed message from an asyncio StreamReader (or similar object
    exposing `readexactly`). Returns the payload bytes (length prefix stripped).

    Raises ValueError if the announced length exceeds MAX_FRAME_SIZE —
    a basic safeguard against a malicious or confused peer claiming
    gigabyte-sized frames.
    """
    header = await reader.readexactly(LENGTH_PREFIX.size)
    (length,) = LENGTH_PREFIX.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame announces {length} bytes, exceeds cap")
    return await reader.readexactly(length)


# -------- Payload encoding (type byte + body) --------

def encode(msg_type: MsgType, body: bytes = b"") -> bytes:
    """Build a payload: one type byte followed by the body."""
    return bytes([msg_type]) + body


def decode(payload: bytes) -> tuple[MsgType, bytes]:
    """Split a payload into (msg_type, body). Raises on unknown type."""
    if len(payload) < 1:
        raise ValueError("Empty payload")
    try:
        msg_type = MsgType(payload[0])
    except ValueError:
        raise ValueError(f"Unknown message type: 0x{payload[0]:02x}")
    return msg_type, payload[1:]


# -------- JSON body helpers --------

def encode_json(msg_type: MsgType, obj) -> bytes:
    """Encode a JSON-serializable object as the body of a message."""
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return encode(msg_type, body)


def decode_json(body: bytes):
    """Decode a UTF-8 JSON body back into a Python object."""
    return json.loads(body.decode("utf-8"))


# -------- File chunk helpers (binary, not JSON) --------

CHUNK_HEADER = struct.Struct("!I")   # 4-byte chunk sequence number


def encode_file_chunk(seq: int, data: bytes) -> bytes:
    """Body layout: [4-byte seq number][chunk bytes]."""
    return encode(MsgType.FILE_CHUNK, CHUNK_HEADER.pack(seq) + data)


def decode_file_chunk(body: bytes) -> tuple[int, bytes]:
    """Parse a FILE_CHUNK body. Returns (seq, data)."""
    if len(body) < CHUNK_HEADER.size:
        raise ValueError("FILE_CHUNK body too short")
    (seq,) = CHUNK_HEADER.unpack(body[: CHUNK_HEADER.size])
    return seq, body[CHUNK_HEADER.size:]
