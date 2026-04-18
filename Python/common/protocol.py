import json
import struct
from enum import IntEnum


class MsgType(IntEnum):
    HELLO = 0x01

    ROLE_SELECT = 0x10
    ROOM_CREATE = 0x11
    ROOM_JOIN = 0x12
    ROOM_RESULT = 0x13
    PEER_INFO = 0x14
    ERROR = 0x15
    KEEPALIVE = 0x16
    OBSERVE_REQUEST = 0x17
    OBSERVED_ADDR = 0x18

    CHAT = 0x20
    FILE_OFFER = 0x21
    FILE_ACCEPT = 0x22
    FILE_REJECT = 0x23
    FILE_CHUNK = 0x24
    FILE_DONE = 0x25
    BYE = 0x2F


LENGTH_PREFIX = struct.Struct("!I")
MAX_FRAME_SIZE = 16 * 1024 * 1024


def frame(payload: bytes) -> bytes:
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError(f"Payload too large: {len(payload)} bytes")
    return LENGTH_PREFIX.pack(len(payload)) + payload


async def read_frame(reader) -> bytes:
    header = await reader.readexactly(LENGTH_PREFIX.size)
    (length,) = LENGTH_PREFIX.unpack(header)
    if length > MAX_FRAME_SIZE:
        raise ValueError(f"Frame announces {length} bytes, exceeds cap")
    return await reader.readexactly(length)


def encode(msg_type: MsgType, body: bytes = b"") -> bytes:
    return bytes([msg_type]) + body


def decode(payload: bytes) -> tuple:
    if len(payload) < 1:
        raise ValueError("Empty payload")
    try:
        msg_type = MsgType(payload[0])
    except ValueError:
        raise ValueError(f"Unknown message type: 0x{payload[0]:02x}")
    return msg_type, payload[1:]


def encode_json(msg_type: MsgType, obj) -> bytes:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return encode(msg_type, body)


def decode_json(body: bytes):
    return json.loads(body.decode("utf-8"))


CHUNK_HEADER = struct.Struct("!I")


def encode_file_chunk(seq: int, data: bytes) -> bytes:
    return encode(MsgType.FILE_CHUNK, CHUNK_HEADER.pack(seq) + data)


def decode_file_chunk(body: bytes) -> tuple:
    if len(body) < CHUNK_HEADER.size:
        raise ValueError("FILE_CHUNK body too short")
    (seq,) = CHUNK_HEADER.unpack(body[: CHUNK_HEADER.size])
    return seq, body[CHUNK_HEADER.size:]
