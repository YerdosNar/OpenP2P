"""
Wire protocol for the Rendezvous and P2P phases

Frame format on the wire:
    [ 4 bytes: big-endian lenght N ][ N bytes: payload ]

Payload format (after any outer decryption):
    [ 1 bytes: message type ][ body bytes ]

Body format depends on the message type - either UTF-8 JSON or a type-specific
binary layout. See the per-type helpers below.
"""

import json
from re import error
import struct
from enum import IntEnum

class MsgType(IntEnum):
    # handshake
    HELLO       = 0x01

    # rendezvous <-> peer
    ROLE_SELECT = 0x10
    ROOM_CREATE = 0x11
    ROOM_JOIN   = 0x12
    ROOM_RESULT = 0x13
    PEER_INFO   = 0x14
    ERROR       = 0x15
    KEEPALIVE   = 0x16

    # p <-> p
    CHAT        = 0x20
    FILE_OFFER  = 0x21
    FILE_ACCEPT = 0x22
    FILE_REJECT = 0x23
    FILE_CHUNK  = 0x24
    FILE_DONE   = 0x25
    BYE         = 0x2F


LENGTH_PREFIX   = struct.Struct("!I")   # 4-byte big-endian unsigned int
MAX_FRAME_SIZE  = 16 * 1024 * 1024      # 16 MB


def frame(payload: bytes) -> bytes:
