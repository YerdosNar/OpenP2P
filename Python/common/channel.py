"""
Encrypted, framed, typed message channel built on asyncio streams.

AFter ECDH handshake, both sides wrap their (reader, writer) pair in an
EncryptedChannel and use `send_msg/recv_msg` as their only I/O primitive
"""

import asyncio
from common import crypto
from common.protocol import (
    MsgType, frame, read_frame, encode, decode,
)


class EncryptedChannel:
    """
    Thin wrapper that encrypts outgoing payloads and decrypts incoming ones.

    The underlying transport is asyncio streams (TCP). The frame-length prefix
    stays in the clear; the [type||body] portion is what gets encrypted
    """


    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        shared_key: bytes,
    ):
        self._reader = reader
        self._writer = writer
        self._key = shared_key


    async def send_msg(
        self,
        msg_type: MsgType,
        body: bytes = b""
    ) -> None:
        payload = encode(msg_type, body)
        ciphertext = crypto.encrypt(self._key, payload)
        self._writer.write(frame(ciphertext))
        await self._writer.drain()


    async def recv_msg(self) -> tuple[MsgType, bytes]:
        ciphertext = await read_frame(self._reader)
        payload = crypto.decrypt(self._key, ciphertext)
        return decode(payload)


    async def close(self) -> None:
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except Exception:
            pass


    @property
    def peer_address(self) -> tuple[str, int]:
        """Returns the (host, port) the remote end connected from."""
        return self._writer.get_extra_info("peername")[:2]
