"""Authenticated-encrypted framing on top of asyncio TCP streams."""
import asyncio
from common import crypto
from common.protocol import (
    MsgType, frame, read_frame, encode, decode,
)


class EncryptedChannel:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        shared_key: bytes,
    ):
        self._reader = reader
        self._writer = writer
        self._key = shared_key

    async def send_msg(self, msg_type: MsgType, body: bytes = b"") -> None:
        payload = encode(msg_type, body)
        ciphertext = crypto.encrypt(self._key, payload)
        self._writer.write(frame(ciphertext))
        await self._writer.drain()

    async def recv_msg(self):
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
    def peer_address(self):
        return self._writer.get_extra_info("peername")[:2]
