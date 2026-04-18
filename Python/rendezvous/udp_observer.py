import asyncio
import logging
from typing import Optional

log = logging.getLogger("rendezvous.udp")

NONCE_SIZE = 16


class UDPObserver(asyncio.DatagramProtocol):
    def __init__(self):
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._pending = {}

    def connection_made(self, transport) -> None:
        self._transport = transport
        sockname = transport.get_extra_info("sockname")
        log.info("UDP observer listening on %s", sockname)

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) != NONCE_SIZE:
            return
        future = self._pending.pop(data, None)
        if future is None:
            return
        if not future.done():
            future.set_result((addr[0], addr[1]))

    def error_received(self, exc: Exception) -> None:
        log.debug("UDP error: %s", exc)

    def register_nonce(self, nonce: bytes) -> asyncio.Future:
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        fut = asyncio.get_running_loop().create_future()
        self._pending[nonce] = fut
        return fut

    def cancel_nonce(self, nonce: bytes) -> None:
        fut = self._pending.pop(nonce, None)
        if fut is not None and not fut.done():
            fut.cancel()


async def start_udp_observer(host: str, port: int):
    loop = asyncio.get_running_loop()
    observer = UDPObserver()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: observer, local_addr=(host, port)
    )
    return observer, transport
