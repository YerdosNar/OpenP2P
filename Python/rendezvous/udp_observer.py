"""
UDP endpoit for the Rendezvous server.

Listens for probe packets (16-byte nonces) and reports observed source
addresses back to the TCP handlers that waiting on the those nonces.

The glue: each TCP session registers a Future keyed by the nonce it gave
to the peer. When a UDP probe with that nonce arrives, we set the future's
result to the probe's source address.
"""

import asyncio
import logging
from typing import Optional

log = logging.getLogger("rendezvous.udp")

NONCE_SIZE = 16 # 128 bits


class UDPObserver(asyncio.DatagramProtocol):
    """
    asyncio DatagramProtocol that dispatches probes to waiting futures.

    A single instance handles all peers; per-session coordination happens
    through the `pending` dict keyed by nonce.
    """


    def __init__(self):
        self._transport: Optional[asyncio.DatagramTransport] = None
        # nonce (bytes) -> Future that will receive (ip, port)
        self._pending: dict[bytes, asyncio.Future] = {}


    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self._transport = transport
        sockname = transport.get_extra_info("sockname")
        log.info("UDP observer listening on %s", sockname)


    def datagram_received(self, data: bytes, addr: tuple) -> None:
        # accept only exact-sized probes; anything else is noise
        if len(data) != NONCE_SIZE:
            return
        future = self._pending.pop(data, None)
        if future is None:
            # No session waiting for this nonce.
            # Could be a late retry from a session that already succeeded
            # - perfectly normal, ignore
            return
        if not future.done():
            future.set_result((addr[0], addr[1]))


    def error_received(self, exc: Exception) -> None:
        log.debug("UDP error: %s", exc)


    def register_nonce(self, nonce: bytes) -> asyncio.Future:
        """
        Reserve a future for a given nonce.
        The TCP handler awaits this;
        it resolves when a matching UDP probe arrives
        """
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"nonce must be {NONCE_SIZE} bytes")
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[nonce] = fut
        return fut


    def cancel_nonce(self, nonce: bytes) -> None:
        """Remove a pending nonce (on session timeout or error). Idempotent"""
        fut = self._pending.pop(nonce, None)
        if fut is not None and not fut.done():
            fut.cancel()


async def start_udp_observer(
        host: str,
        port: int
) -> tuple[UDPObserver, asyncio.DatagramTransport]:
    """Create and start the UDP observer endpoint"""
    loop = asyncio.get_running_loop()
    observer = UDPObserver()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: observer, local_addr=(host, port)
    )
    return observer, transport
