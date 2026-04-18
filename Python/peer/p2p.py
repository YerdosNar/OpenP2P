"""
Peer-to-peer transport: UDP hole punching and QUIC connection management.

Takes a hole-punched UDP socket and peer info, produces a live QUIC
connection between two peers.
"""

import asyncio
import datetime
import logging
import os
import socket
import ssl
import tempfile
from typing import Optional

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    HandshakeCompleted,
    StreamDataReceived,
    ConnectionTerminated,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("peer.p2p")

# Tunables
HOLEPUNCH_PACKET_COUNT = 10
HOLEPUNCH_INTERVAL = 0.05
HOLEPUNCH_MAGIC = b"PUNCH-v1"
QUIC_ALPN = ["p2p-chat/1"]


# -------- Self-signed cert generation --------

def generate_selfsigned_cert() -> tuple[bytes, bytes]:
    """Generate an ephemeral self-signed cert for QUIC/TLS."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "p2p-peer"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# -------- Hole punching --------

async def punch_hole(
    udp_sock: socket.socket,
    peer_addr: tuple[str, int],
    is_host: bool,
) -> None:
    """Spam tiny UDP packets at peer_addr to open the NAT hole."""
    loop = asyncio.get_running_loop()
    role = "host" if is_host else "joiner"
    log.info("[%s] Hole punching %s:%d", role, peer_addr[0], peer_addr[1])

    for i in range(HOLEPUNCH_PACKET_COUNT):
        packet = HOLEPUNCH_MAGIC + i.to_bytes(2, "big")
        try:
            await loop.sock_sendto(udp_sock, packet, peer_addr)
        except OSError as e:
            log.warning("[%s] punch send failed: %s", role, e)
            break
        await asyncio.sleep(HOLEPUNCH_INTERVAL)

    log.info("[%s] Hole punching complete", role)


# -------- QUIC connection driver --------

class QuicPeer:
    """Drives a QUIC connection over a pre-existing UDP socket."""

    def __init__(
        self,
        udp_sock: socket.socket,
        peer_addr: tuple[str, int],
        is_host: bool,
    ):
        self._sock = udp_sock
        self._peer_addr = peer_addr
        self._is_host = is_host
        self._quic: Optional[QuicConnection] = None
        self._handshake_done: asyncio.Future = (
            asyncio.get_event_loop().create_future()
        )
        self._closed = False
        self._wake = asyncio.Event()
        # Callbacks set by higher layers
        self.on_stream_data = None  # async callable(stream_id, data, end_stream)
        self.on_terminated = None   # async callable(reason)

    def _build_configuration(self) -> QuicConfiguration:
        config = QuicConfiguration(
            is_client=not self._is_host,
            alpn_protocols=QUIC_ALPN,
        )
        if self._is_host:
            cert_pem, key_pem = generate_selfsigned_cert()
            with tempfile.NamedTemporaryFile(
                delete=False, suffix=".pem"
            ) as cf, tempfile.NamedTemporaryFile(
                delete=False, suffix=".pem"
            ) as kf:
                cf.write(cert_pem); cf.flush()
                kf.write(key_pem); kf.flush()
                config.load_cert_chain(cf.name, kf.name)
        else:
            config.verify_mode = ssl.CERT_NONE
        return config

    def _now(self) -> float:
        return asyncio.get_running_loop().time()

    async def run(self) -> None:
        role = "host" if self._is_host else "joiner"
        log.info("[%s] QuicPeer.run starting; peer=%s sock_fd=%d local=%s",
                 role, self._peer_addr,
                 self._sock.fileno(), self._sock.getsockname())

        config = self._build_configuration()
        self._quic = QuicConnection(configuration=config)

        if not self._is_host:
            log.info("[%s] calling QUIC connect()", role)
            self._quic.connect(self._peer_addr, now=self._now())
            # CRITICAL: flush the Initial packet immediately, don't wait
            # for a timer. Without this, the handshake can stall.
            await self._flush_out()

        recv_task = asyncio.create_task(self._recv_loop())
        timer_task = asyncio.create_task(self._timer_loop())

        try:
            await asyncio.gather(recv_task, timer_task)
        except asyncio.CancelledError:
            pass
        finally:
            self._closed = True
            self._wake.set()

    async def wait_handshake(self, timeout: float = 10.0) -> bool:
        try:
            await asyncio.wait_for(self._handshake_done, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    # ---- Socket pumping ----

    async def _recv_loop(self) -> None:
        loop = asyncio.get_running_loop()
        role = "host" if self._is_host else "joiner"
        while not self._closed:
            try:
                data, addr = await loop.sock_recvfrom(self._sock, 65535)
            except OSError as e:
                log.error("[%s] sock_recvfrom failed: %s", role, e)
                return

            log.debug("[%s] RX %d bytes from %s", role, len(data), addr)

            if data.startswith(HOLEPUNCH_MAGIC):
                log.debug("[%s]   (hole-punch packet, ignored)", role)
                continue
            if len(data) == 0:
                continue

            self._quic.receive_datagram(data, addr, now=self._now())
            await self._process_quic_events()
            await self._flush_out()

    async def _timer_loop(self) -> None:
        role = "host" if self._is_host else "joiner"
        while not self._closed:
            assert self._quic is not None
            timer_at = self._quic.get_timer()
            now = self._now()
            if timer_at is None:
                # No timer active; wait briefly and poll again
                try:
                    await asyncio.wait_for(self._wake.wait(), 0.1)
                except asyncio.TimeoutError:
                    pass
                self._wake.clear()
                continue
            delay = max(0.0, timer_at - now)
            if delay > 0:
                try:
                    await asyncio.wait_for(self._wake.wait(), delay)
                    self._wake.clear()
                    continue
                except asyncio.TimeoutError:
                    pass
            self._quic.handle_timer(now=self._now())
            await self._process_quic_events()
            await self._flush_out()

    async def _flush_out(self) -> None:
        loop = asyncio.get_running_loop()
        role = "host" if self._is_host else "joiner"
        assert self._quic is not None
        count = 0
        total_bytes = 0
        for data, addr in self._quic.datagrams_to_send(now=self._now()):
            try:
                await loop.sock_sendto(self._sock, data, addr)
                count += 1
                total_bytes += len(data)
            except OSError as e:
                log.warning("[%s] QUIC sendto failed: %s", role, e)
                return
        if count:
            log.debug("[%s] TX %d datagrams (%d bytes) to %s",
                      role, count, total_bytes, self._peer_addr)

    async def _process_quic_events(self) -> None:
        role = "host" if self._is_host else "joiner"
        assert self._quic is not None
        while True:
            event = self._quic.next_event()
            if event is None:
                return
            log.debug("[%s] QUIC event: %s", role, type(event).__name__)
            if isinstance(event, HandshakeCompleted):
                log.info("[%s] QUIC handshake completed (alpn=%s)",
                         role, event.alpn_protocol)
                if not self._handshake_done.done():
                    self._handshake_done.set_result(True)
            elif isinstance(event, StreamDataReceived):
                if self.on_stream_data is not None:
                    await self.on_stream_data(
                        event.stream_id, event.data, event.end_stream
                    )
            elif isinstance(event, ConnectionTerminated):
                log.info("[%s] QUIC terminated: %s", role, event.reason_phrase)
                if not self._handshake_done.done():
                    self._handshake_done.set_exception(
                        RuntimeError(
                            f"QUIC terminated before handshake: "
                            f"{event.reason_phrase}"
                        )
                    )
                if self.on_terminated is not None:
                    await self.on_terminated(event.reason_phrase)
                self._closed = True
                self._wake.set()
                return

    # ---- API for higher layers ----

    def send_stream(
        self, stream_id: int, data: bytes, end_stream: bool = False
    ) -> None:
        assert self._quic is not None
        self._quic.send_stream_data(stream_id, data, end_stream=end_stream)
        self._wake.set()

    def get_next_stream_id(self) -> int:
        assert self._quic is not None
        return self._quic.get_next_available_stream_id()

    async def close(self) -> None:
        if self._quic is not None and not self._closed:
            self._quic.close()
            await self._flush_out()
        self._closed = True
        self._wake.set()
