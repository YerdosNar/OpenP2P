"""UDP hole punching and QUIC transport for a single peer-to-peer link.

This module owns the UDP socket after rendezvous is complete. It:
  1. Sprays a handful of packets toward the peer's observed endpoint to
     open the NAT pinhole (punch_hole()).
  2. Runs a QUIC connection over that same socket -- the host is the QUIC
     server, the joiner is the QUIC client.

Two bugs that used to live here and are now fixed:

  (a) The timer loop only flushed outgoing QUIC datagrams on *timer* wake,
      not on `send_stream()` wake. That meant chat messages queued by
      Session.send_chat() could sit inside aioquic indefinitely on an
      otherwise-idle link until some QUIC-internal timer fired.

  (b) `StreamDataReceived` events that arrived before on_stream_data was
      registered (i.e. between QUIC handshake completing and the caller
      constructing a Session) were silently dropped. We now buffer them and
      replay as soon as a handler is installed.
"""
import asyncio
import datetime
import logging
import socket
import ssl
import tempfile
from typing import Optional

from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import (
    HandshakeCompleted,
    StreamDataReceived,
    ConnectionTerminated,
)
from aioquic.quic.packet import pull_quic_header
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("peer.p2p")

HOLEPUNCH_PACKET_COUNT = 10
HOLEPUNCH_INTERVAL = 0.05
HOLEPUNCH_MAGIC = b"PUNCH-v1"
QUIC_ALPN = ["p2p-chat/1"]


def generate_selfsigned_cert():
    """A throwaway cert for QUIC's TLS layer. Identity here is meaningless --
    the Session layer does a real mutual HMAC auth over X25519-derived keys
    after the QUIC handshake completes."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "p2p-peer"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
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


async def punch_hole(
    udp_sock: socket.socket,
    peer_addr,
    is_host: bool,
) -> None:
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


class QuicPeer:
    def __init__(
        self,
        udp_sock: socket.socket,
        peer_addr,
        is_host: bool,
    ):
        self._sock = udp_sock
        self._peer_addr = peer_addr
        self._is_host = is_host
        self._quic: Optional[QuicConnection] = None
        self._handshake_done = asyncio.get_event_loop().create_future()
        self._closed = False
        self._wake = asyncio.Event()

        # Stream-data events that arrived before on_stream_data was registered
        # are queued here and replayed the moment a handler is attached.
        self._stream_data_backlog = []
        self._on_stream_data = None

        self.on_terminated = None

    # `on_stream_data` is a property so that assigning it drains any backlog.
    @property
    def on_stream_data(self):
        return self._on_stream_data

    @on_stream_data.setter
    def on_stream_data(self, cb):
        self._on_stream_data = cb
        if cb is None or not self._stream_data_backlog:
            return
        backlog = self._stream_data_backlog
        self._stream_data_backlog = []

        async def replay():
            for sid, data, end in backlog:
                try:
                    await cb(sid, data, end)
                except Exception:
                    log.exception("stream-data replay handler raised")
        asyncio.create_task(replay())

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
        log.info("[%s] QuicPeer.run starting; peer=%s local=%s",
                 role, self._peer_addr, self._sock.getsockname())

        config = self._build_configuration()

        if not self._is_host:
            self._quic = QuicConnection(configuration=config)
            log.info("[%s] calling QUIC connect()", role)
            self._quic.connect(self._peer_addr, now=self._now())
            await self._flush_out()
        else:
            log.info("[%s] waiting for first client Initial...", role)

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
        except Exception:
            return False

    async def _recv_loop(self) -> None:
        loop = asyncio.get_running_loop()
        role = "host" if self._is_host else "joiner"
        while not self._closed:
            try:
                data, addr = await loop.sock_recvfrom(self._sock, 65535)
            except OSError as e:
                log.error("[%s] sock_recvfrom failed: %s", role, e)
                return

            # Ignore hole-punch packets and keepalives.
            if data.startswith(HOLEPUNCH_MAGIC):
                continue
            if len(data) == 0:
                continue
            # NAT keepalive (single \x00 byte) sent by the rendezvous-era
            # keepalive loop. Drop silently.
            if len(data) == 1 and data == b"\x00":
                continue

            if self._is_host and self._quic is None:
                try:
                    buf = Buffer(data=data)
                    header = pull_quic_header(buf, host_cid_length=8)
                except Exception as e:
                    log.warning("[%s] cannot parse first packet header: %s",
                                role, e)
                    continue
                log.info("[%s] first Initial received; DCID=%s",
                         role, header.destination_cid.hex())
                config = self._build_configuration()
                self._quic = QuicConnection(
                    configuration=config,
                    original_destination_connection_id=header.destination_cid,
                )

            self._quic.receive_datagram(data, addr, now=self._now())
            await self._process_quic_events()
            await self._flush_out()

    async def _timer_loop(self) -> None:
        # Wakes on either (a) a QUIC timer firing, or (b) send_stream() setting
        # `_wake`. Either way it MUST pump events + flush outgoing datagrams,
        # otherwise queued stream data can sit idle inside aioquic.
        while not self._closed:
            if self._quic is None:
                try:
                    await asyncio.wait_for(self._wake.wait(), 0.5)
                except asyncio.TimeoutError:
                    pass
                self._wake.clear()
                continue

            timer_at = self._quic.get_timer()
            now = self._now()
            delay = 0.1 if timer_at is None else max(0.0, timer_at - now)

            try:
                await asyncio.wait_for(self._wake.wait(), delay)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

            # Fire the QUIC timer only if it's actually due.
            t = self._quic.get_timer()
            if t is not None and t <= self._now():
                self._quic.handle_timer(now=self._now())

            await self._process_quic_events()
            await self._flush_out()

    async def _flush_out(self) -> None:
        loop = asyncio.get_running_loop()
        role = "host" if self._is_host else "joiner"
        if self._quic is None:
            return
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
        if self._quic is None:
            return
        while True:
            event = self._quic.next_event()
            if event is None:
                return
            if isinstance(event, HandshakeCompleted):
                log.info("[%s] QUIC handshake completed (alpn=%s)",
                         role, event.alpn_protocol)
                if not self._handshake_done.done():
                    self._handshake_done.set_result(True)
            elif isinstance(event, StreamDataReceived):
                if self._on_stream_data is not None:
                    await self._on_stream_data(
                        event.stream_id, event.data, event.end_stream
                    )
                else:
                    # Buffer until Session registers a handler.
                    self._stream_data_backlog.append(
                        (event.stream_id, event.data, event.end_stream)
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
            try:
                self._quic.close()
                await self._flush_out()
            except Exception:
                pass
        self._closed = True
        self._wake.set()
