"""
Peer-to-peer transport: UDP hole punching and QUIC connection management.

This module takes a PeerHandoff from the Rendezvous phase and produces
an authenticated QUIC connection to the other peer.
"""

import asyncio
import logging
import os
import socket
import ssl
from typing import Optional

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, ConnectionTerminated
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

from common import crypto
from common.protocol import MsgType, frame, encode, decode

log = logging.getLogger("peer.p2p")

# Tunables
HOLEPUNCH_PACKET_COUNT = 10
HOLEPUNCH_INTERVAL = 0.05
HOLEPUNCH_MAGIC = b"PUNCH-v1"
QUIC_ALPN = ["p2p-chat/1"]


# -------- Self-signed cert generation for QUIC --------

def generate_selfsigned_cert() -> tuple[bytes, bytes]:
    """
    Generate an ephemeral self-signed certificate and RSA key in PEM form.
    QUIC/TLS needs these but we don't use them for identity — peer identity
    is verified separately via X25519 challenge-response.
    """
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
    """
    Spam a few tiny UDP packets at peer_addr to open the NAT hole.

    Both peers run this simultaneously. Packets carry a magic string so
    anything echoed back is recognizable as peer traffic, not random noise.

    This function sends; incoming punch packets are consumed by the packet
    dispatcher in run_quic_connection.
    """
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


# -------- QUIC connection driver (shared client/server logic) --------

class QuicPeer:
    """
    Drives a QUIC connection over a pre-existing UDP socket.

    One instance per peer. Handles both client role (joiner) and server
    role (host), differing only in the initial QuicConnection setup.
    """

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
        self._handshake_done: asyncio.Future = asyncio.get_event_loop().create_future()
        self._closed = False
        # Application-level callbacks set by higher layers (Step 9b).
        self.on_stream_data = None  # async callable(stream_id, data, end_stream)
        self.on_terminated = None   # async callable(reason)

    def _build_configuration(self) -> QuicConfiguration:
        config = QuicConfiguration(
            is_client=not self._is_host,
            alpn_protocols=QUIC_ALPN,
        )
        if self._is_host:
            cert_pem, key_pem = generate_selfsigned_cert()
            # Write to temp files because aioquic's load_cert_chain reads paths.
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cf, \
                 tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as kf:
                cf.write(cert_pem); cf.flush()
                kf.write(key_pem); kf.flush()
                config.load_cert_chain(cf.name, kf.name)
        else:
            # Client: accept any cert (we authenticate via X25519 below).
            config.verify_mode = ssl.CERT_NONE
        return config

    async def run(self) -> None:
        """Main loop: drive the QUIC state machine until handshake + done."""
        config = self._build_configuration()
        self._quic = QuicConnection(configuration=config)

        if not self._is_host:
            # Client initiates the handshake.
            self._quic.connect(self._peer_addr, now=self._now())

        send_task = asyncio.create_task(self._send_loop())
        recv_task = asyncio.create_task(self._recv_loop())
        timer_task = asyncio.create_task(self._timer_loop())

        try:
            await asyncio.gather(send_task, recv_task, timer_task)
        except asyncio.CancelledError:
            pass
        finally:
            self._closed = True

    async def wait_handshake(self, timeout: float = 10.0) -> bool:
        """Await the QUIC TLS handshake. True on success, False on timeout."""
        try:
            await asyncio.wait_for(self._handshake_done, timeout)
            return True
        except asyncio.TimeoutError:
            return False

    def _now(self) -> float:
        return asyncio.get_running_loop().time()

    # ---- Socket pumping ----

    async def _recv_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while not self._closed:
            try:
                data, addr = await loop.sock_recvfrom(self._sock, 65535)
            except OSError:
                return

            # Filter: ignore hole-punch echoes and other stray UDP noise.
            if data.startswith(HOLEPUNCH_MAGIC):
                continue
            if len(data) == 0:
                continue

            # Feed QUIC.
            self._quic.receive_datagram(data, addr, now=self._now())
            await self._process_quic_events()
            # Any processing may have queued outgoing packets.
            await self._flush_out()

    async def _send_loop(self) -> None:
        # The send_loop only exists to keep the structured-gather alive; the
        # actual sends happen via _flush_out called from recv/timer paths.
        # We still need a heartbeat so aioquic's timer-driven retransmits fire.
        while not self._closed:
            await asyncio.sleep(3600)  # essentially sleep forever

    async def _timer_loop(self) -> None:
        """Fire QUIC's internal timers (retransmits, etc.)."""
        while not self._closed:
            assert self._quic is not None
            timer_at = self._quic.get_timer()
            now = self._now()
            if timer_at is None:
                await asyncio.sleep(0.05)
                continue
            delay = max(0.0, timer_at - now)
            await asyncio.sleep(delay)
            self._quic.handle_timer(now=self._now())
            await self._process_quic_events()
            await self._flush_out()

    async def _flush_out(self) -> None:
        loop = asyncio.get_running_loop()
        assert self._quic is not None
        for data, addr in self._quic.datagrams_to_send(now=self._now()):
            try:
                await loop.sock_sendto(self._sock, data, addr)
            except OSError as e:
                log.warning("QUIC sendto failed: %s", e)
                return

    async def _process_quic_events(self) -> None:
        assert self._quic is not None
        while True:
            event = self._quic.next_event()
            if event is None:
                return
            if isinstance(event, HandshakeCompleted):
                log.info("QUIC handshake completed (alpn=%s)", event.alpn_protocol)
                if not self._handshake_done.done():
                    self._handshake_done.set_result(True)
            elif isinstance(event, StreamDataReceived):
                if self.on_stream_data is not None:
                    await self.on_stream_data(event.stream_id, event.data, event.end_stream)
            elif isinstance(event, ConnectionTerminated):
                log.info("QUIC terminated: %s", event.reason_phrase)
                if not self._handshake_done.done():
                    self._handshake_done.set_exception(
                        RuntimeError(f"QUIC terminated before handshake: {event.reason_phrase}")
                    )
                if self.on_terminated is not None:
                    await self.on_terminated(event.reason_phrase)
                self._closed = True
                return

    # ---- API for higher layers (used in Step 9b) ----

    def send_stream(self, stream_id: int, data: bytes, end_stream: bool = False) -> None:
        assert self._quic is not None
        self._quic.send_stream_data(stream_id, data, end_stream=end_stream)

    def get_next_stream_id(self) -> int:
        """Client streams are even, server streams are odd (per QUIC spec).
        We just use whichever bidirectional stream ID QUIC hands us next."""
        assert self._quic is not None
        return self._quic.get_next_available_stream_id()

    async def close(self) -> None:
        if self._quic is not None and not self._closed:
            self._quic.close()
            await self._flush_out()
        self._closed = True


# -------- Peer authentication over QUIC --------

CHALLENGE_SIZE = 32
AUTH_STREAM_ID = None  # set to 0 below; first bidirectional stream
AUTH_TIMEOUT = 5.0


async def authenticate_peer(
    quic_peer: QuicPeer,
    our_priv,
    expected_peer_pubkey: bytes,
) -> bool:
    """
    Prove mutual possession of the X25519 keys agreed via Rendezvous.

    Both sides derive an auth secret from ECDH (re-using the P2P keys).
    Each sends a challenge; each responds with HMAC(auth_secret, challenge).
    If both HMACs verify, we're talking to the right peer.

    This is simpler and stronger than just trusting QUIC's TLS cert (which
    is self-signed and not identity-bound).
    """
    import hmac, hashlib

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    peer_pub_obj = X25519PublicKey.from_public_bytes(expected_peer_pubkey)
    auth_key = crypto.derive_shared_key(our_priv, peer_pub_obj, info=b"p2p-auth v1")

    # Use a dedicated stream. Stream 0 is bidirectional in QUIC.
    # Both sides can open streams; using next_available keeps it clean.
    stream_id = quic_peer.get_next_stream_id()

    # Send our challenge.
    our_challenge = os.urandom(CHALLENGE_SIZE)
    quic_peer.send_stream(stream_id, our_challenge, end_stream=False)

    # We'll receive peer's challenge and peer's response to ours.
    # To keep this simple, buffer incoming stream data and parse:
    #   first 32 bytes = peer's challenge
    #   next 32 bytes  = peer's HMAC of our challenge
    buf = bytearray()
    got_auth: asyncio.Future = asyncio.get_running_loop().create_future()

    async def on_data(sid: int, data: bytes, end_stream: bool):
        if sid != stream_id:
            return  # future streams belong to the app layer
        buf.extend(data)
        if len(buf) >= CHALLENGE_SIZE * 2 and not got_auth.done():
            got_auth.set_result(True)

    quic_peer.on_stream_data = on_data

    # Send our response to peer's challenge as soon as we see it.
    try:
        await asyncio.wait_for(got_auth, AUTH_TIMEOUT)
    except asyncio.TimeoutError:
        log.error("Auth: peer did not send challenge+response within %.1fs", AUTH_TIMEOUT)
        return False

    peer_challenge = bytes(buf[:CHALLENGE_SIZE])
    peer_response = bytes(buf[CHALLENGE_SIZE : CHALLENGE_SIZE * 2])

    # Verify peer's HMAC of our challenge.
    expected = hmac.new(auth_key, our_challenge, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, peer_response):
        log.error("Auth: peer's HMAC does not verify")
        return False

    # Send our HMAC of peer's challenge.
    our_response = hmac.new(auth_key, peer_challenge, hashlib.sha256).digest()
    quic_peer.send_stream(stream_id, our_response, end_stream=True)

    # Give the peer time to receive before we clear the callback.
    await asyncio.sleep(0.2)
    quic_peer.on_stream_data = None
    log.info("Peer authentication succeeded")
    return True
