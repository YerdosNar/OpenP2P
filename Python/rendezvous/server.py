"""
The Rendezvous server.

Listens for TCP connections from peers. For each peer:
  1. Exchanges X25519 public keys (plaintext HELLO).
  2. Derives a shared key and establishes an encrypted channel.
  3. Drives the host-or-join flow, using RoomRegistry as the meeting point.

The server does NOT speak QUIC. Peers speak QUIC only to each other,
after Rendezvous has brokered the introduction.
"""

import asyncio
import json
import logging
import os
from typing import Optional

from common import crypto
from common.channel import EncryptedChannel
from common.protocol import (
    MsgType, frame, read_frame, encode,
)
from rendezvous.room import RoomRegistry
from rendezvous.udp_observer import start_udp_observer, UDPObserver, NONCE_SIZE

log = logging.getLogger("rendezvous")

# Your spec's exact prompt text.
ROLE_PROMPT = "Are you [H]ost or [J]oin [h/j]: "


class RendezvousServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self._host = host
        self._port = port
        self._registry = RoomRegistry()
        self._server: Optional[asyncio.base_events.Server] = None
        self._udp_observer: Optional[UDPObserver] = None
        self._udp_transport: Optional[asyncio.DatagramTransport] = None

    async def serve_forever(self) -> None:
        # Start UDP observer first so it's ready when the first peer arrives.
        self._udp_observer, self._udp_transport = await start_udp_observer(
            self._host, self._port
        )

        self._server = await asyncio.start_server(
            self._handle_connection, self._host, self._port
        )
        for s in (self._server.sockets or []):
            log.info("Rendezvous TCP listening on %s", s.getsockname())

        try:
            async with self._server:
                await self._server.serve_forever()
        finally:
            if self._udp_transport is not None:
                self._udp_transport.close()


    # -------- UDP endpoint observation --------

    OBSERVE_TIMEOUT_SECONDS = 3.0

    async def _observe_peer_udp(
        self, channel: EncryptedChannel, peername: tuple
    ) -> Optional[tuple[str, int]]:
        """
        Ask the peer to send a UDP probe so we can observe their NAT-translated
        UDP endpoint. Returns (ip, port) or None on failure (peer already sent
        ERROR to itself via the outer handler if needed).
        """
        assert self._udp_observer is not None

        nonce = os.urandom(NONCE_SIZE)
        future = self._udp_observer.register_nonce(nonce)

        # Tell the peer: send a UDP probe containing this nonce.
        await channel.send_msg(MsgType.OBSERVE_REQUEST, nonce)

        try:
            ip, port = await asyncio.wait_for(future, self.OBSERVE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            self._udp_observer.cancel_nonce(nonce)
            log.warning("%s: UDP probe did not arrive within %.1fs",
                        peername, self.OBSERVE_TIMEOUT_SECONDS)
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "UDP observation failed; cannot hole punch"})
                    .encode("utf-8"),
            )
            return None

        log.info("%s: observed UDP endpoint %s:%d", peername, ip, port)

        # Inform the peer of what we saw. Not strictly required for the
        # protocol to work, but useful for the peer's logs and diagnostics.
        await channel.send_msg(
            MsgType.OBSERVED_ADDR,
            json.dumps({"ip": ip, "port": port}).encode("utf-8"),
        )
        return (ip, port)

    # -------- Per-connection handler --------

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername")
        log.info("New connection from %s", peername)

        # Each session gets its own ephemeral keypair — forward secrecy for free.
        server_priv, server_pub = crypto.generate_keypair()

        try:
            # ---- Step 1-2: HELLO exchange (plaintext) ----
            peer_hello = await read_frame(reader)
            from common.protocol import decode
            msg_type, body = decode(peer_hello)
            if msg_type != MsgType.HELLO or len(body) != 32:
                log.warning("%s sent bad HELLO; closing", peername)
                return
            peer_pub = crypto.deserialize_public_key(body)

            our_hello = encode(MsgType.HELLO, crypto.serialize_public_key(server_pub))
            writer.write(frame(our_hello))
            await writer.drain()

            # ---- Step 3-4: derive key, open encrypted channel ----
            shared_key = crypto.derive_shared_key(
                server_priv, peer_pub, info=b"rendezvous v1"
            )
            channel = EncryptedChannel(reader, writer, shared_key)
            log.info("%s: encrypted channel established", peername)

            # ---- NEW: UDP observation ----
            observed = await self._observe_peer_udp(channel, peername)
            if observed is None:
                return
            observed_ip, observed_port = observed

            # ---- Step 5-6: ask host or joiner ----
            await channel.send_msg(
                MsgType.ROLE_SELECT, ROLE_PROMPT.encode("utf-8")
            )
            msg_type, body = await channel.recv_msg()
            if msg_type != MsgType.ROLE_SELECT:
                log.warning("%s: expected ROLE_SELECT reply, got %s", peername, msg_type)
                return

            role = body.decode("utf-8").strip().lower()
            if role == "h":
                await self._handle_host_session(channel, peername, observed_ip, observed_port)
            elif role == "j":
                await self._handle_joiner_session(channel, peername, observed_ip, observed_port)
            else:
                await channel.send_msg(
                    MsgType.ERROR,
                    json.dumps({"reason": f"unknown role {role!r}"}).encode("utf-8"),
                )

        except asyncio.IncompleteReadError:
            log.info("%s: disconnected mid-handshake", peername)
        except Exception:
            log.exception("%s: error in session", peername)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            log.info("%s: connection closed", peername)

    # -------- Host flow --------

    async def _handle_host_session(
        self, channel: EncryptedChannel, peername: tuple,
        observed_ip: str, observed_port: int,
    ) -> None:
        # Expect ROOM_CREATE.
        msg_type, body = await channel.recv_msg()
        if msg_type != MsgType.ROOM_CREATE:
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "expected ROOM_CREATE"}).encode("utf-8"),
            )
            return

        try:
            payload = json.loads(body.decode("utf-8"))
            room_id = str(payload["room_id"])
            room_pw = str(payload["room_pw"])
            host_pubkey = bytes.fromhex(payload["pubkey"])  # P2P pubkey (hex)
        except (KeyError, ValueError, TypeError) as e:
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": f"malformed ROOM_CREATE: {e}"}).encode("utf-8"),
            )
            return

        try:
            room = self._registry.create_room(
                room_id=room_id,
                room_pw=room_pw,
                host_pubkey=host_pubkey,
                host_ip=observed_ip,
                host_port=observed_port,
            )
        except KeyError:
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "room_id already in use"}).encode("utf-8"),
            )
            return
        except ValueError as e:
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": str(e)}).encode("utf-8"),
            )
            return

        self._registry.schedule_timeout(room)
        log.info("Host %s created room %r (ttl=%.0fs)", peername, room_id, 180.0)

        # Confirm room created, then await joiner.
        await channel.send_msg(
            MsgType.ROOM_RESULT,
            json.dumps({"ok": True, "waiting_seconds": 180}).encode("utf-8"),
        )

        try:
            joiner_info = await room.joiner_arrived
        except asyncio.CancelledError:
            raise  # Let the outer handler log and clean up.
        except TimeoutError:
            log.info("Room %r: host %s timed out waiting", room_id, peername)
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "timeout: no joiner within 3 minutes"}).encode("utf-8"),
            )
            return

        # Push PEER_INFO to the host.
        await channel.send_msg(
            MsgType.PEER_INFO,
            json.dumps({
                "ip": joiner_info["ip"],
                "port": joiner_info["port"],
                "pubkey": joiner_info["pubkey"].hex(),
            }).encode("utf-8"),
        )
        log.info("Room %r: host notified of joiner %s:%d",
                 room_id, joiner_info["ip"], joiner_info["port"])

        # On exit, ensure the room is gone (try_join already did, but be defensive).
        self._registry.remove_host(room_id)

    # -------- Joiner flow --------

    async def _handle_joiner_session(
        self, channel: EncryptedChannel, peername: tuple,
        observed_ip: str, observed_port: int,
    ) -> None:
        msg_type, body = await channel.recv_msg()
        if msg_type != MsgType.ROOM_JOIN:
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "expected ROOM_JOIN"}).encode("utf-8"),
            )
            return

        try:
            payload = json.loads(body.decode("utf-8"))
            room_id = str(payload["room_id"])
            room_pw = str(payload["room_pw"])
            joiner_pubkey = bytes.fromhex(payload["pubkey"])
        except (KeyError, ValueError, TypeError) as e:
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": f"malformed ROOM_JOIN: {e}"}).encode("utf-8"),
            )
            return

        result = self._registry.try_join(
            room_id=room_id,
            candidate_pw=room_pw,
            joiner_pubkey=joiner_pubkey,
            joiner_ip=observed_ip,
            joiner_port=observed_port,
        )
        if result is None:
            log.info("Joiner %s: failed to join %r (no room or bad pw)",
                     peername, room_id)
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "no matching room (wrong id or pw)"}).encode("utf-8"),
            )
            return

        # Send the host's info to the joiner.
        await channel.send_msg(
            MsgType.ROOM_RESULT,
            json.dumps({
                "ok": True,
                "ip": result.host_ip,
                "port": result.host_port,
                "pubkey": result.host_pubkey.hex(),
            }).encode("utf-8"),
        )
        log.info("Joiner %s matched room %r with host %s:%d",
                 peername, room_id, result.host_ip, result.host_port)


# -------- Entry point --------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    server = RendezvousServer()
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        log.info("Shutting down.")


if __name__ == "__main__":
    main()
