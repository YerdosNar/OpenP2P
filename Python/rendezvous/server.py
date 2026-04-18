import asyncio
import json
import logging
import os
from typing import Optional

from common import crypto
from common.channel import EncryptedChannel
from common.protocol import (
    MsgType, frame, read_frame, encode, decode,
)
from rendezvous.room import RoomRegistry
from rendezvous.udp_observer import start_udp_observer, UDPObserver, NONCE_SIZE

log = logging.getLogger("rendezvous")

ROLE_PROMPT = "Are you [H]ost or [J]oin [h/j]: "


class RendezvousServer:
    OBSERVE_TIMEOUT_SECONDS = 3.0

    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self._host = host
        self._port = port
        self._registry = RoomRegistry()
        self._server = None
        self._udp_observer: Optional[UDPObserver] = None
        self._udp_transport = None

    async def serve_forever(self) -> None:
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

    async def _observe_peer_udp(self, channel: EncryptedChannel, peername):
        assert self._udp_observer is not None

        nonce = os.urandom(NONCE_SIZE)
        future = self._udp_observer.register_nonce(nonce)

        await channel.send_msg(MsgType.OBSERVE_REQUEST, nonce)

        try:
            ip, port = await asyncio.wait_for(future, self.OBSERVE_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            self._udp_observer.cancel_nonce(nonce)
            log.warning("%s: UDP probe did not arrive within %.1fs",
                        peername, self.OBSERVE_TIMEOUT_SECONDS)
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "UDP observation failed; cannot hole punch"}).encode("utf-8"),
            )
            return None

        log.info("%s: observed UDP endpoint %s:%d", peername, ip, port)

        await channel.send_msg(
            MsgType.OBSERVED_ADDR,
            json.dumps({"ip": ip, "port": port}).encode("utf-8"),
        )
        return (ip, port)

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peername = writer.get_extra_info("peername")
        log.info("New connection from %s", peername)

        server_priv, server_pub = crypto.generate_keypair()

        try:
            peer_hello = await read_frame(reader)
            msg_type, body = decode(peer_hello)
            if msg_type != MsgType.HELLO or len(body) != 32:
                log.warning("%s sent bad HELLO; closing", peername)
                return
            peer_pub = crypto.deserialize_public_key(body)

            our_hello = encode(MsgType.HELLO, crypto.serialize_public_key(server_pub))
            writer.write(frame(our_hello))
            await writer.drain()

            shared_key = crypto.derive_shared_key(
                server_priv, peer_pub, info=b"rendezvous v1"
            )
            channel = EncryptedChannel(reader, writer, shared_key)
            log.info("%s: encrypted channel established", peername)

            observed = await self._observe_peer_udp(channel, peername)
            if observed is None:
                return
            observed_ip, observed_port = observed

            await channel.send_msg(
                MsgType.ROLE_SELECT, ROLE_PROMPT.encode("utf-8")
            )
            msg_type, body = await channel.recv_msg()
            if msg_type != MsgType.ROLE_SELECT:
                log.warning("%s: expected ROLE_SELECT reply, got %s", peername, msg_type)
                return

            role = body.decode("utf-8").strip().lower()
            if role == "h":
                await self._handle_host_session(
                    channel, peername, observed_ip, observed_port)
            elif role == "j":
                await self._handle_joiner_session(
                    channel, peername, observed_ip, observed_port)
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

    async def _handle_host_session(
        self, channel: EncryptedChannel, peername,
        observed_ip: str, observed_port: int,
    ) -> None:
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
            host_pubkey = bytes.fromhex(payload["pubkey"])
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
        log.info("Host %s created room %r (ttl=180s)", peername, room_id)

        await channel.send_msg(
            MsgType.ROOM_RESULT,
            json.dumps({"ok": True, "waiting_seconds": 180}).encode("utf-8"),
        )

        try:
            joiner_info = await room.joiner_arrived
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            log.info("Room %r: host %s timed out waiting", room_id, peername)
            await channel.send_msg(
                MsgType.ERROR,
                json.dumps({"reason": "timeout: no joiner within 3 minutes"}).encode("utf-8"),
            )
            return

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

        self._registry.remove_host(room_id)

    async def _handle_joiner_session(
        self, channel: EncryptedChannel, peername,
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
