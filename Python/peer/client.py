"""Interactive peer client:

  1. TCP-connect to the rendezvous server, do HELLO + X25519 handshake.
  2. Rendezvous observes our public UDP endpoint via a nonce probe.
  3. User picks host/joiner, gives room ID + password.
  4. Rendezvous exchanges (ip, port, pubkey) between the two peers.
  5. UDP hole-punch toward peer.
  6. QUIC handshake over the punched socket (host = QUIC server).
  7. Session: mutual HMAC auth, then chat + file transfer."""
import asyncio
import json
import logging
import socket
import sys
from dataclasses import dataclass
from typing import Optional

from common import crypto
from common.channel import EncryptedChannel
from common.protocol import (
    MsgType, frame, read_frame, encode, decode,
)
from common.socket_utils import (
    create_reusable_udp_socket, get_local_endpoint, nat_keepalive_loop,
)

log = logging.getLogger("peer")


@dataclass
class PeerHandoff:
    udp_socket: socket.socket
    our_local_port: int
    our_observed_ip: str
    our_observed_port: int
    peer_ip: str
    peer_port: int
    peer_pubkey: bytes
    our_priv: object
    our_pub: object
    is_host: bool


PROBE_RETRIES = 5
PROBE_INTERVAL = 0.2


class PeerClient:
    def __init__(self, rendezvous_host: str, rendezvous_port: int):
        self._rz_host = rendezvous_host
        self._rz_port = rendezvous_port

    async def run(self) -> Optional[PeerHandoff]:
        # Keypair used for end-to-end identity with the *peer*.
        p2p_priv, p2p_pub = crypto.generate_keypair()

        udp_sock = create_reusable_udp_socket()
        local_host, local_port = get_local_endpoint(udp_sock)
        log.info("UDP socket bound to %s:%d", local_host, local_port)

        try:
            reader, writer = await asyncio.open_connection(
                self._rz_host, self._rz_port
            )
        except OSError as e:
            log.error("Cannot connect to Rendezvous %s:%d -- %s",
                      self._rz_host, self._rz_port, e)
            udp_sock.close()
            return None

        keepalive_task = None
        success = False
        try:
            channel = await self._handshake(reader, writer)
            if channel is None:
                return None

            observed = await self._handle_observe(channel, udp_sock)
            if observed is None:
                return None
            observed_ip, observed_port = observed
            log.info("Rendezvous observed us at %s:%d",
                     observed_ip, observed_port)

            # Keep the NAT mapping alive toward the rendezvous while we're
            # deciding on role / waiting for a peer.
            keepalive_task = asyncio.create_task(
                nat_keepalive_loop(udp_sock, (self._rz_host, self._rz_port))
            )

            mt, body = await channel.recv_msg()
            if mt != MsgType.ROLE_SELECT:
                log.error("Expected ROLE_SELECT prompt, got %s", mt)
                return None
            prompt_text = body.decode("utf-8")

            role = await asyncio.to_thread(input, prompt_text)
            role = role.strip().lower()
            if role not in ("h", "j"):
                log.error("Invalid role %r -- must be 'h' or 'j'", role)
                await channel.send_msg(
                    MsgType.ROLE_SELECT, role.encode("utf-8")
                )
                return None
            await channel.send_msg(
                MsgType.ROLE_SELECT, role.encode("utf-8")
            )

            is_host = (role == "h")
            if is_host:
                peer_info = await self._run_host_flow(channel, p2p_pub)
            else:
                peer_info = await self._run_joiner_flow(channel, p2p_pub)

            if peer_info is None:
                return None

            success = True
            return PeerHandoff(
                udp_socket=udp_sock,
                our_local_port=local_port,
                our_observed_ip=observed_ip,
                our_observed_port=observed_port,
                peer_ip=peer_info["ip"],
                peer_port=peer_info["port"],
                peer_pubkey=peer_info["pubkey"],
                our_priv=p2p_priv,
                our_pub=p2p_pub,
                is_host=is_host,
            )

        finally:
            if keepalive_task is not None:
                keepalive_task.cancel()
                try:
                    await keepalive_task
                except asyncio.CancelledError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if not success:
                udp_sock.close()

    async def _handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> Optional[EncryptedChannel]:
        rz_priv, rz_pub = crypto.generate_keypair()
        writer.write(frame(
            encode(MsgType.HELLO, crypto.serialize_public_key(rz_pub))
        ))
        await writer.drain()

        payload = await read_frame(reader)
        mt, body = decode(payload)
        if mt != MsgType.HELLO or len(body) != 32:
            log.error("Server HELLO malformed")
            return None

        server_pub = crypto.deserialize_public_key(body)
        shared_key = crypto.derive_shared_key(
            rz_priv, server_pub, info=b"rendezvous v1"
        )
        log.info("Encrypted channel to Rendezvous established")
        return EncryptedChannel(reader, writer, shared_key)

    async def _handle_observe(
        self, channel: EncryptedChannel, udp_sock: socket.socket
    ):
        mt, body = await channel.recv_msg()
        if mt != MsgType.OBSERVE_REQUEST:
            log.error("Expected OBSERVE_REQUEST, got %s", mt)
            return None
        nonce = body
        if len(nonce) != 16:
            log.error("OBSERVE_REQUEST nonce wrong size: %d", len(nonce))
            return None

        async def probe_sender():
            loop = asyncio.get_running_loop()
            for _ in range(PROBE_RETRIES):
                try:
                    await loop.sock_sendto(
                        udp_sock, nonce, (self._rz_host, self._rz_port)
                    )
                except OSError as e:
                    log.warning("Probe send failed: %s", e)
                    return
                await asyncio.sleep(PROBE_INTERVAL)

        sender_task = asyncio.create_task(probe_sender())
        try:
            mt, body = await channel.recv_msg()
        finally:
            sender_task.cancel()
            try:
                await sender_task
            except asyncio.CancelledError:
                pass

        if mt == MsgType.ERROR:
            log.error("Rendezvous: %s", _reason(body))
            return None
        if mt != MsgType.OBSERVED_ADDR:
            log.error("Expected OBSERVED_ADDR, got %s", mt)
            return None

        obs = json.loads(body.decode())
        return obs["ip"], int(obs["port"])

    async def _run_host_flow(
        self, channel: EncryptedChannel, p2p_pub
    ):
        room_id = await asyncio.to_thread(input, "Enter HostRoom ID: ")
        room_pw = await asyncio.to_thread(input, "Enter HostRoom PW: ")

        await channel.send_msg(
            MsgType.ROOM_CREATE,
            json.dumps({
                "room_id": room_id.strip(),
                "room_pw": room_pw.strip(),
                "pubkey": crypto.serialize_public_key(p2p_pub).hex(),
            }).encode("utf-8"),
        )

        mt, body = await channel.recv_msg()
        if mt == MsgType.ERROR:
            log.error("Host: %s", _reason(body))
            return None
        if mt != MsgType.ROOM_RESULT:
            log.error("Host: expected ROOM_RESULT, got %s", mt)
            return None

        result = json.loads(body.decode())
        wait_s = int(result.get("waiting_seconds", 180))
        print(f"Room created. Waiting up to {wait_s} seconds for a joiner...")

        mt, body = await channel.recv_msg()
        if mt == MsgType.ERROR:
            log.error("Host: %s", _reason(body))
            return None
        if mt != MsgType.PEER_INFO:
            log.error("Host: expected PEER_INFO, got %s", mt)
            return None

        info = json.loads(body.decode())
        return {
            "ip": info["ip"],
            "port": int(info["port"]),
            "pubkey": bytes.fromhex(info["pubkey"]),
        }

    async def _run_joiner_flow(
        self, channel: EncryptedChannel, p2p_pub
    ):
        room_id = await asyncio.to_thread(input, "Enter HostRoom ID: ")
        room_pw = await asyncio.to_thread(input, "Enter HostRoom PW: ")

        await channel.send_msg(
            MsgType.ROOM_JOIN,
            json.dumps({
                "room_id": room_id.strip(),
                "room_pw": room_pw.strip(),
                "pubkey": crypto.serialize_public_key(p2p_pub).hex(),
            }).encode("utf-8"),
        )

        mt, body = await channel.recv_msg()
        if mt == MsgType.ERROR:
            log.error("Joiner: %s", _reason(body))
            return None
        if mt != MsgType.ROOM_RESULT:
            log.error("Joiner: expected ROOM_RESULT, got %s", mt)
            return None

        result = json.loads(body.decode())
        return {
            "ip": result["ip"],
            "port": int(result["port"]),
            "pubkey": bytes.fromhex(result["pubkey"]),
        }


def _reason(body: bytes) -> str:
    try:
        return json.loads(body.decode()).get("reason", body.decode())
    except Exception:
        return body.decode(errors="replace")


async def _main(rendezvous_host: str, rendezvous_port: int):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("quic").setLevel(logging.WARNING)
    logging.getLogger("aioquic").setLevel(logging.WARNING)

    client = PeerClient(rendezvous_host, rendezvous_port)
    handoff = await client.run()
    if handoff is None:
        print("\nRendezvous failed. Exiting.")
        sys.exit(1)

    print("\n=== Rendezvous complete ===")
    print(f"  Our observed endpoint: "
          f"{handoff.our_observed_ip}:{handoff.our_observed_port}")
    print(f"  Peer endpoint:         {handoff.peer_ip}:{handoff.peer_port}")
    print(f"  Peer public key:       {handoff.peer_pubkey.hex()[:32]}...")
    print(f"  Our role:              "
          f"{'HOST (QUIC server)' if handoff.is_host else 'JOINER (QUIC client)'}")

    from peer.p2p import punch_hole, QuicPeer
    from peer.session import Session

    peer_addr = (handoff.peer_ip, handoff.peer_port)

    print("\n=== Hole punching ===")
    await punch_hole(
        handoff.udp_socket, peer_addr, is_host=handoff.is_host
    )

    print("\n=== Starting QUIC ===")
    quic_peer = QuicPeer(
        handoff.udp_socket, peer_addr, is_host=handoff.is_host
    )
    # IMPORTANT: construct Session *before* waiting for handshake so the
    # on_stream_data callback is wired up immediately. QuicPeer also buffers
    # any pre-registration stream data as a belt-and-braces measure.
    session = Session(
        quic_peer,
        handoff.our_priv,
        handoff.peer_pubkey,
        is_host=handoff.is_host,
    )

    run_task = asyncio.create_task(quic_peer.run())

    print("Waiting for QUIC handshake (up to 15s)...")
    ok = await quic_peer.wait_handshake(timeout=15.0)
    if not ok:
        print("\n!!! QUIC handshake TIMED OUT !!!")
        await quic_peer.close()
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass
        handoff.udp_socket.close()
        return

    print("\n*** QUIC connection established! ***\n")

    print("Authenticating peer...")
    auth_ok = await session.authenticate()
    if not auth_ok:
        print("\n!!! Peer authentication FAILED !!!")
        await quic_peer.close()
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass
        handoff.udp_socket.close()
        return

    print("*** Peer authenticated. ***")

    try:
        await session.run_chat_ui()
    except (KeyboardInterrupt, EOFError):
        print("\n[interrupted]")
    finally:
        await session.send_bye()
        await asyncio.sleep(0.3)
        await quic_peer.close()
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass
        handoff.udp_socket.close()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True,
                        help="Rendezvous server host")
    parser.add_argument("--port", type=int, default=8888,
                        help="Rendezvous server port (default 8888)")
    args = parser.parse_args()
    try:
        asyncio.run(_main(args.host, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
