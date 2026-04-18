"""
Peer client - Rendezvous side.

Drives the peer's interaction with the Rendezvous server, ending with the
peer having learned the other peer's (IP, port, public key) and holding
an open UDP socket whose NAT mapping is still alive.
"""

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
    MsgType, frame, read_frame, encode, decode
)
from common.socket_utils import (
    create_reusable_udp_socket, get_local_endpoint, nat_keepalive_loop
)

log = logging.getLogger("peer")

@dataclass
class PeerHandoff:
    """Everything we need to start QUIC hole-punching with the other peer."""
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


# Tunables
PROBE_RETRIES = 5
PROBE_INTERVAL = 0.2


class PeerClient:
    def __init__(self, rendezvous_host: str, rendezvous_port: int):
        self._rz_host = rendezvous_host
        self._rz_port = rendezvous_port


    async def run(self) -> Optional[PeerHandoff]:
        """
        Execute Rendezvous flow:
        On success: returns PeerHandoff
        On failure: return None
        """
        # 1. Create P2P keypair. Ephemeral - regenerated
        # every run, giving us forward secrecy.
        p2p_priv, p2p_pub = crypto.generate_keypair()

        # 2. Create UDP socket we'll keep for the whole P2P lifetime
        udp_sock = create_reusable_udp_socket()
        local_host, local_port = get_local_endpoint(udp_sock)
        log.info("UDP socket bound to %s:%d", local_host, local_port)

        # 3. TCP connect to Rendezvous and do handshake
        try:
            reader, writer = await asyncio.open_connection(
                self._rz_host, self._rz_port
            )
        except OSError as e:
            log.error("Cannot connect to Rendezvous %s:%d - %s",
                      self._rz_host, self._rz_port, e)
            udp_sock.close()
            return None

        channel = None
        keepalive_task = None
        try:
            channel = await self._handshake(reader, writer)
            if channel is None:
                return None
            # 4. Handle the OBSERVE_REQUEST - fire UDP probes until the server
            #    sends back OBSERVED_ADDR (or ERROR)
            observed = await self._handle_observe(channel, udp_sock)
            if observed is None:
                return None
            observed_ip, observed_port = observed
            log.info("Rendezvous observed us at %s:%d", observed_ip, observed_port)

            # Now we need to keep NAT hole to Rendezvous alive
            # Just in case slow user input or unexptected slows
            keepalive_task = asyncio.create_task(
                nat_keepalive_loop(udp_sock, (self._rz_host, self._rz_port))
            )

            # 5. Read the role prompt and ask user.
            mt, body = await channel.recv_msg()
            if mt != MsgType.ROLE_SELECT:
                log.error("Expected ROLE_SELECT prompt, got %s", mt)
                return None
            prompt_text = body.decode("utf-8")

            role = await asyncio.to_thread(input, prompt_text)
            role = role.strip().lower()
            if role not in ("h", "j"):
                log.error("Invalid role %r - must be 'h' or 'j'", role)
                await channel.send_msg(MsgType.ROLE_SELECT, role.encode("utf-8"))
                return None
            await channel.send_msg(MsgType.ROLE_SELECT, role.encode("utf-8"))

            # 6. Branch on role.
            if role == "h":
                peer_info = await self._run_host_flow(channel, p2p_pub)
            else:
                peer_info = await self._run_joiner_flow(channel, p2p_pub)

            if peer_info is None:
                return None

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
                is_host=(role == "h"),
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

    # Handshake helpers
    async def _handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> Optional[EncryptedChannel]:
        """Do the plaintext HELLO exchange and return an EncryptedChannel"""
        rz_priv, rz_pub = crypto.generate_keypair()

        # Send our HELLO.
        writer.write(frame(encode(MsgType.HELLO, crypto.serialize_public_key(rz_pub))))
        await writer.drain()

        # REad server's HELLO
        payload = await read_frame(reader)
        mt, body = decode(payload)
        if mt != MsgType.HELLO or len(body) != 32:
            log.error("Server HELLO malformed")
            return None

        server_pub = crypto.deserialize_public_key(body)
        shared_key = crypto.derive_shared_key(rz_priv, server_pub, info=b"rendezvous v1")
        log.info("Encrypted channel to Rendezvous established")
        return EncryptedChannel(reader, writer, shared_key)


    async def _handle_observe(
        self,
        channel: EncryptedChannel,
        udp_sock: socket.socket
    ) -> Optional[tuple[str, int]]:
        """Handle the OBSERVE_REQUEST/OBSERVED_ADDR exchange"""
        mt, body = await channel.recv_msg()
        if mt != MsgType.OBSERVE_REQUEST:
            log.error("Expected OBSERVE_REQUEST, got %s", mt)
            return None
        nonce = body
        if len(nonce) != 16:
            log.error("OBSERVE_REQUEST nonce wrong size: %d", len(nonce))
            return None

        # Fire off retries while waiting for OBSERVED_ADDR on TCP
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
            try:
                reason = json.loads(body.decode()).get("reason", body.decode())
            except Exception:
                reason = body.decode(errors="replace")
            log.error("Rendezvous: %s", reason)
            return None

        if mt != MsgType.OBSERVED_ADDR:
            log.error("Expected OBSERVED_ADDR, got %s", mt)
            return None

        obs = json.loads(body.decode())
        return obs["ip"], int(obs["port"])


    async def _run_host_flow(
        self, channel: EncryptedChannel, p2p_pub
    ) -> Optional[dict]:
        room_id = await asyncio.to_thread(input, "Enter HostRoom ID: ")
        room_pw = await asyncio.to_thread(input, "Enter HostRoom PW: ")

        await channel.send_msg(
            MsgType.ROOM_CREATE,
            json.dumps({
                "room_id": room_id.strip(),
                "room_pw": room_pw.strip(),
                "pubkey": crypto.serialize_public_key(p2p_pub).hex(),
            }).encode("utf-8")
        )

        # First reply: ROOM_RESULT (room created OK) or ERROR.
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

        # Seconds reply: PEER_INFO (joiner arrived) or ERROR (timeout)
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


    # Joiner flow
    async def _run_joiner_flow(
        self, channel: EncryptedChannel, p2p_pub
    ) -> Optional[dict]:
        room_id = await asyncio.to_thread(input, "Enter HostRoom ID: ")
        room_pw = await asyncio.to_thread(input, "Enter HostRoom PW: ")

        await channel.send_msg(
            MsgType.ROOM_JOIN,
            json.dumps({
                "room_id": room_id.strip(),
                "room_pw": room_pw.strip(),
                "pubkey" : crypto.serialize_public_key(p2p_pub).hex(),
            }).encode("utf-8")
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
    """Extraction of ERROR message reason"""
    try:
        return json.loads(body.decode()).get("reason", body.decode())
    except Exception:
        return body.decode(errors="replace")


async def _main(rendezvous_host: str, rendezvous_port: int):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    client = PeerClient(rendezvous_host, rendezvous_port)
    handoff = await client.run()
    if handoff is None:
        print("\nRendezvous failed. Exiting.")
        sys.exit(1)

    print("\n=== Rendezvous complete ===")
    print(f"    Our observed endpoint:  {handoff.our_observed_ip}:{handoff.our_observed_port}")
    print(f"    Peer endpoint:          {handoff.peer_ip}:{handoff.peer_port}")
    print(f"    Peer public key:        {handoff.peer_pubkey.hex()[:32]}...")
    print("\n(Needed to open a QUIC connection to the peer)")

    from peer.p2p import punch_hole, QuicPeer

    peer_addr = (handoff.peer_ip, handoff.peer_port)

    # Phase 1: simultaneous hole punching.
    await punch_hole(handoff.udp_socket, peer_addr, is_host=handoff.is_host)

    # Phase 2: QUIC handshake.
    quic_peer = QuicPeer(handoff.udp_socket, peer_addr, is_host=handoff.is_host)
    run_task = asyncio.create_task(quic_peer.run())

    ok = await quic_peer.wait_handshake(timeout=10.0)
    if not ok:
        print("QUIC handshake timed out.")
        run_task.cancel()
        return

    print("QUIC connection established!")

    # Minimal hello-world: open a stream, exchange one message each way.
    stream_id = quic_peer.get_next_stream_id()
    greeting = f"Hello from {'host' if handoff.is_host else 'joiner'}!".encode()

    async def on_data(sid, data, end):
        print(f"Received on stream {sid}: {data.decode(errors='replace')!r}")

    quic_peer.on_stream_data = on_data
    quic_peer.send_stream(stream_id, greeting, end_stream=False)

    # Let the connection live for a few seconds to exchange messages.
    await asyncio.sleep(5)
    await quic_peer.close()
    run_task.cancel()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True, help="Rendezvous server host")
    parser.add_argument("--port", type=int, default=8888, help="Rendezvous server port")
    args = parser.parse_args()
    asyncio.run(_main(args.host, args.port))


if __name__ == "__main__":
    main()
