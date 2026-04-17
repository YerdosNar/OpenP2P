import asyncio
import os
import socket
from common import crypto
from common.protocol import MsgType, frame, read_frame, encode, decode
from common.socket_utils import create_reusable_udp_socket


async def smoke():
    # 1. TCP connect + HELLO exchange
    reader, writer = await asyncio.open_connection("127.0.0.1", 9999)
    priv, pub = crypto.generate_keypair()
    writer.write(frame(encode(MsgType.HELLO, crypto.serialize_public_key(pub))))
    await writer.drain()

    server_hello = await read_frame(reader)
    mt, body = decode(server_hello)
    assert mt == MsgType.HELLO
    server_pub = crypto.deserialize_public_key(body)
    key = crypto.derive_shared_key(priv, server_pub, info=b"rendezvous v1")
    print("Encrypted channel established")

    # 2. Expect OBSERVE_REQUEST
    ct = await read_frame(reader)
    mt, body = decode(crypto.decrypt(key, ct))
    assert mt == MsgType.OBSERVE_REQUEST
    nonce = body
    assert len(nonce) == 16
    print(f"Got observation nonce: {nonce.hex()[:16]}...")

    # 3. Open a UDP socket and send the probe
    udp_sock = create_reusable_udp_socket()
    local_udp_port = udp_sock.getsockname()[1]
    print(f"Sending probe from local UDP port {local_udp_port}")
    udp_sock.sendto(nonce, ("127.0.0.1", 9999))

    # 4. Expect OBSERVED_ADDR on the TCP channel
    ct = await read_frame(reader)
    mt, body = decode(crypto.decrypt(key, ct))
    assert mt == MsgType.OBSERVED_ADDR
    import json
    observed = json.loads(body.decode())
    print(f"Server observed us at {observed['ip']}:{observed['port']}")
    # On loopback, the observed port should equal our local port
    assert observed["port"] == local_udp_port, \
        f"expected {local_udp_port}, got {observed['port']}"
    print("UDP observation matched local port: SUCCESS")

    # 5. Expect the ROLE prompt
    ct = await read_frame(reader)
    mt, body = decode(crypto.decrypt(key, ct))
    assert mt == MsgType.ROLE_SELECT
    print(f"Role prompt: {body.decode()!r}")

    writer.close()
    await writer.wait_closed()
    udp_sock.close()


asyncio.run(smoke())
