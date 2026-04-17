# test_rendezvous_smoke.py
import asyncio
import struct
from common import crypto
from common.protocol import MsgType, frame, read_frame, encode, decode

async def smoke():
    reader, writer = await asyncio.open_connection("127.0.0.1", 9999)

    # Send HELLO
    priv, pub = crypto.generate_keypair()
    hello = encode(MsgType.HELLO, crypto.serialize_public_key(pub))
    writer.write(frame(hello))
    await writer.drain()

    # Read server's HELLO
    server_hello = await read_frame(reader)
    mt, body = decode(server_hello)
    assert mt == MsgType.HELLO and len(body) == 32
    print(f"Got server pubkey: {body.hex()[:16]}...")

    # Derive shared key
    server_pub = crypto.deserialize_public_key(body)
    key = crypto.derive_shared_key(priv, server_pub, info=b"rendezvous v1")

    # Receive the encrypted role prompt
    ct = await read_frame(reader)
    pt = crypto.decrypt(key, ct)
    mt, body = decode(pt)
    assert mt == MsgType.ROLE_SELECT
    print(f"Server prompt: {body.decode()!r}")

    writer.close()
    await writer.wait_closed()
    print("Smoke test passed.")

asyncio.run(smoke())
