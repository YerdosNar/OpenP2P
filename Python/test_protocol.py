from common.protocol import (
    MsgType, frame, decode, encode_json, decode_json,
    encode_file_chunk, decode_file_chunk,
)

# Round-trip a JSON control message
payload = encode_json(MsgType.ROOM_CREATE, {"room_id": "abc", "pw": "secret"})
wire = frame(payload)
print(f"Framed ROOM_CREATE is {len(wire)} bytes on the wire")

# Simulate a receiver parsing it
from common.protocol import LENGTH_PREFIX
length = LENGTH_PREFIX.unpack(wire[:4])[0]
body_bytes = wire[4 : 4 + length]
msg_type, body = decode(body_bytes)
print(f"Received type={msg_type.name}, body={decode_json(body)}")

# Round-trip a file chunk
chunk_payload = encode_file_chunk(seq=42, data=b"hello world" * 10)
msg_type, body = decode(chunk_payload)
assert msg_type == MsgType.FILE_CHUNK
seq, data = decode_file_chunk(body)
print(f"Chunk seq={seq}, data len={len(data)}")

# Unknown type should raise cleanly
try:
    decode(b"\xFF\x00\x00")
except ValueError as e:
    print(f"Correctly rejected unknown type: {e}")
