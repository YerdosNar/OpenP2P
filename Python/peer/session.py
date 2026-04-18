import asyncio
import hashlib
import hmac
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional

from common import crypto
from common.protocol import (
    MsgType, frame, encode, decode,
    encode_json, decode_json,
    encode_file_chunk, decode_file_chunk,
    LENGTH_PREFIX, MAX_FRAME_SIZE,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

log = logging.getLogger("peer.session")

AUTH_CHALLENGE_SIZE = 32
AUTH_TIMEOUT = 10.0
FILE_CHUNK_SIZE = 32 * 1024
DOWNLOAD_DIR = Path("./downloads")


class StreamReader:
    def __init__(self):
        self._buf = bytearray()
        self._event = asyncio.Event()
        self._closed = False

    def feed(self, data: bytes, end_stream: bool) -> None:
        if data:
            self._buf.extend(data)
        if end_stream:
            self._closed = True
        self._event.set()

    async def read_exactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            if self._closed:
                raise EOFError("stream closed while reading")
            self._event.clear()
            await self._event.wait()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def read_frame(self) -> bytes:
        header = await self.read_exactly(LENGTH_PREFIX.size)
        (length,) = LENGTH_PREFIX.unpack(header)
        if length > MAX_FRAME_SIZE:
            raise ValueError(f"Frame announces {length} bytes, exceeds cap")
        return await self.read_exactly(length)


class Session:
    def __init__(self, quic_peer, our_priv, peer_pubkey_bytes: bytes, is_host: bool):
        self._quic = quic_peer
        self._our_priv = our_priv
        self._peer_pubkey_bytes = peer_pubkey_bytes
        self._is_host = is_host
        self._streams = {}
        self._auth_stream_id = None
        self._chat_stream_id = None
        self._pending_incoming_files = {}
        self._auth_key: Optional[bytes] = None
        self._authenticated = asyncio.Event()
        self._stop = asyncio.Event()
        self._ingress_tasks = []

    async def _on_stream_data(self, stream_id: int, data: bytes, end_stream: bool):
        reader = self._streams.get(stream_id)
        if reader is None:
            reader = StreamReader()
            self._streams[stream_id] = reader
            task = asyncio.create_task(self._handle_incoming_stream(stream_id, reader))
            self._ingress_tasks.append(task)
        reader.feed(data, end_stream)

    async def _handle_incoming_stream(self, stream_id: int, reader: StreamReader):
        try:
            first = await reader.read_frame()
        except (EOFError, asyncio.CancelledError):
            return
        except Exception as e:
            log.warning("stream %d: bad first frame: %s", stream_id, e)
            return

        try:
            mt, body = decode(first)
        except ValueError as e:
            log.warning("stream %d: bad msg type: %s", stream_id, e)
            return

        if mt == MsgType.CHAT:
            await self._chat_ingress_loop(stream_id, reader, initial_body=body)
        elif mt == MsgType.FILE_OFFER:
            await self._file_ingress_loop(stream_id, reader, initial_body=body)
        else:
            log.warning("stream %d: unexpected first message type %s", stream_id, mt)

    async def authenticate(self) -> bool:
        peer_pub_obj = X25519PublicKey.from_public_bytes(self._peer_pubkey_bytes)
        self._auth_key = crypto.derive_shared_key(
            self._our_priv, peer_pub_obj, info=b"p2p-auth v1"
        )

        self._quic.on_stream_data = self._on_stream_data

        our_challenge = os.urandom(AUTH_CHALLENGE_SIZE)

        if self._is_host:
            auth_reader = StreamReader()
            auth_fut = asyncio.get_running_loop().create_future()

            original_on_data = self._quic.on_stream_data

            async def auth_sniffer(sid, data, end):
                if self._auth_stream_id is None:
                    self._auth_stream_id = sid
                    self._streams[sid] = auth_reader
                    if not auth_fut.done():
                        auth_fut.set_result(sid)
                if sid == self._auth_stream_id:
                    auth_reader.feed(data, end)
                else:
                    await original_on_data(sid, data, end)

            self._quic.on_stream_data = auth_sniffer

            try:
                await asyncio.wait_for(auth_fut, AUTH_TIMEOUT)
            except asyncio.TimeoutError:
                log.error("auth: peer did not open auth stream")
                self._quic.on_stream_data = original_on_data
                return False

            try:
                peer_challenge = await asyncio.wait_for(
                    auth_reader.read_exactly(AUTH_CHALLENGE_SIZE), AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                log.error("auth: no peer challenge received")
                self._quic.on_stream_data = original_on_data
                return False

            self._quic.send_stream(self._auth_stream_id, our_challenge, end_stream=False)

            our_response = hmac.new(
                self._auth_key, peer_challenge, hashlib.sha256
            ).digest()
            self._quic.send_stream(self._auth_stream_id, our_response, end_stream=False)

            try:
                peer_response = await asyncio.wait_for(
                    auth_reader.read_exactly(32), AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                log.error("auth: no peer response received")
                self._quic.on_stream_data = original_on_data
                return False

            expected = hmac.new(
                self._auth_key, our_challenge, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, peer_response):
                log.error("auth: peer response INVALID")
                self._quic.on_stream_data = original_on_data
                return False

            self._quic.on_stream_data = self._on_stream_data
            self._authenticated.set()
            log.info("auth: succeeded (host side)")
            return True
        else:
            self._auth_stream_id = self._quic.get_next_stream_id()
            auth_reader = StreamReader()
            self._streams[self._auth_stream_id] = auth_reader

            self._quic.send_stream(
                self._auth_stream_id, our_challenge, end_stream=False
            )

            try:
                peer_challenge = await asyncio.wait_for(
                    auth_reader.read_exactly(AUTH_CHALLENGE_SIZE), AUTH_TIMEOUT
                )
                peer_response = await asyncio.wait_for(
                    auth_reader.read_exactly(32), AUTH_TIMEOUT
                )
            except asyncio.TimeoutError:
                log.error("auth: joiner timed out waiting for host")
                return False

            expected = hmac.new(
                self._auth_key, our_challenge, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(expected, peer_response):
                log.error("auth: host response INVALID")
                return False

            our_response = hmac.new(
                self._auth_key, peer_challenge, hashlib.sha256
            ).digest()
            self._quic.send_stream(
                self._auth_stream_id, our_response, end_stream=False
            )

            self._authenticated.set()
            log.info("auth: succeeded (joiner side)")
            return True

    def _ensure_chat_stream(self) -> int:
        if self._chat_stream_id is None:
            self._chat_stream_id = self._quic.get_next_stream_id()
        return self._chat_stream_id

    async def send_chat(self, text: str) -> None:
        sid = self._ensure_chat_stream()
        payload = encode_json(MsgType.CHAT, {
            "text": text,
            "ts": time.time(),
        })
        self._quic.send_stream(sid, frame(payload), end_stream=False)

    async def _chat_ingress_loop(self, stream_id: int, reader: StreamReader, initial_body: bytes):
        try:
            obj = decode_json(initial_body)
            self._print_chat(obj)
        except Exception as e:
            log.warning("chat: bad first message: %s", e)
            return

        while not self._stop.is_set():
            try:
                payload = await reader.read_frame()
            except (EOFError, asyncio.CancelledError):
                return
            except Exception as e:
                log.warning("chat: read error: %s", e)
                return
            try:
                mt, body = decode(payload)
                if mt == MsgType.CHAT:
                    obj = decode_json(body)
                    self._print_chat(obj)
                elif mt == MsgType.BYE:
                    print("\n[peer said BYE; closing]")
                    self._stop.set()
                    return
                else:
                    log.warning("chat: unexpected message type %s", mt)
            except Exception as e:
                log.warning("chat: parse error: %s", e)

    def _print_chat(self, obj):
        text = obj.get("text", "")
        print(f"\n<peer> {text}\n> ", end="", flush=True)

    async def send_file(self, path: str) -> bool:
        p = Path(path)
        if not p.is_file():
            print(f"File not found: {path}")
            return False
        size = p.stat().st_size
        name = p.name

        h = hashlib.sha256()
        with open(p, "rb") as f:
            while True:
                chunk = f.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        file_hash = h.hexdigest()

        sid = self._quic.get_next_stream_id()

        offer = encode_json(MsgType.FILE_OFFER, {
            "name": name,
            "size": size,
            "sha256": file_hash,
        })
        self._quic.send_stream(sid, frame(offer), end_stream=False)

        reader = StreamReader()
        self._streams[sid] = reader

        print(f"[sent FILE_OFFER for {name} ({size} bytes)]")

        try:
            payload = await asyncio.wait_for(reader.read_frame(), 60.0)
        except asyncio.TimeoutError:
            print("[peer did not respond to FILE_OFFER in 60s]")
            return False

        mt, body = decode(payload)
        if mt == MsgType.FILE_REJECT:
            print("[peer rejected file]")
            return False
        if mt != MsgType.FILE_ACCEPT:
            print(f"[unexpected reply {mt}]")
            return False

        print(f"[peer accepted; sending {name}]")

        seq = 0
        with open(p, "rb") as f:
            while True:
                chunk = f.read(FILE_CHUNK_SIZE)
                if not chunk:
                    break
                payload = encode_file_chunk(seq, chunk)
                self._quic.send_stream(sid, frame(payload), end_stream=False)
                seq += 1
                if seq % 32 == 0:
                    await asyncio.sleep(0)

        done = encode_json(MsgType.FILE_DONE, {
            "total_chunks": seq,
            "sha256": file_hash,
        })
        self._quic.send_stream(sid, frame(done), end_stream=True)

        print(f"[file {name} sent: {seq} chunks]")
        return True

    async def _file_ingress_loop(self, stream_id: int, reader: StreamReader, initial_body: bytes):
        try:
            offer = decode_json(initial_body)
            name = offer["name"]
            size = int(offer["size"])
            expected_hash = offer.get("sha256", "")
        except Exception as e:
            log.warning("file: bad offer: %s", e)
            return

        print(f"\n[peer offering file: {name} ({size} bytes)]")
        print(f"> accept with /accept or reject with /reject", flush=True)

        decision_fut = asyncio.get_running_loop().create_future()
        self._pending_incoming_files[stream_id] = (decision_fut, name, size, expected_hash)

        try:
            accept = await asyncio.wait_for(decision_fut, 60.0)
        except asyncio.TimeoutError:
            print(f"\n[file offer {name} timed out; rejecting]")
            accept = False
        finally:
            self._pending_incoming_files.pop(stream_id, None)

        if not accept:
            reject = encode_json(MsgType.FILE_REJECT, {"reason": "user declined"})
            self._quic.send_stream(stream_id, frame(reject), end_stream=False)
            return

        accept_msg = encode_json(MsgType.FILE_ACCEPT, {})
        self._quic.send_stream(stream_id, frame(accept_msg), end_stream=False)

        DOWNLOAD_DIR.mkdir(exist_ok=True)
        safe_name = Path(name).name
        dest = DOWNLOAD_DIR / safe_name

        i = 1
        while dest.exists():
            dest = DOWNLOAD_DIR / f"{Path(safe_name).stem}_{i}{Path(safe_name).suffix}"
            i += 1

        received = 0
        expected_seq = 0
        h = hashlib.sha256()

        with open(dest, "wb") as f:
            while True:
                try:
                    payload = await reader.read_frame()
                except EOFError:
                    print(f"\n[file {name}: stream closed early]")
                    return
                try:
                    mt, body = decode(payload)
                except ValueError as e:
                    log.warning("file: bad frame: %s", e)
                    return

                if mt == MsgType.FILE_CHUNK:
                    seq, data = decode_file_chunk(body)
                    if seq != expected_seq:
                        log.warning("file: out of order seq %d (expected %d)",
                                    seq, expected_seq)
                    f.write(data)
                    h.update(data)
                    received += len(data)
                    expected_seq += 1
                    if expected_seq % 64 == 0:
                        pct = (received / size * 100) if size else 0
                        print(f"\n[receiving {name}: {received}/{size} bytes ({pct:.1f}%)]\n> ",
                              end="", flush=True)
                elif mt == MsgType.FILE_DONE:
                    done_obj = decode_json(body)
                    got_hash = h.hexdigest()
                    if expected_hash and got_hash != expected_hash:
                        print(f"\n[WARNING: hash mismatch for {name}! got {got_hash[:16]}..]")
                    else:
                        print(f"\n[file received: {dest} ({received} bytes, hash OK)]\n> ",
                              end="", flush=True)
                    return
                else:
                    log.warning("file: unexpected message type %s", mt)

    def accept_pending_file(self):
        for sid, (fut, name, size, _) in list(self._pending_incoming_files.items()):
            if not fut.done():
                fut.set_result(True)
                print(f"[accepting {name}]")
                return True
        print("[no pending file offer]")
        return False

    def reject_pending_file(self):
        for sid, (fut, name, size, _) in list(self._pending_incoming_files.items()):
            if not fut.done():
                fut.set_result(False)
                print(f"[rejected {name}]")
                return True
        print("[no pending file offer]")
        return False

    async def send_bye(self):
        if self._chat_stream_id is not None:
            bye = encode(MsgType.BYE, b"")
            try:
                self._quic.send_stream(self._chat_stream_id, frame(bye), end_stream=True)
            except Exception:
                pass

    async def run_chat_ui(self):
        await self._authenticated.wait()
        print("\n=== Chat ready ===")
        print("Commands: /send <path>  /accept  /reject  /quit")
        print("Anything else is sent as chat text.\n")

        while not self._stop.is_set():
            try:
                line = await asyncio.to_thread(input, "> ")
            except EOFError:
                break
            if self._stop.is_set():
                break
            line = line.rstrip("\n")
            if not line:
                continue

            if line.startswith("/quit"):
                await self.send_bye()
                self._stop.set()
                break
            elif line.startswith("/send "):
                path = line[6:].strip()
                await self.send_file(path)
            elif line.startswith("/accept"):
                self.accept_pending_file()
            elif line.startswith("/reject"):
                self.reject_pending_file()
            else:
                await self.send_chat(line)

    def stop(self):
        self._stop.set()
