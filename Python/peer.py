import socket
import ssl
import threading
import json
import time
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from logger import error, success, warn, info


# ---------------------------------------------------------------------------
# Messaging helpers (length-prefixed framing)
# ---------------------------------------------------------------------------

def send_msg(sock, msg):
    """Send a length-prefixed message over a socket."""
    data = msg.encode()
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_msg(sock):
    """Receive a length-prefixed message from a socket."""
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    length = int.from_bytes(header, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode()


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def derive_key(private_key, peer_pubkey_hex):
    peer_pubkey_bytes = bytes.fromhex(peer_pubkey_hex)
    peer_pubkey = X25519PublicKey.from_public_bytes(peer_pubkey_bytes)
    shared_secret = private_key.exchange(peer_pubkey)
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"p2p-messenger",
    ).derive(shared_secret)


def encrypt(key, plain):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(nonce, plain.encode(), None)
    return nonce + cipher


def decrypt(key, data):
    nonce = data[:12]
    cipher = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cipher, None).decode()


# ---------------------------------------------------------------------------
# Rendezvous exchange
# ---------------------------------------------------------------------------

def rendezvous_exchange(server_host, server_port, local_port, pubkey_hex):
    """
    Connect to the rendezvous server, register as host or joiner,
    and return (peer_ip, peer_port, peer_pubkey_hex).

    We bind to `local_port` so the rendezvous server sees the NAT mapping
    for the same port we'll reuse for the P2P connection.
    """
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass  # SO_REUSEPORT not available on all platforms
    raw_sock.bind(("0.0.0.0", local_port))
    raw_sock.connect((server_host, server_port))

    context = ssl.create_default_context()
    # For self-signed certs during dev — remove in production
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(raw_sock)

    # Gather user input
    choice = input("Are you [H]ost or [J]oin? [h/j]: ").strip().lower()
    room_id = input("Room ID: ").strip()
    room_pw = input("Room PW: ").strip()

    action = "host" if choice == "h" else "join"
    registration = json.dumps({
        "action": action,
        "room_id": room_id,
        "room_pw": room_pw,
        "pubkey": pubkey_hex,
    })
    send_msg(sock, registration)

    # Read response(s) from server
    while True:
        resp_raw = recv_msg(sock)
        if resp_raw is None:
            error("Lost connection to rendezvous server")
            sock.close()
            return None
        resp = json.loads(resp_raw)
        info(f"Server: {resp.get('msg', resp.get('status'))}")

        if resp["status"] == "error":
            sock.close()
            return None
        if resp["status"] == "matched":
            sock.close()
            return resp["peer_ip"], int(resp["peer_port"]), resp["peer_pubkey"]
        # status == "waiting" → keep reading


# ---------------------------------------------------------------------------
# TCP Hole Punch — simultaneous connect + listen
# ---------------------------------------------------------------------------

def tcp_hole_punch(peer_ip, peer_port, local_port, timeout=30):
    """
    Attempt TCP hole punching by running connect() and listen()/accept()
    simultaneously on the same local port.

    Returns a connected socket or None.
    """
    result = {"conn": None}
    stop = threading.Event()

    def do_listen():
        """Listen on local_port and accept an inbound connection."""
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass
            srv.settimeout(2)
            srv.bind(("0.0.0.0", local_port))
            srv.listen(1)
            info(f"Listening on port {local_port}...")
            while not stop.is_set():
                try:
                    conn, addr = srv.accept()
                    info(f"Accepted inbound connection from {addr}")
                    result["conn"] = conn
                    stop.set()
                    break
                except socket.timeout:
                    continue
            srv.close()
        except Exception as e:
            warn(f"Listen thread error: {e}")

    def do_connect():
        """Repeatedly try to connect out to the peer."""
        attempt = 0
        while not stop.is_set() and attempt < 60:
            attempt += 1
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass
                s.settimeout(2)
                s.bind(("0.0.0.0", local_port))
                s.connect((peer_ip, peer_port))
                info(f"Outbound connection to {peer_ip}:{peer_port} succeeded")
                result["conn"] = s
                stop.set()
                return
            except (ConnectionRefusedError, OSError, socket.timeout):
                s.close()
                if attempt % 5 == 0:
                    warn(f"Connect attempt {attempt} failed, retrying...")
                time.sleep(0.5)

    listen_t = threading.Thread(target=do_listen, daemon=True)
    connect_t = threading.Thread(target=do_connect, daemon=True)

    listen_t.start()
    # Small delay so the listen socket is up before we start punching
    time.sleep(0.3)
    connect_t.start()

    listen_t.join(timeout=timeout)
    connect_t.join(timeout=timeout)
    stop.set()

    return result["conn"]


# ---------------------------------------------------------------------------
# E2EE Chat
# ---------------------------------------------------------------------------

def chat(conn, key):
    success("Connected! End-to-end encrypted chat active.")
    info("Type 'quit' to exit.\n")

    def receive_messages():
        try:
            while True:
                header = conn.recv(4)
                if not header or len(header) < 4:
                    break
                msg_len = int.from_bytes(header, "big")
                data = b""
                while len(data) < msg_len:
                    chunk = conn.recv(msg_len - len(data))
                    if not chunk:
                        break
                    data += chunk
                if len(data) < msg_len:
                    break
                msg = decrypt(key, data)
                print(f"\nPeer: {msg}")
        except Exception as e:
            error(f"Receive error: {e}")
        error("\n--- Peer disconnected ---")

    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    try:
        while True:
            msg = input()
            if msg.lower() == "quit":
                break
            encrypted = encrypt(key, msg)
            conn.sendall(len(encrypted).to_bytes(4, "big") + encrypted)
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Generate X25519 keypair
    private_key = X25519PrivateKey.generate()
    pubkey_hex = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    server_host = input("Rendezvous server hostname: ").strip()
    server_ip = socket.gethostbyname(server_host)
    server_port = 8888 # Matches rendezvous.py PORT

    # Pick a local port and reuse it for BOTH the rendezvous connection
    # and the P2P connection — this is critical for hole punching.
    temp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    temp.bind(("0.0.0.0", 0))
    local_port = temp.getsockname()[1]
    temp.close()
    info(f"Using local port: {local_port}")

    # Phase 1: Rendezvous
    result = rendezvous_exchange(server_ip, server_port, local_port, pubkey_hex)
    if result is None:
        error("Rendezvous failed.")
        return

    peer_ip, peer_port, peer_pubkey_hex = result
    info(f"Peer: {peer_ip}:{peer_port}")

    # Phase 2: TCP Hole Punch (simultaneous connect + listen)
    info("Starting TCP hole punch...")
    conn = tcp_hole_punch(peer_ip, peer_port, local_port)

    if conn is None:
        error("TCP hole punch failed. P2P connection could not be established.")
        error("This often means one or both peers are behind a symmetric NAT.")
        return

    # Phase 3: E2EE Chat
    key = derive_key(private_key, peer_pubkey_hex)
    success("Shared secret derived.")
    chat(conn, key)


if __name__ == "__main__":
    main()
