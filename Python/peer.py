import socket
import ssl
import threading
import time
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from logger import error, success, warn, info


def send(sock, msg):
    sock.sendall(msg.encode())


def recv(sock):
    return sock.recv(1024).decode()


def host_join(sock):
    prompt = recv(sock)
    print(prompt, end="")
    choice = input()
    send(sock, choice + "\n")
    return choice.lower()


def id_pw(sock):
    prompt = recv(sock)
    print(prompt, end="")
    if prompt.startswith("Invalid"):
        return
    room_id = input()
    send(sock, room_id + "\n")

    prompt = recv(sock)
    print(prompt, end="")
    room_pw = input()
    send(sock, room_pw + "\n")


def derive_key(private_key, peer_pubkey_hex):
    peer_pubkey_bytes = bytes.fromhex(peer_pubkey_hex)
    peer_pubkey = X25519PublicKey.from_public_bytes(peer_pubkey_bytes)
    shared_secret = private_key.exchange(peer_pubkey)
    key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"p2p-messenger",
    ).derive(shared_secret)
    return key


def encrypt(key, plain):
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    cipher = aesgcm.encrypt(nonce, plain.encode(), None)
    return nonce + cipher


def decrypt(key, data):
    nonce = data[:12]
    cipher = data[12:]
    aesgcm = AESGCM(key)
    plain = aesgcm.decrypt(nonce, cipher, None)
    return plain.decode()


def chat(conn, key):
    success("Connected! E2EE chat")
    info("\ttype 'quit' to exit\n")

    def receive_messages():
        try:
            while True:
                # First 4 bytes = message length
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
            error(f"[!] Error {e}")
        error("\n--- Peer disconnected ---")

    recv_thread = threading.Thread(target=receive_messages, daemon=True)
    recv_thread.start()

    try:
        while True:
            msg = input()
            if msg.lower() == "quit":
                break
            encrypted = encrypt(key, msg)
            # Send length prefix + encrypted data
            conn.sendall(len(encrypted).to_bytes(4, "big") + encrypted)
    except:
        pass
    finally:
        conn.close()


def p2p_connect(peer_ip, peer_port, my_port):
    for attempt in range(10):
        try:
            s = set_sockopt(my_port)
            s.connect((peer_ip, peer_port))
            return s
        except:
            warn(f"Attempt {attempt+1}/10 failed")
            time.sleep(2)
    return None


def parse_ip_port_pubkey(response):
    parts = response.split(":")
    return parts[1], parts[2], parts[3]


def set_sockopt(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("0.0.0.0", port))
    return sock


def main():
    private_key = X25519PrivateKey.generate()
    public_key_hex = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    print("Enter Rendezvous Domain name: ")
    dom_name = input()
    vps_ip = socket.gethostbyname(dom_name)
    vps_port = 8888

    raw_sock = set_sockopt(0)
    my_port = raw_sock.getsockname()[1]
    info(f"My P2P port: {my_port}")

    raw_sock.connect((vps_ip, vps_port))

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(raw_sock)

    send(sock, public_key_hex + "\n")

    choice = host_join(sock)
    id_pw(sock)

    response = recv(sock)
    print(response)

    if choice == "h":
        response = recv(sock)
        print(response)

    peer_ip = None
    peer_port = None
    peer_pubkey_hex = None

    if response.startswith("PEER_INFO:"):
        peer_ip, peer_port, peer_pubkey_hex = parse_ip_port_pubkey(response)

    # Close rendezvous connection
    sock.close()

    if peer_ip:
        info(f"\nAttempting P2P connection: {peer_ip}:{peer_port})...")
        conn = p2p_connect(peer_ip, peer_port, my_port)
        if conn:
            key = derive_key(private_key, peer_pubkey_hex)
            success("E2EE key derived successfully.")
            chat(conn, key)
        else:
            error("Failed to establish P2P connection.")


if __name__ == "__main__":
    main()
