import socket
import ssl
import threading
import time
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RENDEZVOUS_HOST = "127.0.0.1"
RENDEZVOUS_PORT = 5000


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
    print("\n--- Connected! E2EE chat (type 'quit' to exit) ---\n")

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
            pass
        print("\n--- Peer disconnected ---")

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
    if my_port < peer_port:
        # I am the "server" — just listen
        print("(I am listener)")
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        srv.bind(("0.0.0.0", my_port))
        srv.listen(1)
        srv.settimeout(30)
        try:
            conn, addr = srv.accept()
            conn.settimeout(None)
            return conn
        except socket.timeout:
            return None
        finally:
            srv.close()
    else:
        # I am the "client" — just connect
        print("(I am connector)")
        time.sleep(1)  # Give listener time to start
        for attempt in range(10):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s.bind(("0.0.0.0", my_port))
                s.connect((peer_ip, peer_port))
                return s
            except:
                try:
                    s.close()
                except:
                    pass
                time.sleep(2)
        return None


def main():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key_hex = public_key_bytes.hex()
    print(f"My public key: {public_key_hex}")

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    raw_sock.bind(("0.0.0.0", 0))
    my_port = raw_sock.getsockname()[1]
    print(f"My P2P port: {my_port}")

    raw_sock.connect((RENDEZVOUS_HOST, RENDEZVOUS_PORT))

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
        peer_data = response.split("PEER_INFO:")[1].strip()
        parts = peer_data.split(":")
        peer_ip = parts[0]
        peer_port = int(parts[1])
        peer_pubkey_hex = parts[2]
        print(f"Peer IP: {peer_ip}")
        print(f"Peer Port: {peer_port}")
        print(f"Peer Public Key: {peer_pubkey_hex}")

    # Close rendezvous connection
    sock.close()

    if peer_ip:
        print(f"\nAttempting P2P connection (my port: {my_port}, peer: {peer_ip}:{peer_port})...")
        conn = p2p_connect(peer_ip, peer_port, my_port)
        if conn:
            key = derive_key(private_key, peer_pubkey_hex)
            print("E2EE key derived successfully.")
            chat(conn, key)
        else:
            print("Failed to establish P2P connection.")


if __name__ == "__main__":
    main()
