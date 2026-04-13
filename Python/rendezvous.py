import socket
import threading
import ssl
import json

from logger import info, warn, error

HOST = "0.0.0.0"
PORT = 8888

rooms = {}
rooms_lock = threading.Lock()


def send_msg(conn, msg):
    """Send a length-prefixed message."""
    data = msg.encode()
    conn.sendall(len(data).to_bytes(4, "big") + data)


def recv_msg(conn):
    """Receive a length-prefixed message."""
    header = conn.recv(4)
    if not header or len(header) < 4:
        return None
    length = int.from_bytes(header, "big")
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode()


def handle_client(conn, addr):
    info(f"{addr} connected")
    try:
        # Step 1: Receive the client's registration as JSON
        raw = recv_msg(conn)
        if not raw:
            return
        reg = json.loads(raw)

        action = reg["action"]      # "host" or "join"
        room_id = reg["room_id"]
        room_pw = reg["room_pw"]
        pubkey_hex = reg["pubkey"]

        if action == "host":
            handle_host(conn, addr, room_id, room_pw, pubkey_hex)
        elif action == "join":
            handle_join(conn, addr, room_id, room_pw, pubkey_hex)
        else:
            send_msg(conn, json.dumps({"status": "error", "msg": "Invalid action"}))

    except Exception as e:
        error(f"Error with {addr}: {e}")
    finally:
        conn.close()
        warn(f"{addr} disconnected")


def handle_host(conn, addr, room_id, room_pw, pubkey_hex):
    event = threading.Event()

    with rooms_lock:
        if room_id in rooms:
            send_msg(conn, json.dumps({"status": "error", "msg": "Room ID already exists"}))
            return
        rooms[room_id] = {
            "password": room_pw,
            "addr": addr,
            "conn": conn,
            "event": event,
            "pubkey": pubkey_hex,
        }

    info(f"Room '{room_id}' created by {addr}")
    send_msg(conn, json.dumps({"status": "waiting", "msg": f"Room '{room_id}' created. Waiting..."}))

    # Block until a joiner arrives or timeout
    joined = event.wait(timeout=180)
    if not joined:
        send_msg(conn, json.dumps({"status": "error", "msg": "Room expired. No one joined."}))
        with rooms_lock:
            rooms.pop(room_id, None)
        return

    # The joiner thread stored peer info in the room dict before setting the event
    with rooms_lock:
        room = rooms.pop(room_id, None)

    if room and "joiner_info" in room:
        joiner = room["joiner_info"]
        send_msg(conn, json.dumps({
            "status": "matched",
            "peer_ip": joiner["ip"],
            "peer_port": joiner["port"],
            "peer_pubkey": joiner["pubkey"],
        }))
        info(f"Sent joiner info to host {addr}")


def handle_join(conn, addr, room_id, room_pw, pubkey_hex):
    with rooms_lock:
        room = rooms.get(room_id)
        if room is None or room["password"] != room_pw:
            send_msg(conn, json.dumps({"status": "error", "msg": "Invalid room ID or password"}))
            return

        # Store joiner info so the host thread can read it
        room["joiner_info"] = {
            "ip": addr[0],
            "port": addr[1],
            "pubkey": pubkey_hex,
        }

        host_addr = room["addr"]
        host_pubkey = room["pubkey"]
        event = room["event"]

    # Send host info to the joiner
    send_msg(conn, json.dumps({
        "status": "matched",
        "peer_ip": host_addr[0],
        "peer_port": host_addr[1],
        "peer_pubkey": host_pubkey,
    }))
    info(f"Sent host info to joiner {addr}")

    # Signal the host thread AFTER storing joiner info
    event.set()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("server.crt", "server.key")

    info(f"Rendezvous server listening on {HOST}:{PORT} (TLS)")

    while True:
        raw_conn, addr = server.accept()
        try:
            conn = context.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError as e:
            error(f"TLS handshake failed for {addr}: {e}")
            raw_conn.close()
            continue
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    main()
