import socket
import threading
import ssl

HOST = "0.0.0.0"
PORT = 5000

rooms = {}  # {room_id: {"password": str, "addr": tuple, "conn": conn}}
rooms_lock = threading.Lock()


def send(conn, msg):
    conn.sendall(msg.encode())


def recv(conn):
    return conn.recv(1024).decode().strip()


def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    try:
        pubkey_hex = recv(conn)
        print(f"[*] {addr} public key: {pubkey_hex}")

        send(conn, "Are you [H]ost or [J]oin [h/j]: ")
        choice = recv(conn).lower()

        if choice == "h":
            send(conn, "Enter HostRoom ID: ")
            room_id = recv(conn)
            send(conn, "Enter HostRoom PW: ")
            room_pw = recv(conn)

            event = threading.Event()

            with rooms_lock:
                rooms[room_id] = {
                    "password": room_pw,
                    "addr": addr,
                    "conn": conn,
                    "event": event,
                    "pubkey": pubkey_hex,
                }
            print(f"[*] Room '{room_id}' created by {addr}")
            send(conn, f"Room '{room_id}' created. Waiting for someone to join...\n")

            # Block until a joiner triggers the event or 3 min timeout
            joined = event.wait(timeout=180)
            if not joined:
                send(conn, "Room expired. No one joined.\n")
                with rooms_lock:
                    rooms.pop(room_id, None)

        elif choice == "j":
            send(conn, "Enter HostRoom ID: ")
            room_id = recv(conn)
            send(conn, "Enter HostRoom PW: ")
            room_pw = recv(conn)

            with rooms_lock:
                room = rooms.get(room_id)
                if room is None or room["password"] != room_pw:
                    send(conn, "Invalid ID or Password\n")
                    conn.close()
                    return
                del rooms[room_id]

            host_conn = room["conn"]
            host_addr = room["addr"]
            host_pubkey = room["pubkey"]

            host_info = f"{host_addr[0]}:{host_addr[1]}:{host_pubkey}"
            joiner_info = f"{addr[0]}:{addr[1]}:{pubkey_hex}"

            send(conn, f"PEER_INFO:{host_info}")
            send(host_conn, f"PEER_INFO:{joiner_info}")

            print(f"[*] Exchanged info between {host_addr} and {addr}")

            room["event"].set()  # Wake up the host thread
            room["conn"].close()
        else:
            send(conn, "Invalid choice\n")

    except Exception as e:
        print(f"[!] Error with {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] {addr} disconnected")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("server.crt", "server.key")

    print(f"Rendezvous server listening on {HOST}:{PORT} (TLS)")

    while True:
        raw_conn, addr = server.accept()
        conn = context.wrap_socket(raw_conn, server_side=True)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    main()
