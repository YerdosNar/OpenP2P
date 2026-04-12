import socket
import threading

HOST = "0.0.0.0"
PORT = 8888

rooms = {}
rooms_lock = threading.Lock()


def send(conn, msg):
    conn.sendall(msg.encode())


def recv(conn):
    return conn.recv(1024).decode().strip()


def handle_client(conn, addr):
    print(f"[+] {addr} connected")
    try:
        send(conn, "Are you [H]ost or [J]oin [h/j]: ")
        choice = recv(conn).lower()

        if choice == "h":
            send(conn, "Enter HostRoom ID: ")
            room_id = recv(conn)
            send(conn, "Enter HostRoom PW: ")
            room_pw = recv(conn)

            with rooms_lock:
                rooms[room_id] = {
                    "password": room_pw,
                    "addr": addr,
                    "conn": conn
                }
            print(f"[*] Room '{room_id}' created by {addr}")
            send(conn, f"Room '{room_id}' created. Waiting for someone to join...\n")

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

            send(conn, "Matched! (details coming soon.)\n")
            send(room["conn"], "Someone joined! (details coming soon)\n")
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
    print(f"Rendezvous server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()


if __name__ == "__main__":
    main()
