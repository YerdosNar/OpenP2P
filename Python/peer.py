import socket

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
        exit(1)

    room_id = input()
    send(sock, room_id + "\n")

    # Room PW
    prompt = recv(sock)
    print(prompt, end="")
    room_pw = input()
    send(sock, room_pw + "\n")


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((RENDEZVOUS_HOST, RENDEZVOUS_PORT))

    # Host/Join prompt
    choice = host_join(sock)

    # Room ID:PW
    id_pw(sock)

    # Response
    response = recv(sock)
    print(response)

    if choice == "h":
        # Response "wait for joiner"
        response = recv(sock)
        print(response)

    # Parse peer info if we got it
    if response.startswith("PEER_INFO:"):
        parts = response.split(":")
        peer_ip = parts[1]
        peer_port = int(parts[2])
        peer_pubkey = parts[3]
        print(f"peer_ip: {peer_ip}")
        print(f"peer_port: {peer_port}")
        print(f"peer_pubkey: {peer_pubkey}")

    sock.close()


if __name__ == "__main__":
    main()
