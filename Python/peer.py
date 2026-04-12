import socket

RENDEZVOUS_HOST = "127.0.0.1"
RENDEZVOUS_PORT = 8888


def send(sock, msg):
    sock.sendall(msg.encode())


def recv(sock):
    return sock.recv(1024).decode()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((RENDEZVOUS_HOST, RENDEZVOUS_PORT))

    # Host/Join prompt
    prompt = recv(sock)
    print(prompt, end="")
    choice = input()
    send(sock, choice + "\n")

    # Room ID
    prompt = recv(sock)
    print(prompt, end="")
    room_id = input()
    send(sock, room_id + "\n")

    # Room PW
    prompt = recv(sock)
    print(prompt, end="")
    room_pw = input()
    send(sock, room_pw + "\n")

    #
    response = recv(sock)
    print(response)

    sock.close()


if __name__ == "__main__":
    main()
