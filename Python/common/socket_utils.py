import asyncio
import socket
import sys


def create_reusable_udp_socket(
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setblocking(False)
    sock.bind((bind_host, bind_port))
    return sock


def get_local_endpoint(sock: socket.socket):
    host, port = sock.getsockname()
    return host, port


KEEPALIVE_INTERVAL = 15.0
KEEPALIVE_PAYLOAD = b"\x00"


async def nat_keepalive_loop(
    sock: socket.socket,
    remote_addr,
    interval: float = KEEPALIVE_INTERVAL,
) -> None:
    loop = asyncio.get_running_loop()
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                await loop.sock_sendto(sock, KEEPALIVE_PAYLOAD, remote_addr)
            except (OSError, ConnectionError):
                return
    except asyncio.CancelledError:
        raise


def describe_platform_support() -> str:
    bits = [f"platform={sys.platform}"]
    bits.append("SO_REUSEADDR=yes")
    bits.append(
        "SO_REUSEPORT=yes" if hasattr(socket, "SO_REUSEPORT") else "SO_REUSEPORT=no"
    )
    return ", ".join(bits)
