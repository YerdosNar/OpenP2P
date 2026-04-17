"""
Cross-platform UDP socket helpers for hole punching

Key guarantee: sockets created here can coexist with another socket bound to
the same local port (on platforms that support it), which is essential for
reusing the Rendezvous-facing port as the QUIC-facing port withtout losing
the NAT mapping
"""

import asyncio
import socket
import sys


def create_reusable_udp_socket(
        bind_host: str = "0.0.0.0",
        bind_port: int = 0,
) -> socket.socket:
    """
    Create a UDP socket bound to (bind_host, bind_port) with REUSEADDR
    (and REUSEPORT where available) set.

    Pass bind_port=0 to let the OS pick an ephemeral port; the chosen port
    is readable afterward via sock.getsockname()[1]
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # SO_REUSEADDR
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEPORT if available
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass

    # Non-blocking so we can hand this to asynio later.
    sock.setblocking(False)

    sock.bind((bind_host, bind_port))
    return sock


def get_local_endpoint(sock: socket.socket) -> tuple[str, int]:
    """Return (host, port) that the socket is actually bound to"""
    host, port = sock.getsockname()
    return host, port


KEEPALIVE_INTERVAL = 15.0    # seconds
KEEPALIVE_PAYLOAD  = b"\x00" # just a single byte to refresh the mapping


async def nat_keepalive_loop(
        sock: socket.socket,
        remote_addr: tuple[str, int],
        interval: float = KEEPALIVE_INTERVAL
) -> None:
    """
    Periodically send a tiny UDP packet to remote_addr to keep the NAT
    mapping for `sock`'s local port alive

    Meant to run as a background asyncio task. Cancel the task to stop it.
    The remote end should either ignore these bytes or treat them as
    a defined KEEPALIVE message at the protocol layer.
    """
    loop = asyncio.get_running_loop()
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                await loop.sock_sendto(sock, KEEPALIVE_PAYLOAD, remote_addr)
            except (OSError, ConnectionError):
                return
    except asyncio.CancelledError:
        # Normal shutdown
        raise


def describe_platform_support() -> str:
    """Human-readable summary of which socket options this platform offers.
    Useful to print at startup when debugging hole-punch issues on the hardware."""
    bits = [f"platform={sys.platform}"]
    bits.append("SO_REUSEADDR=yes")
    bits.append(
        "SO_REUSEPORT=yes" if hasattr(socket, "SO_REUSEPORT") else "SO_REUSEPORT=no"
    )
    return ", ".join(bits)
