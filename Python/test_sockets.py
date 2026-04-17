import asyncio
from common.socket_utils import (
    create_reusable_udp_socket,
    get_local_endpoint,
    describe_platform_support,
    nat_keepalive_loop,
)

print(describe_platform_support())

# 1. Create a socket, check it got a port
s1 = create_reusable_udp_socket()
host, port = get_local_endpoint(s1)
print(f"Socket 1 bound to {host}:{port}")

# 2. Create a SECOND socket on the same port — this is the core test.
#    If SO_REUSEPORT (or Windows SO_REUSEADDR) works, this succeeds.
try:
    s2 = create_reusable_udp_socket(bind_port=port)
    _, port2 = get_local_endpoint(s2)
    print(f"Socket 2 bound to same port {port2}: SUCCESS")
    s2.close()
except OSError as e:
    print(f"Second bind failed: {e}")
    print("This platform may not support dual-bind; hole punching will need to reuse the same socket instead.")

# 3. Keepalive task smoke test — start it, cancel it, confirm clean shutdown.
async def keepalive_test():
    # Send keepalives to ourselves (loopback) just to exercise the code path.
    task = asyncio.create_task(
        nat_keepalive_loop(s1, ("127.0.0.1", port), interval=0.1)
    )
    await asyncio.sleep(0.35)  # Let it fire a few times
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        print("Keepalive task cancelled cleanly: SUCCESS")

asyncio.run(keepalive_test())
s1.close()
