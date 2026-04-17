import asyncio
from rendezvous.room import RoomRegistry, ROOM_TTL_SECONDS


async def test_happy_path():
    reg = RoomRegistry()

    host_pk = b"\x01" * 32
    joiner_pk = b"\x02" * 32

    room = reg.create_room("abc", "secret", host_pk, "1.2.3.4", 5000)
    reg.schedule_timeout(room)
    assert len(reg) == 1

    # Simulate the host awaiting the joiner, joiner arriving shortly after.
    async def simulate_joiner():
        await asyncio.sleep(0.05)
        return reg.try_join("abc", "secret", joiner_pk, "9.8.7.6", 6000)

    joiner_task = asyncio.create_task(simulate_joiner())
    joiner_info = await room.joiner_arrived   # host-side await
    result = await joiner_task

    assert joiner_info["pubkey"] == joiner_pk
    assert joiner_info["ip"] == "9.8.7.6"
    assert result.host_pubkey == host_pk
    assert len(reg) == 0  # Room should be gone
    print("Happy path: OK")


async def test_wrong_password():
    reg = RoomRegistry()
    room = reg.create_room("abc", "secret", b"\x01" * 32, "1.2.3.4", 5000)
    reg.schedule_timeout(room)

    result = reg.try_join("abc", "WRONG", b"\x02" * 32, "9.8.7.6", 6000)
    assert result is None
    assert reg.has_room("abc")  # Room still there; joiner was rejected.
    reg.remove_host("abc")      # Clean up.
    print("Wrong password: OK")


async def test_duplicate_room_id():
    reg = RoomRegistry()
    reg.create_room("abc", "s", b"\x01" * 32, "1.2.3.4", 5000)
    try:
        reg.create_room("abc", "s", b"\x01" * 32, "1.2.3.4", 5001)
    except KeyError:
        print("Duplicate room ID rejected: OK")
    else:
        raise AssertionError("Expected KeyError on duplicate room_id")
    reg.remove_host("abc")


async def test_timeout():
    # Temporarily shrink the TTL for this test only.
    import rendezvous.room as rm
    original = rm.ROOM_TTL_SECONDS
    rm.ROOM_TTL_SECONDS = 0.1  # 100 ms

    try:
        reg = RoomRegistry()
        room = reg.create_room("t", "p", b"\x01" * 32, "1.2.3.4", 5000)
        reg.schedule_timeout(room)

        try:
            await room.joiner_arrived
        except TimeoutError:
            print("Timeout fired and host was notified: OK")
        else:
            raise AssertionError("Expected TimeoutError")

        assert len(reg) == 0
    finally:
        rm.ROOM_TTL_SECONDS = original


async def main():
    await test_happy_path()
    await test_wrong_password()
    await test_duplicate_room_id()
    await test_timeout()
    print("All room tests passed.")


asyncio.run(main())
