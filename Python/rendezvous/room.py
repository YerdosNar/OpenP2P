"""
In-memory state for the Rendezvous server.

A `Room` reporesents a host waiting for a joiner. The `RoomRegistry` owns
all active rooms, enforces unique IDs, and handles the 3-minute timeout.

All operations assume a single asyncio event loop - no external locking
"""

import asyncio
import hmac
import time
from dataclasses import dataclass, field
from typing import Optional

ROOM_TTL_SECONDS = 180.0


@dataclass
class Room:
    room_id: str
    room_pw: str
    host_pubkey: bytes
    host_ip: str
    host_port: int
    created_at: float

    joiner_arrived: asyncio.Future = field(default_factory=asyncio.Future)

    _timeout_task: Optional[asyncio.Task] = None


    def is_expired(self, now: Optional[float] = None) -> bool:
        """True if the 3-minute TTL has elapsed"""
        now = now if now is not None else time.monotonic()
        return (now - self.created_at) >= ROOM_TTL_SECONDS


    def seconds_remaining(self, now: Optional[float] = None) -> float:
        """How long this room has left before expiring"""
        now = now if now is not None else time.monotonic()
        return max(0.0, ROOM_TTL_SECONDS - (now - self.created_at))


    def check_password(self, candidate: str) -> bool:
        """Constant-time password comparison."""
        return hmac.compare_digest(self.room_pw, candidate)


@dataclass
class JoinResult:
    """What the registry returns to a successful joiner"""
    host_pubkey: bytes
    host_ip: str
    host_port: int


class RoomRegistry:
    """
    Tracks all active rooms, keyed by room_id.

    Single-event-loop ownership - no share across threads without
    adding locks.
    """


    def __init__(self):
        self._rooms: dict[str, Room] = {}


    def create_room(
        self,
        room_id: str,
        room_pw: str,
        host_pubkey: bytes,
        host_ip: str,
        host_port: int,
    ) -> Room:
        """
        Register a new room. Raises KeyError if `room_id` is taken.

        The caller (server code) is responsible for scheduling the timeout
        via schedule_timeout() after awaiting on the host side.
        """
        if room_id in self._rooms:
            raise KeyError(f"Room {room_id!r} already exists")

        if len(host_pubkey) != 32:
            raise ValueError("host_pubkey must be 32 bytes(X25519)")

        room = Room(
            room_id=room_id,
            room_pw=room_pw,
            host_pubkey=host_pubkey,
            host_ip=host_ip,
            host_port=host_port,
            created_at=time.monotonic()
        )
        self._rooms[room_id] = room
        return room


    def schedule_timeout(self, room: Room) -> None:
        """
        Start the 3-minute timeout task for a room. Call this once, after
        create_room(), from an async context.
        """
        async def _expire():
            try:
                await asyncio.sleep(ROOM_TTL_SECONDS)
            except asyncio.CancelledError:
                return # Room was deleted early; nothing to do
            # If here, dlete and notify the host (if waiting)
            self._expire_room(room.room_id)

        room._timeout_task = asyncio.create_task(_expire())


    def _expire_room(self, room_id: str) -> None:
        """Internal: remove a room because it timed out."""
        room = self._rooms.pop(room_id, None)
        if room is None:
            return # Already gone
        if not room.joiner_arrived.done():
            room.joiner_arrived.set_exception(
                TimeoutError(f"Room {room_id!r} expired without a joiner")
            )


    def remove_host(self, room_id: str) -> None:
        """
        Called when the host's session ends for any reason (graceful disconnect,
        error, cancellation). Idempotent.
        """
        room = self._rooms.pop(room_id, None)
        if room is None:
            return
        if room._timeout_task is not None and not room._timeout_task.done():
            room._timeout_task.cancel()
        if not room.joiner_arrived.done():
            room.joiner_arrived.cancel()


    def try_join(
        self,
        room_id: str,
        candidate_pw: str,
        joiner_pubkey: bytes,
        joiner_ip: str,
        joiner_port: int,
    ) -> Optional[JoinResult]:
        """
        Attempt to join

        SUCCESS: removes the room, cancels its timeout, resolves the host's
        future with the joiner's info, and returns a JoinResult for the joiner

        FAIL (no such room, wrong password): returns None. The caller
        is responsible for kicking the joiner.
        """
        room = self._rooms.get(room_id)
        if room is None:
            return None
        if not room.check_password(candidate_pw):
            return None
        if len(joiner_pubkey) != 32:
            return None

        # Remove from registry FIRST so noone else can match
        del self._rooms[room_id]

        # cancel the expiry time; it's no longer needed
        if room._timeout_task is not None and not room._timeout_task.done():
            room._timeout_task.cancel()

        # Wake the host with the joiner's details
        if not room.joiner_arrived.done():
            room.joiner_arrived.set_result({
                "pubkey": joiner_pubkey,
                "ip": joiner_ip,
                "port": joiner_port,
            })

        return JoinResult(
            host_pubkey=room.host_pubkey,
            host_ip=room.host_ip,
            host_port=room.host_port,
        )


    # introspection
    def __len__(self) -> int:
        return len(self._rooms)

    def has_room(self, room_id: str) -> bool:
        return room_id in self._rooms
