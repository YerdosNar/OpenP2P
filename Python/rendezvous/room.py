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
        now = now if now is not None else time.monotonic()
        return (now - self.created_at) >= ROOM_TTL_SECONDS

    def seconds_remaining(self, now: Optional[float] = None) -> float:
        now = now if now is not None else time.monotonic()
        return max(0.0, ROOM_TTL_SECONDS - (now - self.created_at))

    def check_password(self, candidate: str) -> bool:
        return hmac.compare_digest(self.room_pw, candidate)


@dataclass
class JoinResult:
    host_pubkey: bytes
    host_ip: str
    host_port: int


class RoomRegistry:
    def __init__(self):
        self._rooms = {}

    def create_room(
        self,
        room_id: str,
        room_pw: str,
        host_pubkey: bytes,
        host_ip: str,
        host_port: int,
    ) -> Room:
        if room_id in self._rooms:
            raise KeyError(f"Room {room_id!r} already exists")

        if len(host_pubkey) != 32:
            raise ValueError("host_pubkey must be 32 bytes (X25519)")

        room = Room(
            room_id=room_id,
            room_pw=room_pw,
            host_pubkey=host_pubkey,
            host_ip=host_ip,
            host_port=host_port,
            created_at=time.monotonic(),
        )
        self._rooms[room_id] = room
        return room

    def schedule_timeout(self, room: Room) -> None:
        async def _expire():
            try:
                await asyncio.sleep(ROOM_TTL_SECONDS)
            except asyncio.CancelledError:
                return
            self._expire_room(room.room_id)

        room._timeout_task = asyncio.create_task(_expire())

    def _expire_room(self, room_id: str) -> None:
        room = self._rooms.pop(room_id, None)
        if room is None:
            return
        if not room.joiner_arrived.done():
            room.joiner_arrived.set_exception(
                TimeoutError(f"Room {room_id!r} expired without a joiner")
            )

    def remove_host(self, room_id: str) -> None:
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
        room = self._rooms.get(room_id)
        if room is None:
            return None
        if not room.check_password(candidate_pw):
            return None
        if len(joiner_pubkey) != 32:
            return None

        del self._rooms[room_id]

        if room._timeout_task is not None and not room._timeout_task.done():
            room._timeout_task.cancel()

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

    def __len__(self) -> int:
        return len(self._rooms)

    def has_room(self, room_id: str) -> bool:
        return room_id in self._rooms
