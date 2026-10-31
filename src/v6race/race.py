"""Open several connections to one destination and keep the first that completes.

On the campus network each new IPv6 flow is independently dropped about half
the time, so k parallel attempts all fail with probability ~0.5^k.
"""

import asyncio
import errno
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

Dial = Callable[[], Awaitable[socket.socket]]


@dataclass
class RaceResult:
    sock: socket.socket | None
    attempts: int
    failures: int
    elapsed: float
    # Attempts the far end actively refused. A refusal means the path works
    # (the port is closed); only silent drops suggest a blocked address.
    refused: int = 0
    # Attempts that failed because this host had no network (Wi-Fi
    # reconnecting): says nothing about the destination.
    local: int = 0

    def blocked(self) -> bool:
        """Whether the failure points at the destination being unreachable."""
        return self.sock is None and self.local == 0 and self.refused < self.attempts


# This host has no usable network right now.
LOCAL_ERRNOS = {errno.ENETUNREACH, errno.ENETDOWN, errno.EADDRNOTAVAIL, errno.EHOSTUNREACH}


def is_local_failure(exc: BaseException) -> bool:
    return isinstance(exc, OSError) and exc.errno in LOCAL_ERRNOS


def _close_if_connected(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception() is None:
        task.result().close()


async def race(dial: Dial, wave_size: int, waves: int, wave_interval: float, deadline: float) -> RaceResult:
    """Run `dial` in waves until one succeeds or `deadline` seconds pass.

    A new wave starts every `wave_interval` seconds, or at once when every
    attempt in flight has already failed (fast refusals shouldn't wait).
    """
    loop = asyncio.get_running_loop()
    start = loop.time()
    pending: set[asyncio.Task] = set()
    launched_waves = attempts = failures = refused = local = 0
    winner = None

    def launch() -> None:
        nonlocal launched_waves, attempts
        launched_waves += 1
        for _ in range(wave_size):
            pending.add(asyncio.ensure_future(dial()))
            attempts += 1

    try:
        while winner is None:
            now = loop.time() - start
            if now >= deadline:
                break
            if launched_waves < waves and (not pending or now >= launched_waves * wave_interval):
                launch()
            if not pending:
                break
            wake = deadline
            if launched_waves < waves:
                wake = min(wake, launched_waves * wave_interval)
            done, _ = await asyncio.wait(pending, timeout=max(0.0, wake - now), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                pending.discard(task)
                if task.exception() is not None:
                    failures += 1
                    refused += isinstance(task.exception(), ConnectionRefusedError)
                    local += is_local_failure(task.exception())
                elif winner is None:
                    winner = task.result()
                else:
                    task.result().close()
    finally:
        for task in pending:
            task.cancel()
            task.add_done_callback(_close_if_connected)
    return RaceResult(winner, attempts, failures, loop.time() - start, refused, local)


async def dial_tcp6(addr: str, port: int, timeout: float,
                    prepare: Callable[[socket.socket], None] | None = None) -> socket.socket:
    """One non-blocking IPv6 TCP connect; `prepare` sets egress options (egress.py)."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        if prepare:
            prepare(sock)
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, (addr, port, 0, 0)), timeout)
    except BaseException:
        sock.close()
        raise
    return sock
