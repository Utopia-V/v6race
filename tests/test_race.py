import asyncio
import random
import socket

import pytest

from v6race.race import race


class FakeNet:
    """Each dial independently connects after `delay` or hangs/refuses."""

    def __init__(self, outcomes):
        self.outcomes = iter(outcomes)
        self.opened: list[socket.socket] = []

    async def dial(self):
        kind, delay = next(self.outcomes)
        await asyncio.sleep(delay)
        if kind == "ok":
            s = socket.socket()
            self.opened.append(s)
            return s
        if kind == "refuse":
            raise ConnectionRefusedError
        await asyncio.sleep(3600)  # silent drop


def plan(**kw):
    return dict(wave_size=4, waves=2, wave_interval=0.2, deadline=0.6) | kw


async def test_first_success_wins_and_others_are_closed():
    net = FakeNet([("drop", 0), ("ok", 0.05), ("ok", 0.01), ("drop", 0)])
    r = await race(net.dial, **plan(waves=1))
    assert r.sock is not None and r.attempts == 4
    await asyncio.sleep(0.1)  # let the slower success finish and be closed
    assert [s.fileno() == -1 for s in net.opened].count(False) == 1


async def test_second_wave_rescues_dead_first_wave():
    net = FakeNet([("drop", 0)] * 4 + [("ok", 0.01)] + [("drop", 0)] * 3)
    r = await race(net.dial, **plan())
    assert r.sock is not None and r.attempts == 8
    assert 0.2 <= r.elapsed < 0.4


async def test_fast_refusals_start_next_wave_at_once():
    net = FakeNet([("refuse", 0.01)] * 4 + [("ok", 0.01)] * 4)
    r = await race(net.dial, **plan())
    assert r.sock is not None and r.elapsed < 0.1 and r.failures == 4


async def test_all_fail_by_deadline():
    net = FakeNet([("drop", 0)] * 8)
    r = await race(net.dial, **plan())
    assert r.sock is None and r.attempts == 8
    assert 0.6 <= r.elapsed < 0.7


async def test_all_refused_returns_early():
    net = FakeNet([("refuse", 0.01)] * 8)
    r = await race(net.dial, **plan())
    assert r.sock is None and r.failures == 8 and r.elapsed < 0.1


@pytest.mark.parametrize("seed", range(3))
async def test_success_rate_on_half_dropping_network(seed):
    rng = random.Random(seed)
    wins = 0
    for _ in range(50):
        net = FakeNet([("ok" if rng.random() < 0.5 else "drop", 0.001) for _ in range(8)])
        wins += (await race(net.dial, **plan(wave_interval=0.01, deadline=0.05))).sock is not None
    assert wins >= 47  # expected 1 - 0.5**8 ≈ 99.6%
