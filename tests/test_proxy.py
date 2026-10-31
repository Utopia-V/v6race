"""End to end over loopback: client -> Proxy.serve -> upstream echo server."""

import asyncio

from v6race.config import Config
from v6race.proxy import Proxy


async def echo_server(family_host: str):
    async def handle(r, w):
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
        w.close()

    server = await asyncio.start_server(handle, family_host, 0)
    return server, server.sockets[0].getsockname()[1]


async def serve_through(proxy: Proxy, addr: str, port: int, payload: bytes, host=None) -> bytes:
    """Connect a client to a one-shot listener whose connection goes through `proxy`."""
    async def on_client(r, w):
        await proxy.serve(r, w, addr, port, host=host)

    front = await asyncio.start_server(on_client, "::1", 0)
    r, w = await asyncio.open_connection("::1", front.sockets[0].getsockname()[1])
    w.write(payload)
    await w.drain()
    w.write_eof()
    out = await asyncio.wait_for(r.read(), 5)
    w.close()
    front.close()
    return out


def fast_cfg(**kw) -> Config:
    return Config(**(dict(wave_size=2, waves=2, wave_interval=0.1, connect_timeout=0.3, hello_timeout=0.3) | kw))


async def test_relays_over_v6():
    server, port = await echo_server("::1")
    proxy = Proxy(fast_cfg())
    data = b"x" * 300_000
    assert await serve_through(proxy, "::1", port, data) == data
    assert proxy.stats.v6_ok == 1 and proxy.stats.bytes_up == len(data)
    server.close()


async def test_falls_back_to_v4_by_name_and_remembers_dead_prefix():
    server, port = await echo_server("127.0.0.1")
    proxy = Proxy(fast_cfg())

    async def dead_v6(addr, port):
        await asyncio.sleep(3600)

    proxy.dial_v6 = dead_v6
    req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    assert await serve_through(proxy, "2001:db8::1", port, req) == req
    assert proxy.stats.fallback_ok == 1 and proxy.dead.is_dead("2001:db8::99")
    # Second connection to the same /64 skips the race entirely.
    assert await serve_through(proxy, "2001:db8::2", port, req) == req
    assert proxy.stats.dead_skips == 1
    server.close()


async def test_no_name_no_fallback():
    proxy = Proxy(fast_cfg())

    async def refused(addr, port):
        raise ConnectionRefusedError

    proxy.dial_v6 = refused
    assert await serve_through(proxy, "2001:db8::1", 22, b"SSH-2.0-x\r\n") == b""
    assert proxy.stats.failed == 1


async def test_half_closed_idle_connection_is_reaped(monkeypatch):
    import v6race.proxy as p
    monkeypatch.setattr(p, "HALF_CLOSED_IDLE", 0.2)

    async def silent(r, w):  # reads, never answers, never closes
        await r.read()
        await asyncio.sleep(3600)

    server = await asyncio.start_server(silent, "::1", 0)
    proxy = Proxy(fast_cfg())
    out = await asyncio.wait_for(serve_through(proxy, "::1", server.sockets[0].getsockname()[1], b"hi"), 2)
    assert out == b"" and proxy.stats.active == 0
    server.close()


async def test_dead_prefix_without_name_still_races():
    server, port = await echo_server("::1")
    proxy = Proxy(fast_cfg())
    proxy.dead.mark("::1")
    # No SNI/Host in the payload: racing is the only way, and it works.
    assert await serve_through(proxy, "::1", port, b"SSH-2.0-x\r\n") == b"SSH-2.0-x\r\n"
    assert proxy.stats.v6_ok == 1 and proxy.stats.dead_skips == 0
    server.close()


async def test_client_leaving_cancels_race():
    proxy = Proxy(fast_cfg(connect_timeout=5))
    dials = []

    async def slow(addr, port):
        dials.append(1)
        await asyncio.sleep(3600)

    proxy.dial_v6 = slow

    async def on_client(r, w):
        await proxy.serve(r, w, "2001:db8::1", 443)

    front = await asyncio.start_server(on_client, "::1", 0)
    r, w = await asyncio.open_connection("::1", front.sockets[0].getsockname()[1])
    w.close()  # like Mihomo dropping a tcp-concurrent loser
    for _ in range(50):
        await asyncio.sleep(0.02)
        if proxy.stats.active == 0:
            break
    assert proxy.stats.abandoned == 1 and proxy.stats.active == 0 and len(dials) == 2
    front.close()


async def connect_proxy_server(log: list):
    """Minimal HTTP CONNECT proxy that echoes after accepting."""
    async def handle(r, w):
        head = await r.readuntil(b"\r\n\r\n")
        log.append(head.split(b" ")[1].decode())
        w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
        w.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_direct_v4_failure_falls_back_to_mihomo_once():
    log = []
    server, pport = await connect_proxy_server(log)
    proxy = Proxy(fast_cfg(mihomo_proxy=f"127.0.0.1:{pport}"), direct_v4=True)
    direct_calls = []

    async def dead_v6(addr, port):
        raise ConnectionRefusedError

    async def blocked_v4(host, port):
        direct_calls.append(host)
        raise TimeoutError

    proxy.dial_v6 = dead_v6
    proxy.dial_v4_direct = blocked_v4
    req = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n"
    assert await serve_through(proxy, "2001:db8::1", 443, req) == req
    assert log == ["blocked.example:443"] and proxy.stats.fallback_ok == 1
    # Direct IPv4 is remembered as blocked: the second time goes straight to Mihomo.
    assert await serve_through(proxy, "2001:db8::1", 443, req) == req
    assert direct_calls == ["blocked.example"] and len(log) == 2
    # At the cap of connections going through Mihomo for one host, a loop stops.
    import v6race.proxy as p
    for _ in range(50):  # let the previous connection's server side finish
        if not proxy.via_mihomo:
            break
        await asyncio.sleep(0.02)
    proxy.via_mihomo["blocked.example"] = p.MIHOMO_PER_HOST
    assert await serve_through(proxy, "2001:db8::1", 443, req) == b""
    assert len(log) == 2 and proxy.stats.failed == 1
    server.close()


async def test_v4_only_site_never_uses_ipv6():
    v6_server, v6_port = await echo_server("::1")
    v4_server, v4_port = await echo_server("127.0.0.1")
    req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    proxy = Proxy(fast_cfg(v4_only=["localhost"]))

    # The race would win, but the IPv4-only name arrives first: IPv4 is used.
    async def via_v6_port(addr, port):
        return await Proxy.dial_v6(proxy, "::1", v6_port)

    proxy.dial_v6 = via_v6_port
    assert await serve_through(proxy, "2001:db8::1", v4_port, req) == req
    assert proxy.stats.v4_only == 1 and proxy.stats.fallback_ok == 1

    # The race wins before the client speaks: the IPv6 connection is dropped
    # once the name shows up, and IPv4 is used.
    async def on_client(r, w):
        await proxy.serve(r, w, "2001:db8::1", v4_port)

    front = await asyncio.start_server(on_client, "::1", 0)
    r, w = await asyncio.open_connection("::1", front.sockets[0].getsockname()[1])
    await asyncio.sleep(0.1)
    w.write(req)
    w.write_eof()
    assert await asyncio.wait_for(r.read(), 5) == req
    assert proxy.stats.v4_only == 2 and proxy.stats.v6_ok == 0  # the IPv6 win was not used
    front.close()
    v6_server.close()
    v4_server.close()


async def test_mihomo_guard_is_held_while_the_connection_lives():
    log = []
    server, pport = await connect_proxy_server(log)
    proxy = Proxy(fast_cfg(mihomo_proxy=f"127.0.0.1:{pport}"), direct_v4=True)

    async def refused(addr, port):
        raise ConnectionRefusedError

    async def blocked_v4(host, port):
        raise TimeoutError

    proxy.dial_v6, proxy.dial_v4_direct = refused, blocked_v4

    async def on_client(r, w):
        await proxy.serve(r, w, "2001:db8::1", 443)

    front = await asyncio.start_server(on_client, "::1", 0)
    r, w = await asyncio.open_connection("::1", front.sockets[0].getsockname()[1])
    w.write(b"GET / HTTP/1.1\r\nHost: loop.example\r\n\r\n")
    await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 5)  # echoed back: relay is up
    assert proxy.via_mihomo == {"loop.example": 1}
    w.close()
    for _ in range(50):
        await asyncio.sleep(0.02)
        if not proxy.via_mihomo:
            break
    assert proxy.via_mihomo == {}
    front.close()
    server.close()


async def test_closed_port_does_not_mark_the_prefix_dead():
    proxy = Proxy(fast_cfg())

    async def refused(addr, port):
        raise ConnectionRefusedError

    proxy.dial_v6 = refused
    assert await serve_through(proxy, "2001:db8::1", 1, b"SSH-2.0-x\r\n") == b""
    assert not proxy.dead.is_dead("2001:db8::2")


async def test_large_response_after_client_half_close_is_not_truncated():
    payload = b"z" * 2_000_000

    async def server(r, w):
        await r.read()  # wait for the client's EOF, then answer a lot
        w.write(payload)
        await w.drain()
        w.close()

    up = await asyncio.start_server(server, "::1", 0)
    proxy = Proxy(fast_cfg())
    assert await serve_through(proxy, "::1", up.sockets[0].getsockname()[1], b"get") == payload
    assert proxy.stats.bytes_down == len(payload)
    up.close()


async def test_an_outage_is_not_remembered_as_a_block():
    import errno
    proxy = Proxy(fast_cfg(), direct_v4=True)

    async def no_route(addr, port):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")

    async def v4_down(host, port):
        from v6race.proxy import NoNetwork
        raise NoNetwork("no DNS server answered")

    proxy.dial_v6, proxy.dial_v4_direct = no_route, v4_down
    req = b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n"
    await serve_through(proxy, "2001:db8::1", 443, req)
    assert not proxy.dead.is_dead("2001:db8::1")                 # Wi-Fi was reconnecting:
    assert not proxy.v4_blocked.is_dead(("site.example", 443))   # nothing is remembered


async def test_switching_to_ipv4_drops_the_ipv6_race():
    v6_server, v6_port = await echo_server("::1")
    v4_server, v4_port = await echo_server("127.0.0.1")
    proxy = Proxy(fast_cfg(v4_only=["localhost"], wave_interval=0.05))
    opened = []

    async def slow_v6(addr, port):
        await asyncio.sleep(0.2)  # wins only after the client has spoken
        s = await Proxy.dial_v6(proxy, "::1", v6_port)
        opened.append(s)
        return s

    proxy.dial_v6 = slow_v6
    req = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    assert await serve_through(proxy, "2001:db8::1", v4_port, req) == req
    await asyncio.sleep(0.3)
    assert all(s.fileno() == -1 for s in opened)  # no IPv6 winner left open
    v6_server.close()
    v4_server.close()
