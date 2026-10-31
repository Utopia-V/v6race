"""Proxy mode end to end over loopback: SOCKS5 and HTTP clients -> v6race -> upstream."""

import asyncio
import struct

from v6race.config import Config
from v6race.dns import AAAA
from v6race.proxy import Proxy
from v6race.server import proxy_handler


async def echo_server(host: str):
    async def handle(r, w):
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
        w.close()

    server = await asyncio.start_server(handle, host, 0)
    return server, server.sockets[0].getsockname()[1]


def make_proxy(names: dict, **kw) -> Proxy:
    """`names`: host -> (AAAA list, A list). DNS goes nowhere."""
    cfg = Config(**(dict(wave_size=2, waves=2, wave_interval=0.1, connect_timeout=0.3) | kw))
    proxy = Proxy(cfg)
    proxy.lookups = []

    async def lookup(host, qtype):
        proxy.lookups.append((host, qtype))
        v6, v4 = names.get(host, ([], []))
        return v6 if qtype == AAAA else v4

    proxy.lookup = lookup
    return proxy


async def front(proxy: Proxy):
    server = await asyncio.start_server(proxy_handler(proxy), "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def socks_connect(port: int, host: str, dport: int):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"\x05\x01\x00")
    assert await r.readexactly(2) == b"\x05\x00"
    name = host.encode()
    w.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", dport))
    reply = await r.readexactly(10)
    return r, w, reply[1]


async def test_socks_name_with_aaaa_is_raced_over_ipv6():
    up, uport = await echo_server("::1")
    proxy = make_proxy({"v6.example": (["::1"], ["127.0.0.1"])})
    srv, port = await front(proxy)
    r, w, code = await socks_connect(port, "v6.example", uport)
    assert code == 0
    w.write(b"ping")
    assert await r.readexactly(4) == b"ping"
    w.close()
    assert proxy.stats.v6_ok == 1 and proxy.stats.fallback_ok == 0
    srv.close()
    up.close()


async def test_http_connect_without_aaaa_falls_back_to_ipv4():
    up, uport = await echo_server("127.0.0.1")
    proxy = make_proxy({"v4.example": ([], ["127.0.0.1"])})
    srv, port = await front(proxy)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(f"CONNECT v4.example:{uport} HTTP/1.1\r\nHost: v4.example:{uport}\r\n\r\n".encode())
    assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 200")
    w.write(b"hello")
    assert await r.readexactly(5) == b"hello"
    w.close()
    assert proxy.stats.fallback_ok == 1 and proxy.stats.v6_ok == 0
    srv.close()
    up.close()


async def test_plain_http_is_forwarded_in_origin_form():
    seen = []

    async def web(r, w):
        seen.append(await r.readuntil(b"\r\n\r\n"))
        w.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await w.drain()
        w.close()

    up = await asyncio.start_server(web, "127.0.0.1", 0)
    uport = up.sockets[0].getsockname()[1]
    proxy = make_proxy({"web.example": ([], ["127.0.0.1"])})
    srv, port = await front(proxy)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(f"GET http://web.example:{uport}/a?b=1 HTTP/1.1\r\nHost: web.example\r\n"
            "Proxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n".encode())
    assert (await asyncio.wait_for(r.read(), 5)).startswith(b"HTTP/1.1 204")
    head = seen[0].decode()
    assert head.startswith("GET /a?b=1 HTTP/1.1\r\n")
    assert "Proxy-Connection" not in head and "keep-alive" not in head and "Connection: close" in head
    srv.close()
    up.close()


async def test_ipv4_only_sites_skip_the_aaaa_lookup():
    up, uport = await echo_server("127.0.0.1")
    proxy = make_proxy({"pay.bank.example": (["::1"], ["127.0.0.1"])}, v4_only=["bank.example"])
    srv, port = await front(proxy)
    r, w, code = await socks_connect(port, "pay.bank.example", uport)
    assert code == 0
    w.close()
    assert proxy.lookups == [("pay.bank.example", 1)] and proxy.stats.v4_only == 1
    srv.close()
    up.close()


async def test_unreachable_is_reported_to_the_client_and_dead_prefix_skipped():
    proxy = make_proxy({"gone.example": (["2001:db8::1"], [])})

    async def dropped(addr, port):  # silently dropped, like a blocked address
        await asyncio.sleep(3600)

    proxy.dial_v6 = dropped
    srv, port = await front(proxy)
    _, w, code = await socks_connect(port, "gone.example", 443)
    assert code == 4  # host unreachable
    w.close()
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"CONNECT gone.example:443 HTTP/1.1\r\n\r\n")
    assert (await r.readuntil(b"\r\n\r\n")).startswith(b"HTTP/1.1 502")
    w.close()
    assert proxy.stats.failed == 2 and proxy.stats.dead_skips == 1  # second time: no race
    srv.close()


async def test_http_uri_without_path_and_with_wrong_host_header():
    seen = []

    async def web(r, w):
        seen.append(await r.readuntil(b"\r\n\r\n"))
        w.write(b"HTTP/1.1 204 No Content\r\n\r\n")
        await w.drain()
        w.close()

    up = await asyncio.start_server(web, "127.0.0.1", 0)
    uport = up.sockets[0].getsockname()[1]
    proxy = make_proxy({"a.example": ([], ["127.0.0.1"])})
    srv, port = await front(proxy)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(f"GET http://a.example:{uport}?q=1 HTTP/1.1\r\nHost: b.example\r\n\r\n".encode())
    await asyncio.wait_for(r.read(), 5)
    head = seen[0].decode()
    assert head.startswith("GET /?q=1 HTTP/1.1\r\n")
    assert f"Host: a.example:{uport}\r\n" in head and "b.example" not in head
    srv.close()
    up.close()


async def test_socks_client_insisting_on_authentication_is_refused():
    proxy = make_proxy({})
    srv, port = await front(proxy)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(b"\x05\x01\x02")  # offers username/password only
    assert await r.readexactly(2) == b"\x05\xff"
    w.close()
    srv.close()


async def test_websocket_upgrade_keeps_its_connection_header():
    seen = []

    async def web(r, w):
        seen.append(await r.readuntil(b"\r\n\r\n"))
        w.close()

    up = await asyncio.start_server(web, "127.0.0.1", 0)
    uport = up.sockets[0].getsockname()[1]
    proxy = make_proxy({"ws.example": ([], ["127.0.0.1"])})
    srv, port = await front(proxy)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(f"GET http://ws.example:{uport}/chat HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\n\r\n".encode())
    await asyncio.wait_for(r.read(), 5)
    head = seen[0].decode()
    assert "Connection: Upgrade" in head and "Connection: close" not in head
    srv.close()
    up.close()
