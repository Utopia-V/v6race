"""Listeners: transparent (Linux TPROXY, needs CAP_NET_ADMIN) and proxy mode
(SOCKS5 + HTTP on one port, unprivileged, Linux and Windows)."""

import asyncio
import dataclasses
import json
import logging
import os
import signal
import socket
import struct
from pathlib import Path
from urllib.parse import urlsplit

from . import rules
from .config import Config
from .egress import Egress
from .proxy import Proxy

log = logging.getLogger("v6race")
IPV6_TRANSPARENT = 75
# Strong references to connection handlers, so a handler waiting on a future
# nobody else holds can't be garbage-collected mid-connection.
_handlers: set[asyncio.Task] = set()


def _track(handler):
    async def wrapped(reader, writer):
        task = asyncio.current_task()
        _handlers.add(task)
        try:
            await handler(reader, writer)
        finally:
            _handlers.discard(task)
    return wrapped


async def _write_status(proxy: Proxy, cfg: Config, mode: str) -> None:
    if not cfg.status_path:
        return
    path = Path(cfg.status_path)
    while True:
        data = dataclasses.asdict(proxy.stats) | {
            "mode": mode,
            "pid": os.getpid(),
            "dead_prefixes": len(proxy.dead),
            "rules_installed": rules.present(cfg) if mode == "transparent" else None,
        }
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data))
            tmp.replace(path)
        except OSError as e:
            log.warning("status file not written: %s", type(e).__name__)
        await asyncio.sleep(5)


def quiet_exceptions(cfg: Config) -> None:
    """asyncio's default handler logs transports with their full addresses;
    keep those for log_addresses mode only."""
    if cfg.log_addresses:
        return

    def handler(loop, context):
        exc = context.get("exception")
        log.warning("%s: %s", context.get("message", "error"), type(exc).__name__ if exc else "")

    asyncio.get_running_loop().set_exception_handler(handler)


async def _until_signal() -> None:
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
    except NotImplementedError:
        pass  # Windows: Ctrl+C arrives as KeyboardInterrupt from asyncio.run
    await stop.wait()


def is_local_address(addr: str) -> bool:
    """Whether `addr` is one of this host's addresses: only those can be bound
    without IP_TRANSPARENT. Intercepted connections keep the remote address."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
            probe.bind((addr, 0))
        return True
    except OSError:
        return False


def transparent_listener(port: int) -> socket.socket:
    """Needs CAP_NET_ADMIN (PermissionError without it)."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_TRANSPARENT, 1)
        sock.bind(("::", port))
    except BaseException:
        sock.close()
        raise
    return sock


async def run_transparent(cfg: Config) -> None:
    quiet_exceptions(cfg)
    proxy = Proxy(cfg, Egress(mark=cfg.bypass_mark, fallback_dns=list(cfg.fallback_dns)), direct_v4=True)
    sock = transparent_listener(cfg.port)

    async def on_client(reader, writer):
        addr, port = writer.get_extra_info("sockname")[:2]
        local = is_local_address(addr)
        if (local and port == cfg.port) or proxy.full():
            # A direct connection to the listener, not an intercepted one
            # (serving it would make v6race connect to itself, endlessly);
            # or too many connections already.
            writer.transport.abort()
            return
        await proxy.serve(reader, writer, addr, port, local=local)

    server = await asyncio.start_server(_track(on_client), sock=sock, backlog=1024)
    rules.up(cfg)
    log.info("transparent mode on port %d, rules installed", cfg.port)
    status = asyncio.create_task(_write_status(proxy, cfg, "transparent"))
    devices = asyncio.create_task(_sync_device_route(cfg))
    try:
        await _until_signal()
    finally:
        devices.cancel()
        status.cancel()
        server.close()
        for error in rules.down(cfg):
            log.error("cleanup: %s", error)
        log.info("rules removed, stopped")


async def _sync_device_route(cfg: Config) -> None:
    last = None
    while True:
        await asyncio.sleep(10)
        try:
            device = await asyncio.to_thread(rules.sync_device_route, cfg)
        except OSError as e:
            log.warning("device route check failed: %s", e)
            continue
        if device != last:
            log.info("loop-back route on device %s", device or "(none: no default IPv6 route)")
            last = device


async def run_proxy(cfg: Config, listen: str, egress: Egress, on_start=None, sock: socket.socket | None = None) -> None:
    """SOCKS5 and HTTP proxy on one port. The client names the destination;
    v6race races its IPv6 addresses and falls back to IPv4 itself. `sock`: an
    already bound listening socket (else bind `listen`)."""
    quiet_exceptions(cfg)
    proxy = Proxy(cfg, egress)
    if sock is not None:
        server = await asyncio.start_server(_track(proxy_handler(proxy)), sock=sock)
    else:
        host, _, port = listen.rpartition(":")
        server = await asyncio.start_server(_track(proxy_handler(proxy)), host.strip("[]"), int(port))
    log.info("proxy mode on %s", listen)
    status = asyncio.create_task(_write_status(proxy, cfg, "proxy"))
    try:
        if on_start:
            on_start(proxy)
        await _until_signal()
    finally:
        status.cancel()
        server.close()


def proxy_handler(proxy: Proxy):
    """Connection handler for proxy mode: SOCKS5 if the first byte is 5, else HTTP."""
    async def on_client(reader, writer):
        if proxy.full():
            writer.transport.abort()
            return
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 30)
        except (asyncio.IncompleteReadError, TimeoutError, OSError):
            writer.transport.abort()
            return
        try:
            if first == b"\x05":
                await _serve_socks(proxy, reader, writer)
            else:
                await _serve_http(proxy, first, reader, writer)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, OSError, TimeoutError):
            await _finish(writer)
    return on_client


async def _finish(writer) -> None:
    """Close after an error reply: let the reply go out first, briefly."""
    if writer.is_closing():
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (TimeoutError, OSError):
        writer.transport.abort()


async def _serve_socks(proxy: Proxy, reader, writer) -> None:
    name, port = await asyncio.wait_for(_socks_request(reader, writer), 30)

    async def reply(ok: bool) -> None:
        writer.write((b"\x05\x00" if ok else b"\x05\x04") + b"\x00\x01" + bytes(6))
        await writer.drain()

    await proxy.serve_named(reader, writer, name, port, reply)


async def _socks_request(reader, writer) -> tuple[str, int]:
    """The SOCKS5 greeting and CONNECT request (the version byte is already read)."""
    (n,) = await reader.readexactly(1)
    if 0 not in await reader.readexactly(n):  # we only do "no authentication"
        writer.write(b"\x05\xff")
        raise ValueError("client requires authentication")
    writer.write(b"\x05\x00")
    ver, cmd, _, atyp = await reader.readexactly(4)
    if ver != 5 or cmd != 1:
        writer.write(b"\x05\x07\x00\x01" + bytes(6))  # command not supported
        raise ValueError("only SOCKS5 CONNECT")
    if atyp == 1:
        name = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
    elif atyp == 4:
        name = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    elif atyp == 3:
        # Names arrive in ASCII (internationalized names as xn-- punycode).
        name = (await reader.readexactly((await reader.readexactly(1))[0])).decode("ascii")
    else:
        writer.write(b"\x05\x08\x00\x01" + bytes(6))  # address type not supported
        raise ValueError("bad address type")
    (port,) = struct.unpack("!H", await reader.readexactly(2))
    return name, port


async def _serve_http(proxy: Proxy, first: bytes, reader, writer) -> None:
    head = first + await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    request_line, _, rest = head.partition(b"\r\n")
    method, target, version = request_line.decode("latin-1").split(" ", 2)
    bad = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

    if method == "CONNECT":
        host, port = _split_host_port(target, 443)

        async def reply(ok: bool) -> None:
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n" if ok
                         else b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()

        await proxy.serve_named(reader, writer, host, port, reply)
        return

    # Plain HTTP: "GET http://host[:port]/path?query HTTP/1.1". Forward one
    # request in origin form with Host taken from the URI (RFC 9112 §3.2.2),
    # and close afterwards so a kept-alive client connection can't send a
    # second request for another host down this one.
    url = urlsplit(target)
    try:
        host, port = url.hostname, url.port or 80
    except ValueError:  # bad port
        host = None
    if url.scheme.lower() != "http" or not host or url.username or url.password:
        writer.write(bad)
        raise ValueError("not a plain-HTTP proxy request")
    path = (url.path or "/") + (f"?{url.query}" if url.query else "")
    authority = f"[{host}]" if ":" in host else host
    if url.port:
        authority += f":{url.port}"
    lines = [h for h in rest.split(b"\r\n") if h]
    # A WebSocket (or other) upgrade needs its Connection: Upgrade; after the
    # 101 the relay just carries the tunnel. Anything else gets one request.
    upgrade = any(h.lower().startswith(b"upgrade:") for h in lines)
    drop = (b"host:", b"proxy-connection:", b"proxy-authorization:", b"keep-alive:") + (() if upgrade else (b"connection:",))
    headers = [h for h in lines if not h.lower().startswith(drop)]
    forward = (f"{method} {path} {version}\r\nHost: {authority}\r\n".encode("latin-1")
               + b"".join(h + b"\r\n" for h in headers) + (b"" if upgrade else b"Connection: close\r\n") + b"\r\n")

    async def reply(ok: bool) -> None:
        if not ok:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()

    await proxy.serve_named(reader, writer, host, port, reply, first=forward)


def _split_host_port(authority: str, default: int) -> tuple[str, int]:
    if authority.startswith("["):  # [v6]:port
        host, _, port = authority[1:].partition("]")
        return host, int(port[1:]) if port.startswith(":") else default
    host, sep, port = authority.rpartition(":")
    if not sep or not port.isdigit():
        return authority, default
    return host, int(port)
