"""Serve one client connection: race IPv6 upstream, fall back to IPv4 by name."""

import asyncio
import ipaddress
import itertools
import logging
import socket
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from .config import Config
from .dns import A, AAAA, resolve
from .egress import Egress
from .race import dial_tcp6, is_local_failure, race
from .sniff import read_hello, server_name, valid_hostname

log = logging.getLogger("v6race")


@dataclass
class Stats:
    started: float = field(default_factory=time.time)
    connections: int = 0
    active: int = 0
    v6_ok: int = 0
    v6_first_wave: int = 0
    attempts: int = 0
    dead_skips: int = 0
    fallback_ok: int = 0
    abandoned: int = 0
    v4_only: int = 0
    failed: int = 0
    bytes_up: int = 0
    bytes_down: int = 0


class ExpiringSet:
    """Keys that expire after `ttl` seconds, at most `maxsize` of them (the
    oldest are dropped first)."""

    def __init__(self, ttl: float, maxsize: int = 4096):
        self.ttl = ttl
        self.maxsize = maxsize
        self._until: OrderedDict = OrderedDict()

    def is_dead(self, key) -> bool:
        until = self._until.get(key)
        if until is not None and until < time.monotonic():
            del self._until[key]
            return False
        return until is not None

    def mark(self, key) -> None:
        self._until.pop(key, None)
        self._until[key] = time.monotonic() + self.ttl
        while len(self._until) > self.maxsize:
            self._until.popitem(last=False)

    def clear(self, key) -> None:
        self._until.pop(key, None)

    def __len__(self) -> int:
        now = time.monotonic()
        return sum(1 for t in self._until.values() if t >= now)


class DeadPrefixes(ExpiringSet):
    """/64 prefixes where a whole race was silently dropped (e.g. blocked sites)."""

    @staticmethod
    def _key(addr: str) -> ipaddress.IPv6Network:
        return ipaddress.IPv6Network(f"{addr}/64", strict=False)

    def is_dead(self, addr: str) -> bool:
        return super().is_dead(self._key(addr))

    def mark(self, addr: str) -> None:
        super().mark(self._key(addr))

    def clear(self, addr: str) -> None:
        super().clear(self._key(addr))


class DeadNames(ExpiringSet):
    """(host, port) pairs whose direct IPv4 connect failed recently."""


class NoNetwork(OSError):
    """This host has no usable network right now: not evidence that the
    destination is blocked, so nothing gets remembered as dead."""


def mask(addr: str) -> str:
    """Keep the routing prefix for debugging, drop the host part."""
    try:
        return str(ipaddress.IPv6Network(f"{addr}/48", strict=False))
    except ValueError:
        return "?"


class Proxy:
    def __init__(self, cfg: Config, egress: Egress | None = None, direct_v4: bool = False):
        self.cfg = cfg
        self.egress = egress or Egress(fallback_dns=list(cfg.fallback_dns))
        self.direct_v4 = direct_v4
        self.stats = Stats()
        self.dead = DeadPrefixes(cfg.dead_ttl)
        self.v4_blocked = DeadNames(cfg.dead_ttl)
        self.via_mihomo: dict[str, int] = {}
        self._dns_cache: OrderedDict[tuple[str, int], tuple[float, list[str]]] = OrderedDict()

    def _show(self, addr: str) -> str:
        return addr if self.cfg.log_addresses else mask(addr)

    async def dial_v6(self, addr: str, port: int) -> socket.socket:
        return await dial_tcp6(addr, port, self.cfg.connect_timeout, self.egress.prepare)

    async def lookup(self, host: str, qtype: int) -> list[str] | None:
        """Resolve on the physical network's DNS (not the system resolver,
        which a proxy client may answer with fake IPs). Cached briefly.
        None if no resolver answered at all."""
        now = time.monotonic()
        key = (host, qtype)
        hit = self._dns_cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        addrs = await resolve(host, self.egress.dns_servers(), qtype, self.egress.prepare,
                              fallback=self.egress.fallback_dns)
        if addrs is None:  # no server answered: don't remember it as "no records"
            return None
        self._dns_cache.pop(key, None)
        self._dns_cache[key] = (now + (60 if addrs else 10), addrs)
        while len(self._dns_cache) > 4096:
            self._dns_cache.popitem(last=False)
        return addrs

    async def dial_v4(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, bool]:
        """Returns (reader, writer, via_mihomo). A via-Mihomo connection holds
        the loop guard for `host` until the caller releases it."""
        if not self.direct_v4:
            # SOCKS test mode: plain connect by name (through Mihomo if it is on).
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, family=socket.AF_INET), 10)
            return r, w, False
        # 1. Direct IPv4 around Mihomo: right for Mihomo's own DIRECT dials and
        #    for everything when Mihomo is off.
        if not self.v4_blocked.is_dead((host, port)):
            try:
                r, w = await self.dial_v4_direct(host, port)
                return r, w, False
            except NoNetwork:
                raise  # say nothing about the site; next time try direct again
            except (OSError, TimeoutError) as e:
                self.v4_blocked.mark((host, port))
                # errno only by default: the message can contain addresses.
                log.info("direct IPv4 to %s failed: %s errno=%s; trying Mihomo",
                         host if self.cfg.log_addresses else "<host>", type(e).__name__, getattr(e, "errno", None))
        # 2. By name through Mihomo, so its rules apply: right for apps that
        #    bypassed fake-ip and reached a blocked site over IPv6. If Mihomo
        #    sends it DIRECT, its IPv6 dial comes straight back here, and a
        #    returning connection can't be told apart from a new one. So cap
        #    the connections to `host` that are going through Mihomo, for as
        #    long as they live: a loop stops at the cap, ordinary parallel
        #    connections to one site still fit under it.
        if not self.cfg.mihomo_proxy or self.via_mihomo.get(host, 0) >= MIHOMO_PER_HOST:
            raise OSError("no fallback left")
        self.via_mihomo[host] = self.via_mihomo.get(host, 0) + 1
        try:
            r, w = await self.dial_via_proxy(host, port)
        except BaseException:
            self.release_mihomo(host)
            raise
        return r, w, True

    def release_mihomo(self, host: str) -> None:
        self.via_mihomo[host] -= 1
        if not self.via_mihomo[host]:
            del self.via_mihomo[host]

    async def dial_v4_direct(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        # Resolve and connect around any proxy TUN: through the system resolver
        # and Mihomo, the fallback could come straight back to v6race (dns.py).
        try:
            addrs = [str(ipaddress.IPv4Address(host))]
        except ValueError:
            addrs = await self.lookup(host, A)
        if addrs is None:
            raise NoNetwork("no DNS server answered")
        if not addrs:
            raise OSError("no A record")
        loop = asyncio.get_running_loop()
        local = 0
        for addr in addrs[:2]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setblocking(False)
                self.egress.prepare(sock)
                await asyncio.wait_for(loop.sock_connect(sock, (addr, port)), 2)
                return await asyncio.open_connection(sock=sock)  # the transport owns it now
            except (OSError, TimeoutError) as e:
                sock.close()
                local += is_local_failure(e)
            except BaseException:  # cancelled: don't leave the socket to the GC
                sock.close()
                raise
        raise NoNetwork("no route") if local else OSError("IPv4 connect failed")

    async def open_named(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Proxy mode: the client names the destination. Race its IPv6
        addresses; fall back to IPv4 directly (the client already chose direct)."""
        cfg, st = self.cfg, self.stats
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            ip = None
        if ip is None and not valid_hostname(host):
            raise OSError("invalid host name")
        if ip is not None and ip.version == 4:
            r, w = await self.dial_v4_direct(str(ip), port)
            st.fallback_ok += 1
            return r, w
        if ip is not None:
            v6 = [str(ip)]
        elif self.v4_only(host):
            st.v4_only += 1
            v6 = []
        else:
            v6 = await self.lookup(host, AAAA) or []
        live = [a for a in v6 if not self.dead.is_dead(a)]
        st.dead_skips += bool(v6) and not live
        if live:
            addrs = itertools.cycle(live)
            result = await race(lambda: self.dial_v6(next(addrs), port), cfg.wave_size, cfg.waves,
                                cfg.wave_interval, cfg.connect_timeout)
            st.attempts += result.attempts
            if result.sock is not None:
                st.v6_ok += 1
                st.v6_first_wave += result.elapsed < cfg.wave_interval
                return await asyncio.open_connection(sock=result.sock)
            if result.blocked():
                for a in live[:result.attempts]:
                    self.dead.mark(a)
            log.info("v6 race failed: %s port %d, %d attempts", self._show(live[0]), port, result.attempts)
        if ip is not None:
            raise OSError("IPv6 destination unreachable")
        r, w = await self.dial_v4_direct(host, port)
        st.fallback_ok += 1
        return r, w

    async def serve_named(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int,
                          reply: Callable[[bool], Awaitable[None]], first: bytes = b"") -> None:
        """Open `host`, tell the client how it went (`reply`), then relay.
        `first` is sent upstream before the client's remaining bytes."""
        st = self.stats
        st.connections += 1
        st.active += 1
        try:
            try:
                up_reader, up_writer = await self.open_named(host, port)
            except (OSError, TimeoutError) as e:
                st.failed += 1
                log.info("open failed: %s port %d: %s", host if self.cfg.log_addresses else "<host>", port,
                         type(e).__name__)
                await reply(False)
                return
            try:
                await reply(True)
            except BaseException:
                up_writer.transport.abort()
                raise
            if first:
                up_writer.write(first)
                st.bytes_up += len(first)
            await relay(reader, writer, up_reader, up_writer, st)
        finally:
            st.active -= 1
            if not writer.is_closing():
                writer.transport.abort()

    async def dial_via_proxy(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """HTTP CONNECT through Mihomo's mixed port."""
        phost, _, pport = self.cfg.mihomo_proxy.rpartition(":")
        reader, writer = await asyncio.wait_for(asyncio.open_connection(phost, int(pport)), 2)
        try:
            writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
            if head.split(b" ", 2)[1:2] != [b"200"]:
                raise OSError(f"proxy refused: {head.split(b'\r\n', 1)[0].decode('ascii', 'replace')}")
        except BaseException:
            writer.transport.abort()
            raise
        return reader, writer

    def v4_only(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.cfg.v4_only)

    async def _name(self, hello_task: asyncio.Task, hello: bytearray, host: str | None, timeout: float) -> str | None:
        if host is None:
            try:
                await asyncio.wait_for(asyncio.shield(hello_task), timeout)
            except TimeoutError:
                pass
            host = server_name(bytes(hello))
        return host

    @staticmethod
    async def _drop_race(race_task: asyncio.Task) -> None:
        """Stop a race whose result won't be used, closing its winner if any."""
        race_task.cancel()
        await asyncio.gather(race_task, return_exceptions=True)
        if not race_task.cancelled() and race_task.exception() is None and race_task.result().sock:
            race_task.result().sock.close()

    def full(self) -> bool:
        return self.stats.active >= self.cfg.max_connections

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr: str, port: int,
                    host: str | None = None, local: bool = False) -> None:
        """`local`: the destination is one of this host's own addresses; one
        plain connect, no race (a local service shouldn't see 4-8 connections)."""
        cfg, st = self.cfg, self.stats
        st.connections += 1
        st.active += 1
        hello = bytearray()
        hello_task = asyncio.create_task(read_hello(reader, hello))
        race_task = None
        sock = None
        guard = False
        use_v4 = None  # why IPv6 is skipped: "dead" or "v4_only"
        try:
            if host is not None and self.v4_only(host):
                use_v4 = "v4_only"
            elif self.dead.is_dead(addr):
                # Skip IPv6 only if the client's first bytes name the host;
                # otherwise (ssh, server-first protocols) racing is the only way.
                host = await self._name(hello_task, hello, host, cfg.hello_timeout)
                if host is not None:
                    use_v4 = "v4_only" if self.v4_only(host) else "dead"

            if use_v4 is None:
                race_task = asyncio.ensure_future(race(lambda: self.dial_v6(addr, port),
                                                       1 if local else cfg.wave_size, 1 if local else cfg.waves,
                                                       cfg.wave_interval, cfg.connect_timeout))
                done, _ = await asyncio.wait({race_task, hello_task}, return_when=asyncio.FIRST_COMPLETED)
                if race_task not in done:
                    name = host or server_name(bytes(hello))
                    if not hello and reader.at_eof():
                        # The client left before sending anything, e.g. Mihomo's
                        # tcp-concurrent closing the dials it didn't pick.
                        st.abandoned += 1
                        return
                    if name is not None and self.v4_only(name):
                        use_v4, host = "v4_only", name
                        await self._drop_race(race_task)

            if use_v4 is None:
                result = await race_task
                st.attempts += result.attempts
                sock = result.sock
                if sock is not None:
                    self.dead.clear(addr)
                    # The race won before the client's first bytes arrived
                    # (they normally follow the accept within a millisecond):
                    # check the IPv4-only list before using the connection.
                    name = await self._name(hello_task, hello, host, SNIFF_GRACE)
                    if name is not None and self.v4_only(name):
                        sock.close()
                        sock, use_v4, host = None, "v4_only", name
                    else:
                        st.v6_ok += 1
                        st.v6_first_wave += result.elapsed < cfg.wave_interval
                else:
                    if result.blocked():
                        self.dead.mark(addr)
                    log.info("v6 race failed: %s port %d, %d attempts", self._show(addr), port, result.attempts)
            st.v4_only += use_v4 == "v4_only"
            st.dead_skips += use_v4 == "dead"

            if sock is not None:
                up_reader, up_writer = await asyncio.open_connection(sock=sock)
                sock = None  # the transport owns it now
            else:
                host = await self._name(hello_task, hello, host, cfg.hello_timeout)
                if host is None:
                    st.failed += 1
                    return
                try:
                    up_reader, up_writer, guard = await self.dial_v4(host, port)
                except (OSError, TimeoutError, asyncio.IncompleteReadError) as e:
                    st.failed += 1
                    log.info("v4 fallback failed: %s port %d: %s", host if cfg.log_addresses else "<host>", port,
                             type(e).__name__)
                    return
                st.fallback_ok += 1

            hello_task.cancel()
            await asyncio.gather(hello_task, return_exceptions=True)
            if hello:
                up_writer.write(bytes(hello))
                st.bytes_up += len(hello)
            await relay(reader, writer, up_reader, up_writer, st)
        finally:
            hello_task.cancel()
            if race_task is not None and sock is None and not (race_task.done() and use_v4 is None):
                await self._drop_race(race_task)
            if sock is not None:
                sock.close()
            if guard:
                self.release_mihomo(host)
            st.active -= 1
            if not writer.is_closing():
                writer.transport.abort()


SNIFF_GRACE = 0.3
HALF_CLOSED_IDLE = 60.0
MIHOMO_PER_HOST = 8


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, other: asyncio.StreamWriter,
                st: Stats, field: str, seen: list[float]) -> bool:
    """Copy until EOF and pass the EOF on. True on a clean end."""
    loop = asyncio.get_running_loop()
    try:
        while data := await src.read(65536):
            dst.write(data)
            await dst.drain()
            setattr(st, field, getattr(st, field) + len(data))  # live, not at close
            seen[0] = loop.time()
        if dst.can_write_eof():
            dst.write_eof()
        return True
    except (OSError, RuntimeError):
        dst.transport.abort()
        other.transport.abort()
        return False


async def relay(c_reader, c_writer, u_reader, u_writer, st: Stats) -> None:
    """Copy both ways, passing half-closes through. Once one direction has
    ended, give up on the other after HALF_CLOSED_IDLE seconds without data:
    some peers (or Mihomo in between) never answer a half-close."""
    loop = asyncio.get_running_loop()
    seen = [loop.time()]
    pipes = {asyncio.ensure_future(_pipe(c_reader, u_writer, c_writer, st, "bytes_up", seen)),
             asyncio.ensure_future(_pipe(u_reader, c_writer, u_writer, st, "bytes_down", seen))}
    clean = False
    try:
        _, pending = await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
        while pending:
            _, pending = await asyncio.wait(pending, timeout=HALF_CLOSED_IDLE)
            if pending and loop.time() - seen[0] >= HALF_CLOSED_IDLE:
                break
        clean = not pending and all(t.result() for t in pipes)
    finally:
        for task in pipes:
            task.cancel()
        await asyncio.gather(*pipes, return_exceptions=True)
        await _close(u_writer, c_writer, graceful=clean)


async def _close(*writers: asyncio.StreamWriter, graceful: bool) -> None:
    """After a clean end, close normally so buffered data still goes out
    (abort() would drop it); otherwise, or if that stalls, abort."""
    if graceful:
        for w in writers:
            w.close()
        try:
            await asyncio.wait_for(asyncio.gather(*(w.wait_closed() for w in writers), return_exceptions=True), 10)
            return
        except TimeoutError:
            pass
    for w in writers:
        w.transport.abort()
