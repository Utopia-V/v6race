"""Minimal A-record lookup over UDP, sent with the bypass mark.

The IPv4 fallback can't use the system resolver: with Mihomo on, that returns
fake-ip addresses, and connecting to them sends the fallback back into Mihomo,
which (with dns.ipv6 on) dials IPv6 again and lands in v6race again: a loop.
"""

import asyncio
import random
import socket
import struct
from collections.abc import Callable
from pathlib import Path

RESOLVED_UPSTREAMS = Path("/run/systemd/resolve/resolv.conf")


def system_upstreams(path: Path = RESOLVED_UPSTREAMS) -> list[str]:
    """IPv4 upstream servers systemd-resolved uses (e.g. the campus DNS from
    DHCP), which the network can't block the way it may block public DNS."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver" and "." in parts[1] and not parts[1].startswith("127."):
            out.append(parts[1])
    return out


A, AAAA = 1, 28


def build_query(name: str, qid: int, qtype: int = A) -> bytes:
    # Encode first, then measure: a label's length field counts the encoded bytes.
    labels = name.rstrip(".").encode("idna").split(b".")
    if any(not 0 < len(label) <= 63 for label in labels) or sum(len(l) + 1 for l in labels) > 254:
        raise ValueError("invalid domain name")
    qname = b"".join(bytes([len(label)]) + label for label in labels)
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + b"\x00" + struct.pack("!HH", qtype, 1)


def _skip_name(msg: bytes, p: int) -> int:
    while True:
        n = msg[p]
        if n == 0:
            return p + 1
        if n & 0xC0 == 0xC0:
            return p + 2
        p += 1 + n


def parse_answers(msg: bytes, qid: int, qtype: int = A) -> list[str] | None:
    """Addresses of `qtype` in the answer section (CNAME chains included).
    None if this isn't a valid answer to our query; [] if the name has none."""
    rid, flags, qd, an = struct.unpack("!HHHH", msg[:8])
    if rid != qid or not flags & 0x8000:
        return None
    if flags & 0x0200:  # truncated: not a complete answer; let another server win
        return None
    rcode = flags & 0x000F
    if rcode not in (0, 3):  # NOERROR, NXDOMAIN
        return None
    p = 12
    for _ in range(qd):
        p = _skip_name(msg, p) + 4
    out = []
    size, family = (4, socket.AF_INET) if qtype == A else (16, socket.AF_INET6)
    for _ in range(an):
        p = _skip_name(msg, p)
        rtype, _, _, rdlen = struct.unpack("!HHIH", msg[p : p + 10])
        p += 10
        if rtype == qtype and rdlen == size:
            out.append(socket.inet_ntop(family, msg[p : p + size]))
        p += rdlen
    return out


def parse_a(msg: bytes, qid: int) -> list[str]:
    return parse_answers(msg, qid, A) or []


async def resolve(name: str, servers: list[str], qtype: int = A,
                  prepare: Callable[[socket.socket], None] | None = None, timeout: float = 2.0,
                  fallback: list[str] | None = None, fallback_after: float = 1.0) -> list[str] | None:
    """Ask `servers` at once; the first valid answer wins (an empty answer
    counts: a name without AAAA records is an answer, not a failure). The
    `fallback` servers are asked only once the others have all failed or
    `fallback_after` seconds have passed, so public resolvers don't see every
    name. None if nobody answered."""
    loop = asyncio.get_running_loop()

    async def ask(server: str) -> list[str]:
        qid = random.getrandbits(16)
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            if prepare:
                prepare(sock)
            await loop.sock_connect(sock, (server, 53))
            await loop.sock_sendall(sock, build_query(name, qid, qtype))
            while True:
                answer = parse_answers(await loop.sock_recv(sock, 4096), qid, qtype)
                if answer is not None:
                    return answer
        finally:
            sock.close()

    start = loop.time()
    deadline, fallback_at = start + timeout, start + fallback_after
    pending = {asyncio.ensure_future(ask(s)) for s in servers}
    later = list(fallback or [])
    try:
        while True:
            now = loop.time()
            if later and (not pending or now >= fallback_at):
                pending |= {asyncio.ensure_future(ask(s)) for s in later}
                later = []
            if not pending or now >= deadline:
                break
            wake = min(deadline, fallback_at) if later else deadline
            done, pending = await asyncio.wait(pending, timeout=max(0.0, wake - now),
                                               return_when=asyncio.FIRST_COMPLETED)
            for fut in done:
                try:
                    return fut.result()
                except (OSError, struct.error, IndexError, ValueError):
                    continue
    finally:
        for t in pending:
            t.cancel()
    return None


async def resolve_a(name: str, servers: list[str], mark: int = 0, timeout: float = 2.0) -> list[str]:
    def prepare(sock):
        if mark:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    return await resolve(name, servers, A, prepare, timeout) or []
