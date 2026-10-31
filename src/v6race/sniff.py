"""Read the destination host name from a client's first bytes.

Used only when every IPv6 attempt failed: the client's handshake with us has
already completed, so the only way to reach the site over IPv4 is by name.
TLS clients put it in the ClientHello's SNI extension, HTTP clients in Host.
"""

import asyncio
import re

MAX_HELLO = 16384 + 5
_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOSTNAME = re.compile(rf"(?:{_LABEL}\.)*{_LABEL}\.?")


def valid_hostname(name: str) -> bool:
    """Plain DNS names only: the result goes into DNS queries and, as a last
    resort, into an HTTP CONNECT line, so no spaces or control characters."""
    return len(name) <= 253 and _HOSTNAME.fullmatch(name) is not None


def server_name(data: bytes) -> str | None:
    name = tls_sni(data) or http_host(data)
    return name if name is not None and valid_hostname(name) else None


def tls_sni(data: bytes) -> str | None:
    # TLS record: type(1)=0x16 handshake, version(2), length(2); then
    # handshake: type(1)=1 ClientHello, length(3), version(2), random(32),
    # session id, cipher suites, compression methods, extensions.
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None
        body = data[5 : 5 + int.from_bytes(data[3:5])]
        if body[0] != 1:
            return None
        p = 4 + 2 + 32
        p += 1 + body[p]
        p += 2 + int.from_bytes(body[p : p + 2])
        p += 1 + body[p]
        end = p + 2 + int.from_bytes(body[p : p + 2])
        p += 2
        while p + 4 <= end:
            ext_type = int.from_bytes(body[p : p + 2])
            ext_len = int.from_bytes(body[p + 2 : p + 4])
            p += 4
            if ext_type == 0:  # server_name: list length(2), name type(1)=0, name length(2), name
                if body[p + 2] != 0:
                    return None
                n = int.from_bytes(body[p + 3 : p + 5])
                name = body[p + 5 : p + 5 + n]
                return name.decode("ascii") if len(name) == n and n else None
            p += ext_len
    except (IndexError, UnicodeDecodeError):
        pass
    return None


def http_host(data: bytes) -> str | None:
    head, sep, _ = data.partition(b"\r\n\r\n")
    if not sep:
        return None
    lines = head.split(b"\r\n")
    if len(lines[0].split(b" ")) != 3:
        return None
    for line in lines[1:]:
        key, _, value = line.partition(b":")
        if key.strip().lower() == b"host":
            host = value.strip().decode("ascii", "replace")
            if host.startswith("["):  # [v6]:port has no name to fall back to
                return None
            return host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return None


def hello_complete(data: bytes) -> bool:
    if len(data) >= MAX_HELLO:
        return True
    if data[:1] == b"\x16":
        return len(data) >= 5 and len(data) >= 5 + int.from_bytes(data[3:5])
    return b"\r\n\r\n" in data or (len(data) >= 8 and not data[:8].isascii())


async def read_hello(reader: asyncio.StreamReader, buf: bytearray) -> None:
    """Accumulate the client's first message into `buf` (kept if cancelled)."""
    while not buf or not hello_complete(bytes(buf)):
        chunk = await reader.read(MAX_HELLO - len(buf))
        if not chunk:
            return
        buf += chunk
