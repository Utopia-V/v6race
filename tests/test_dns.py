import asyncio
import socket
import struct

from v6race.dns import build_query, parse_a, resolve_a


def answer(query: bytes, addrs: list[str], cname: bool = True) -> bytes:
    qid = query[:2]
    question = query[12:]
    rrs = b""
    count = 0
    if cname:  # www -> target via CNAME, then A records for the target
        target = b"\x06target\x07example\x00"
        rrs += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        count += 1
    for a in addrs:
        rrs += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
        count += 1
    return qid + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0) + question + rrs


def test_parse_follows_cname_and_checks_id():
    q = build_query("www.example.com", 0x1234)
    msg = answer(q, ["1.2.3.4", "5.6.7.8"])
    assert parse_a(msg, 0x1234) == ["1.2.3.4", "5.6.7.8"]
    assert parse_a(msg, 0x9999) == []


async def test_resolve_against_local_stub():
    loop = asyncio.get_running_loop()

    class Stub(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            self.t.sendto(answer(data, ["9.9.9.9"]), addr)

    transport, _ = await loop.create_datagram_endpoint(Stub, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    real_connect = loop.sock_connect
    try:
        # resolve_a always asks port 53; redirect that to the stub.
        async def connect(sock, addr):
            return await real_connect(sock, (addr[0], port) if addr[1] == 53 else addr)

        loop.sock_connect = connect
        assert await resolve_a("www.example.com", ["127.0.0.1"]) == ["9.9.9.9"]
        assert await resolve_a("www.example.com", ["127.0.0.2"], timeout=0.3) == []
    finally:
        loop.sock_connect = real_connect
        transport.close()


def test_system_upstreams_skips_loopback_and_ipv6(tmp_path):
    f = tmp_path / "resolv.conf"
    f.write_text("# generated\nnameserver 10.0.0.1\nnameserver 127.0.0.53\nnameserver 2001:db8::53\nnameserver 192.0.2.53\nsearch x\n")
    from v6race.dns import system_upstreams
    assert system_upstreams(f) == ["10.0.0.1", "192.0.2.53"]
    assert system_upstreams(tmp_path / "missing") == []


def test_parse_aaaa_and_empty_answers():
    from v6race.dns import AAAA, parse_answers
    q = build_query("v6.example", 7, AAAA)
    rr = b"\xc0\x0c" + struct.pack("!HHIH", 28, 1, 60, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    msg = q[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + q[12:] + rr
    assert parse_answers(msg, 7, AAAA) == ["2001:db8::1"]
    empty = q[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + q[12:]
    assert parse_answers(empty, 7, AAAA) == []          # no AAAA: an answer, not a failure
    servfail = q[:2] + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + q[12:]
    assert parse_answers(servfail, 7, AAAA) is None     # try another server


def test_query_lengths_count_encoded_bytes():
    q1 = build_query("xn--bcher-kva.example", 1)
    q2 = build_query("bücher.example", 1)
    assert q1 == q2 and q1[12] == len("xn--bcher-kva")
    import pytest
    with pytest.raises(ValueError):
        build_query("a" * 64 + ".example", 1)


def test_truncated_answer_does_not_count():
    from v6race.dns import AAAA, parse_answers
    q = build_query("big.example", 9, AAAA)
    truncated = q[:2] + struct.pack("!HHHHH", 0x8380, 1, 0, 0, 0) + q[12:]  # TC set, no answers
    assert parse_answers(truncated, 9, AAAA) is None


async def dns_stub(answer_with):
    """UDP DNS server on 127.0.0.1; `answer_with` None = never answer."""
    loop = asyncio.get_running_loop()
    seen = []

    class Stub(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            seen.append(data)
            if answer_with is not None:
                self.t.sendto(answer(data, answer_with), addr)

    transport, _ = await loop.create_datagram_endpoint(Stub, local_addr=("127.0.0.1", 0))
    return transport, transport.get_extra_info("sockname")[1], seen


async def resolve_via(ports: dict, *args, **kw):
    """Run resolve() with server "addresses" mapped to local stub ports."""
    from v6race.dns import resolve
    loop = asyncio.get_running_loop()
    real = loop.sock_connect

    async def connect(sock, addr):
        return await real(sock, ("127.0.0.1", ports[addr[0]]) if addr[1] == 53 else addr)

    loop.sock_connect = connect
    try:
        return await resolve(*args, **kw)
    finally:
        loop.sock_connect = real


async def test_public_fallback_only_after_the_network_resolver_fails():
    campus, cport, cseen = await dns_stub(["1.1.1.1"])
    public, pport, pseen = await dns_stub(["2.2.2.2"])
    ports = {"10.0.0.1": cport, "9.9.9.9": pport}
    assert await resolve_via(ports, "a.example", ["10.0.0.1"], fallback=["9.9.9.9"]) == ["1.1.1.1"]
    assert pseen == []  # the public resolver never saw the name
    campus.close()

    silent, sport, _ = await dns_stub(None)
    ports["10.0.0.1"] = sport
    loop = asyncio.get_running_loop()
    t = loop.time()
    assert await resolve_via(ports, "a.example", ["10.0.0.1"], fallback=["9.9.9.9"], fallback_after=0.2) == ["2.2.2.2"]
    assert 0.2 <= loop.time() - t < 1.0
    public.close()
    silent.close()


async def test_nobody_answering_is_none_not_empty():
    silent, sport, _ = await dns_stub(None)
    assert await resolve_via({"10.0.0.1": sport}, "a.example", ["10.0.0.1"], timeout=0.3) is None
    silent.close()
