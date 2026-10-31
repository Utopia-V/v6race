import ssl

from v6race.sniff import hello_complete, http_host, server_name, tls_sni


def client_hello(host: str) -> bytes:
    ctx = ssl.create_default_context()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out := ssl.MemoryBIO(), server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_sni_from_real_client_hello():
    hello = client_hello("mirrors.tuna.tsinghua.edu.cn")
    assert hello_complete(hello)
    assert tls_sni(hello) == "mirrors.tuna.tsinghua.edu.cn"


def test_partial_client_hello_is_incomplete_and_unparsed():
    hello = client_hello("example.com")
    assert not hello_complete(hello[:100])
    assert tls_sni(hello[:100]) is None


def test_http_host():
    req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\nAccept: */*\r\n\r\n"
    assert hello_complete(req)
    assert http_host(req) == "example.com"
    assert server_name(b"GET / HTTP/1.1\r\nhost: a.b\r\n\r\n") == "a.b"


def test_no_name():
    assert server_name(b"SSH-2.0-OpenSSH_9.6\r\n") is None
    assert server_name(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n") is None
    assert server_name(b"") is None


def test_names_with_control_characters_are_rejected():
    assert server_name(client_hello("ok.example")) == "ok.example"
    assert server_name(b"GET / HTTP/1.1\r\nHost: a b.example\r\n\r\n") is None
    from v6race.sniff import valid_hostname
    assert valid_hostname("xn--bcher-kva.example") and valid_hostname("_dmarc.example.com")
    assert not valid_hostname("x\r\nX-Injected: 1") and not valid_hostname("-bad.example") and not valid_hostname("")
