import json

from v6race.winsys import (Adapter, ProxyState, choose_adapter, parse_network, proxy_taken, tun_adapters,
                           usable_dns)


def test_parse_network_handles_powershell_single_values():
    # ConvertTo-Json writes a one-element array property as a bare value.
    text = json.dumps({"adapters": [{"index": 12, "name": "WLAN", "description": "Intel Wi-Fi", "up": True,
                                     "hardware": True, "gateway4": True, "gateway6": True, "global6": True,
                                     "dns": "10.0.0.1"}], "clients": "clash-verge"})
    net = parse_network(text)
    assert net.adapters[0].dns == ["10.0.0.1"] and net.clients == ["clash-verge"]
    assert parse_network("").adapters == []


def test_choose_physical_adapter_with_ipv6_over_tun_and_vpn():
    tun = Adapter(30, "Mihomo", "Meta Tunnel", up=True, hardware=False, gateway4=True, gateway6=True, global6=True)
    eth = Adapter(5, "以太网", "Realtek", up=True, hardware=True, gateway4=True)
    wifi = Adapter(12, "WLAN", "Intel Wi-Fi", up=True, hardware=True, gateway4=True, gateway6=True, global6=True)
    down = Adapter(7, "WLAN 2", "USB Wi-Fi", up=False, hardware=True, gateway4=True, gateway6=True, global6=True)
    assert choose_adapter([tun, eth, wifi, down]) is wifi
    assert choose_adapter([tun, eth]) is eth
    assert choose_adapter([tun]) is None
    assert tun_adapters([tun, eth, wifi]) == [tun]


def test_usable_dns_drops_fake_and_local_addresses():
    assert usable_dns(["10.0.0.1", "198.18.0.2", "127.0.0.1", "fe80::1", "2001:da8::666", "x"]) == [
        "10.0.0.1", "2001:da8::666"]


def test_proxy_taken():
    ours = "127.0.0.1:10800"
    assert not proxy_taken(ProxyState(), ours)
    assert not proxy_taken(ProxyState(enable=1, server=ours), ours)
    assert proxy_taken(ProxyState(enable=1, server="127.0.0.1:7890"), ours)
    assert proxy_taken(ProxyState(autoconfig="http://127.0.0.1:33331/pac"), ours)
    assert not proxy_taken(ProxyState(enable=0, server="127.0.0.1:7890"), ours)


def test_teredo_is_not_a_proxy_client():
    teredo = Adapter(9, "Teredo Tunneling Pseudo-Interface", "Teredo Tunneling Pseudo-Interface", up=True)
    wintun = Adapter(30, "Clash", "Wintun Userspace Tunnel", up=True)
    assert tun_adapters([teredo, wintun]) == [wintun]
    assert usable_dns(["fec0:0:0:ffff::1"]) == []


def test_powershell_query_survives_encoding():
    import base64
    from v6race.winsys import PS_QUERY
    encoded = base64.b64encode(PS_QUERY.encode("utf-16-le"))
    assert base64.b64decode(encoded).decode("utf-16-le") == PS_QUERY
    assert len(encoded) < 8000  # well under the 32 767-character command-line limit


def fake_registry(monkeypatch, tmp_path, initial):
    """Stand-ins for the registry so the take/release/recover logic runs anywhere."""
    from v6race import winsys
    reg = {"proxy": initial, "run_once": None}
    monkeypatch.setattr(winsys, "read_proxy", lambda: ProxyState(**reg["proxy"].__dict__))
    monkeypatch.setattr(winsys, "write_proxy", lambda s: reg.__setitem__("proxy", ProxyState(**s.__dict__)))
    monkeypatch.setattr(winsys, "_set_run_once", lambda c: reg.__setitem__("run_once", c))
    monkeypatch.setattr(winsys, "backup_path", lambda: tmp_path / "v6race" / "proxy-backup.json")
    return winsys, reg


def test_take_and_release_restore_the_original(monkeypatch, tmp_path):
    original = ProxyState(enable=0, server="10.1.1.1:3128")
    winsys, reg = fake_registry(monkeypatch, tmp_path, original)
    sp = winsys.SystemProxy("127.0.0.1:10800")
    sp.take()
    assert reg["proxy"].server == "127.0.0.1:10800" and reg["proxy"].enable == 1
    assert reg["run_once"] and winsys.backup_path().exists()
    sp.release()
    assert reg["proxy"] == original and reg["run_once"] is None and not winsys.backup_path().exists()


def test_crash_is_undone_by_recover_without_network(monkeypatch, tmp_path):
    original = ProxyState(enable=1, server="10.1.1.1:3128", override="<local>")
    winsys, reg = fake_registry(monkeypatch, tmp_path, original)
    winsys.SystemProxy("127.0.0.1:10800").take()  # then the process dies
    assert winsys.recover() is True
    assert reg["proxy"] == original and reg["run_once"] is None and not winsys.backup_path().exists()
    assert winsys.recover() is False


def test_recover_leaves_a_proxy_someone_else_set_since(monkeypatch, tmp_path):
    winsys, reg = fake_registry(monkeypatch, tmp_path, ProxyState())
    winsys.SystemProxy("127.0.0.1:10800").take()
    reg["proxy"] = ProxyState(enable=1, server="127.0.0.1:7890")  # user started Clash afterwards
    assert winsys.recover() is False and reg["proxy"].server == "127.0.0.1:7890"


def test_partly_written_take_is_rolled_back(monkeypatch, tmp_path):
    # Proxy off but with a stale address left behind: turning it on part-way
    # (switch on, address not yet written) must not survive a failure.
    original = ProxyState(enable=0, server="127.0.0.1:59999")
    winsys, reg = fake_registry(monkeypatch, tmp_path, original)
    real_write = winsys.write_proxy
    calls = []

    def flaky(state):
        calls.append(state)
        if len(calls) == 1:
            reg["proxy"] = ProxyState(enable=1, server=original.server)  # half done
            raise OSError("registry write failed")
        real_write(state)

    monkeypatch.setattr(winsys, "write_proxy", flaky)
    sp = winsys.SystemProxy("127.0.0.1:10800")
    import pytest
    with pytest.raises(OSError):
        sp.take()
    assert reg["proxy"] == original
    assert sp.saved is None and not winsys.backup_path().exists() and reg["run_once"] is None


def test_failed_restore_keeps_the_backup_for_another_try(monkeypatch, tmp_path):
    original = ProxyState(enable=0)
    winsys, reg = fake_registry(monkeypatch, tmp_path, original)
    sp = winsys.SystemProxy("127.0.0.1:10800")
    sp.take()

    def broken(state):
        raise OSError("registry locked")

    monkeypatch.setattr(winsys, "write_proxy", broken)
    sp.release()
    assert winsys.backup_path().exists() and reg["run_once"]


def test_nothing_is_taken_once_release_has_begun(monkeypatch, tmp_path):
    winsys, reg = fake_registry(monkeypatch, tmp_path, ProxyState())
    sp = winsys.SystemProxy("127.0.0.1:10800")
    sp.release()  # the window was closed before take() got its turn
    assert sp.take() is False
    assert reg["proxy"] == ProxyState() and not winsys.backup_path().exists()


def test_unreadable_backup_is_kept_aside_not_deleted(monkeypatch, tmp_path):
    winsys, reg = fake_registry(monkeypatch, tmp_path, ProxyState())
    winsys.backup_path().parent.mkdir(parents=True)
    winsys.backup_path().write_text("{not json")
    assert winsys.recover() is False
    assert (tmp_path / "v6race" / "proxy-backup.unreadable.json").exists()


def test_readme_shows_the_same_client_snippet_as_the_console():
    from pathlib import Path
    from v6race.windows import CLIENT_SNIPPET
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    assert CLIENT_SNIPPET.format(port=10800) in readme
