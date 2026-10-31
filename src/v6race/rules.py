"""Kernel side of the transparent mode: nftables table + policy routing.

Path of an intercepted connection:
1. output (route chain): a new TCP connection from this host to global IPv6
   (2000::/3) gets a conntrack mark; every packet of it in the original
   direction gets the intercept fwmark. The route chain makes the kernel
   look the route up again with that mark.
2. ip rule: fwmark intercept -> a table whose only route is `local ::/0 dev lo`,
   so the packet loops back into this host.
3. prerouting on lo: tproxy hands it to the v6race listener, which reads the
   original destination with getsockname().
v6race's own upstream sockets carry the bypass mark: step 1 skips them and an
ip rule routes them by the main table, ahead of Mihomo's TUN rules; if the
main table has no route, a second rule makes them fail rather than fall
through to the TUN. cleanup.py removes it all.
"""

import json
import subprocess

from . import cleanup

from .config import Config

TABLE = "v6race"


def nft_script(cfg: Config) -> str:
    m, b = hex(cfg.intercept_mark), hex(cfg.bypass_mark)
    quic = f"""
    chain quic {{
        type filter hook output priority filter; policy accept;
        meta mark {b} return
        ip6 daddr 2000::/3 udp dport 443 reject with icmpv6 type admin-prohibited
    }}""" if cfg.reject_quic else ""
    return f"""table ip6 {TABLE} {{
    chain output {{
        type route hook output priority mangle; policy accept;
        meta mark {b} return
        ip6 daddr != 2000::/3 return
        meta l4proto tcp ct state new tcp flags & (syn | ack) == syn ct mark set {m}
        meta l4proto tcp ct direction original ct mark {m} meta mark set {m}
    }}
    chain prerouting {{
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto tcp meta mark {m} tproxy to :{cfg.port} accept
    }}{quic}
}}
"""


def default_v6_device() -> str:
    out = subprocess.run(["ip", "-6", "route", "show", "default"], capture_output=True, text=True).stdout.split()
    return out[out.index("dev") + 1] if "dev" in out else ""


def params(cfg: Config) -> dict:
    """What cleanup.py needs to remove everything, recorded at install time."""
    return {"intercept_mark": cfg.intercept_mark, "bypass_mark": cfg.bypass_mark,
            "rule_priority": cfg.rule_priority, "route_table": cfg.route_table}


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=stdin, text=True, capture_output=True, check=True)


def up(cfg: Config) -> None:
    """Install everything, or nothing: any failure removes what was added."""
    p = params(cfg)
    # Remove leftovers first, as recorded (an earlier run may have used other
    # parameters), then by the current ones.
    leftovers = cleanup.down(cleanup.load_params()) + cleanup.down(p)
    if leftovers:
        raise RuntimeError("could not remove earlier rules: " + "; ".join(leftovers))
    try:
        for spec in cleanup.rule_specs(p):
            _run(["ip", spec[0], "rule", "add", *spec[2:]])
        _run(["ip", "-6", "route", "add", "local", "::/0", "dev", "lo", "table", str(cfg.route_table)])
        _run(["nft", "-f", "-"], stdin=nft_script(cfg))
        cleanup.STATE_PATH.write_text(json.dumps(p))
    except (subprocess.CalledProcessError, OSError) as e:
        cleanup.down(p)
        detail = e.stderr.strip() if isinstance(e, subprocess.CalledProcessError) else str(e)
        raise RuntimeError(f"installing rules failed: {detail}") from e
    sync_device_route(cfg)


def sync_device_route(cfg: Config) -> str:
    """Keep the loop-back route on the device that carries the default IPv6
    route: sockets bound to a device (Mihomo binds its dials to the Wi-Fi
    card) only match routes on that device. Run at start and periodically:
    the device can change, and a route goes away with its device."""
    table = str(cfg.route_table)
    want = cfg.interface or default_v6_device()
    have = []
    for line in subprocess.run(["ip", "-6", "route", "show", "table", table],
                               capture_output=True, text=True).stdout.splitlines():
        words = line.split()
        if words[:2] in (["local", "default"], ["local", "::/0"]) and "dev" in words:
            dev = words[words.index("dev") + 1]
            if dev != "lo":
                have.append(dev)
    for dev in have:
        if dev != want:
            r = subprocess.run(["ip", "-6", "route", "del", "local", "::/0", "dev", dev, "table", table],
                               capture_output=True, text=True)
            if r.returncode:
                raise OSError(f"removing the route on {dev}: {r.stderr.strip()}")
    if want and want not in have:
        r = subprocess.run(["ip", "-6", "route", "add", "local", "::/0", "dev", want, "table", table, "metric", "100"],
                           capture_output=True, text=True)
        if r.returncode:
            raise OSError(f"adding the route on {want}: {r.stderr.strip()}")
    return want


def down(cfg: Config | None = None) -> list[str]:
    """Remove everything `up` adds, as recorded at install time."""
    return cleanup.down(cleanup.load_params())


def present(cfg: Config) -> bool:
    """Whether the intercept ip rule exists (readable without privileges)."""
    out = subprocess.run(["ip", "-6", "rule", "show"], capture_output=True, text=True).stdout
    prefix = f"{cfg.rule_priority + 1}:"
    return any(line.startswith(prefix) and hex(cfg.intercept_mark) in line for line in out.splitlines())
