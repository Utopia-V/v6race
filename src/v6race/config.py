"""Runtime configuration, read from /etc/v6race/config.toml when present."""

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

DEFAULT_PATH = Path("/etc/v6race/config.toml")

DEFAULT_V4_ONLY = (
    # payments and banking
    "alipay.com", "alipayobjects.com", "antgroup.com", "mybank.cn", "tenpay.com",
    "unionpay.com", "95516.com", "icbc.com.cn", "ccb.com", "boc.cn", "abchina.com",
    "bankcomm.com", "cmbchina.com", "psbc.com",
    # shopping accounts
    "taobao.com", "tmall.com", "jd.com",
    # tickets, games
    "12306.cn", "battlenet.com.cn",
)


@dataclass
class Config:
    # Where the transparent listener accepts intercepted connections.
    port: int = 15300
    # fwmark on intercepted packets; they are routed to lo and handed to the listener.
    intercept_mark: int = 0x7672
    # fwmark on v6race's own upstream sockets: skip interception, route by the main table.
    bypass_mark: int = 0x7673
    route_table: int = 7672
    # Device whose bound sockets must be intercepted too; empty = the device of
    # the default IPv6 route when the service starts.
    interface: str = ""
    # ip rules go before Mihomo's (5210+, 9000+) so its TUN never sees our traffic.
    rule_priority: int = 4990
    # Race plan: `wave_size` connects at t=0, then again every `wave_interval`
    # seconds, at most `waves` waves; give up at `connect_timeout`.
    wave_size: int = 4
    waves: int = 2
    wave_interval: float = 1.0
    connect_timeout: float = 3.0
    # After every attempt to a /64 fails, skip IPv6 for that /64 for this long.
    dead_ttl: float = 600.0
    # DNS servers for the IPv4 fallback's A lookup (queried directly, around
    # Mihomo), after systemd-resolved's own upstreams (e.g. the campus DNS).
    fallback_dns: list[str] = field(default_factory=lambda: ["223.5.5.5", "119.29.29.29"])
    # Mihomo's mixed port (HTTP CONNECT). Last fallback when direct IPv4 fails,
    # so Mihomo's rules decide (e.g. a blocked site reached by an app that
    # bypassed fake-ip). Empty to disable.
    mihomo_proxy: str = "127.0.0.1:7890"
    # Sites that always get IPv4, matched on the host name in the client's
    # first bytes (domain and subdomains). For accounts with strict risk
    # control, so they keep seeing the same campus IPv4 exit as before.
    v4_only: list[str] = field(default_factory=lambda: list(DEFAULT_V4_ONLY))
    # How long to wait for the client's first bytes when falling back to IPv4.
    hello_timeout: float = 3.0
    # Connections served at once; beyond this, new ones are refused so the
    # process keeps file descriptors for its own work.
    max_connections: int = 4096
    # Reject QUIC (UDP 443) over global IPv6 so browsers switch to TCP, which is raced.
    reject_quic: bool = True
    # Write full addresses and host names to the log. Off by default for privacy.
    log_addresses: bool = False
    status_path: str = "/run/v6race/status.json"


def load(path: Path = DEFAULT_PATH) -> Config:
    cfg = Config()
    if path.exists():
        data = tomllib.loads(path.read_text())
        known = {f.name: f for f in fields(Config)}
        for key, value in data.items():
            key = key.replace("-", "_")
            if key not in known:
                raise ValueError(f"{path}: unknown option {key!r}")
            setattr(cfg, key, value)
    validate(cfg)
    return cfg


def validate(cfg: Config) -> None:
    """Refuse values that would make the kernel side misbehave (e.g. a route
    table number that cleanup would then empty) before anything is installed."""
    def need(ok: bool, what: str) -> None:
        if not ok:
            raise ValueError(f"invalid configuration: {what}")

    for name in ("port", "intercept_mark", "bypass_mark", "route_table", "rule_priority", "wave_size", "waves",
                 "max_connections"):
        need(type(getattr(cfg, name)) is int, f"{name} must be an integer")
    for name in ("wave_interval", "connect_timeout", "dead_ttl", "hello_timeout"):
        need(isinstance(getattr(cfg, name), (int, float)) and getattr(cfg, name) >= 0, f"{name} must be >= 0")
    need(0 < cfg.port < 65536, "port")
    need(0 < cfg.intercept_mark < 2**32 and 0 < cfg.bypass_mark < 2**32, "marks must be 1..2^32-1")
    need(cfg.intercept_mark != cfg.bypass_mark, "the two marks must differ")
    need(0 < cfg.route_table < 2**31 and cfg.route_table not in (253, 254, 255), "route_table must be a table of its own")
    need(0 < cfg.rule_priority < 32760, "rule_priority")
    need(1 <= cfg.wave_size <= 32 and 1 <= cfg.waves <= 8, "wave_size 1..32, waves 1..8")
    need(cfg.connect_timeout > 0 and cfg.max_connections >= 16, "connect_timeout > 0, max_connections >= 16")
    need(isinstance(cfg.v4_only, list) and all(isinstance(d, str) for d in cfg.v4_only), "v4_only must be a list of names")
    need(isinstance(cfg.fallback_dns, list) and all(isinstance(d, str) for d in cfg.fallback_dns),
         "fallback_dns must be a list of addresses")
