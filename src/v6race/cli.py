"""v6race: race parallel IPv6 TCP connects to get through networks that randomly drop flows."""

import argparse
import asyncio
import json
import logging
import subprocess
import sys
import time
from pathlib import Path

from . import config, rules
from .egress import Egress
from .server import run_proxy, run_transparent

PROXY_PORT = 10800


def _status(cfg: config.Config, check: bool = False) -> int:
    """`check`: exit 1 unless the service runs, its rules are in place and its
    status is fresh (used by install.sh)."""
    active = subprocess.run(["systemctl", "is-active", "v6race"], capture_output=True, text=True).stdout.strip()
    print(f"service: {active or 'not installed'}")
    print(f"ip rules: {'present' if rules.present(cfg) else 'absent'}")
    path = Path(cfg.status_path)
    try:
        path.exists()
    except PermissionError:
        print(f"status file: {path} not readable by this user")
        return 1
    if not path.exists():
        print("status file: none (daemon not running)")
        return 1 if check or active == "active" else 0
    s = json.loads(path.read_text())
    age = time.time() - path.stat().st_mtime
    print(f"mode: {s['mode']}, up {int(time.time() - s['started']) // 60} min, status written {int(age)} s ago")
    print(f"connections: {s['connections']} total, {s['active']} active, "
          f"{s.get('abandoned', 0)} closed by the client before the race finished")
    if s["v6_ok"]:
        print(f"over IPv6: {s['v6_ok']} ({s['v6_first_wave']} in the first wave), "
              f"{s['attempts'] / max(1, s['connections'] - s['dead_skips'] - s.get('abandoned', 0)):.1f} connects per race")
    print(f"IPv4: {s['fallback_ok']} ok ({s.get('v4_only', 0)} by the IPv4-only list), {s['failed']} failed; "
          f"{s['dead_skips']} skipped IPv6 for dead /64s ({s['dead_prefixes']} now)")
    print(f"relayed: {s['bytes_down'] / 1e6:.1f} MB down, {s['bytes_up'] / 1e6:.1f} MB up")
    if age > 30:
        print("warning: status file is stale; the daemon may have died")
    if check:
        return 0 if active == "active" and rules.present(cfg) and age <= 30 else 1
    return 0


def _restore_proxy() -> int:
    """Run by RunOnce at logon (and by hand). Needs no configuration. A
    non-zero exit keeps the RunOnce entry for the next logon."""
    from . import winsys

    owner = winsys.single_instance()
    if owner is False:
        return 0  # a running v6race owns the system proxy and restores it itself
    if owner is None:
        return 1  # can't tell; RunOnce keeps the entry and tries again
    try:
        print("system proxy restored" if winsys.recover() else "nothing to restore")
    except OSError as e:
        print(f"restore failed: {type(e).__name__}")
        return 1
    return 0


def _default_config_path() -> Path:
    # The Windows exe reads v6race.toml next to itself, if present.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).with_name("v6race.toml")
    return config.DEFAULT_PATH


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="v6race", description=__doc__)
    ap.add_argument("--config", type=Path, default=_default_config_path())
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="Linux transparent mode (needs CAP_NET_ADMIN; normally started by systemd)")
    proxy = sub.add_parser("proxy", help="SOCKS5 + HTTP proxy mode, unprivileged (Linux, Windows)")
    proxy.add_argument("--listen", default=f"127.0.0.1:{PROXY_PORT}")
    proxy.add_argument("--status-path", default="", help="write JSON stats here every 5 s")
    win = sub.add_parser("windows", help="what v6race.exe does by default: proxy mode with a console UI")
    win.add_argument("--port", type=int, default=PROXY_PORT)
    sub.add_parser("restore-proxy", help="Windows: undo a run that left the system proxy pointing at v6race")
    st = sub.add_parser("status", help="show whether interception is on and how it is doing")
    st.add_argument("--check", action="store_true", help="exit 1 unless running, rules in place, status fresh")
    sub.add_parser("rules-up", help="install nftables/ip rules only (root)")
    sub.add_parser("rules-down", help="remove nftables/ip rules (root); `systemctl stop v6race` does this too")
    sub.add_parser("print-rules", help="print the nftables script")
    args = ap.parse_args(argv)
    if args.cmd == "restore-proxy":
        return _restore_proxy()
    if args.cmd == "windows":
        # Loads the configuration itself, after undoing any stale system proxy:
        # a broken config file must not stand in the way of that.
        from . import windows
        logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
        return windows.run(args.config, args.port)
    cfg = config.load(args.config)
    quiet = False
    logging.basicConfig(level=logging.WARNING if quiet else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    if args.cmd == "run":
        asyncio.run(run_transparent(cfg))
    elif args.cmd == "proxy":
        cfg.status_path = args.status_path
        if sys.platform == "win32":
            # Without the adapter binding a TUN client could hand v6race's own
            # connections straight back to it.
            from .windows import windows_egress
            egress = windows_egress(cfg)[0]
        else:
            egress = Egress(device=rules.default_v6_device(), fallback_dns=list(cfg.fallback_dns))
        try:
            asyncio.run(run_proxy(cfg, args.listen, egress))
        except KeyboardInterrupt:
            pass

    elif args.cmd == "status":
        return _status(cfg, args.check)
    elif args.cmd == "rules-up":
        rules.up(cfg)
    elif args.cmd == "rules-down":
        errors = rules.down(cfg)
        for e in errors:
            print(e, file=sys.stderr)
        return 1 if errors else 0
    elif args.cmd == "print-rules":
        print(rules.nft_script(cfg), end="")
    return 0
