"""Remove every kernel object v6race installed. Standard library only, and
independent of the configuration file, so it still works when the config was
edited or broken, or the rest of the package fails to import: systemd runs it
as `python3 -m v6race.cleanup` after the service stops, however it stopped.

What to remove comes from the state file the service wrote when it installed
its rules; without one, the defaults.
"""

import json
import subprocess
import sys
from pathlib import Path

STATE_PATH = Path("/run/v6race/rules.json")
TABLE = "v6race"
DEFAULTS = {"intercept_mark": 0x7672, "bypass_mark": 0x7673, "rule_priority": 4990, "route_table": 7672}
# Errors that only mean "already gone".
GONE = ("No such file", "No such process", "does not exist", "Cannot find", "not found")


def rule_specs(p: dict) -> list[list[str]]:
    """The ip rules, in `ip` argument form without the add/del verb."""
    bypass, intercept, prio, table = hex(p["bypass_mark"]), hex(p["intercept_mark"]), p["rule_priority"], str(p["route_table"])
    return [
        ["-6", "rule", "fwmark", bypass, "lookup", "main", "priority", str(prio)],
        ["-4", "rule", "fwmark", bypass, "lookup", "main", "priority", str(prio)],
        ["-6", "rule", "fwmark", intercept, "lookup", table, "priority", str(prio + 1)],
        # If the main table has no route (Wi-Fi reconnecting), fail instead of
        # falling through to a proxy client's TUN rules.
        ["-6", "rule", "fwmark", bypass, "unreachable", "priority", str(prio + 2)],
        ["-4", "rule", "fwmark", bypass, "unreachable", "priority", str(prio + 2)],
    ]


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=stdin, text=True, capture_output=True)


def load_params() -> dict:
    try:
        return DEFAULTS | json.loads(STATE_PATH.read_text())
    except (OSError, ValueError):
        return dict(DEFAULTS)


def down(p: dict) -> list[str]:
    """Remove the nft table, the ip rules and v6race's routes. Safe to repeat.
    Returns the errors that weren't just "already gone"."""
    errors = []

    def check(r: subprocess.CompletedProcess, what: str) -> bool:
        if r.returncode != 0 and not any(g in r.stderr for g in GONE):
            errors.append(f"{what}: {r.stderr.strip()}")
        return r.returncode == 0

    check(_run(["nft", "delete", "table", "ip6", TABLE]), "nft table")
    for spec in rule_specs(p):
        args = ["ip", spec[0], "rule", "del", *spec[2:]]
        while check(_run(args), " ".join(spec)):  # remove duplicates too
            pass
    table = str(p["route_table"])
    shown = _run(["ip", "-6", "route", "show", "table", table])
    check(shown, "listing routes")
    for line in shown.stdout.splitlines():
        # Only the routes v6race adds; the table number is validated as ours.
        if line.startswith("local default ") or line.startswith("local ::/0 "):
            words = line.split()
            dev = words[words.index("dev") + 1] if "dev" in words else None
            if dev:
                check(_run(["ip", "-6", "route", "del", "local", "::/0", "dev", dev, "table", table]),
                      f"route via {dev}")
    if not errors:  # keep the record while something may be left for a retry
        STATE_PATH.unlink(missing_ok=True)
    return errors


def main() -> int:
    errors = down(load_params())
    for e in errors:
        print(f"v6race cleanup: {e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
