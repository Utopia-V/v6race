#!/bin/sh
# Install or upgrade v6race as a system service. Run as root from the repository root.
# Nothing on the system changes until the new version has passed its checks,
# and the old version is stopped with its own code, so its cleanup still works.
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
cd "$(dirname "$0")"
PY=/usr/bin/python3
"$PY" -c 'import sys; assert sys.version_info >= (3, 12)' 2>/dev/null || { echo "needs $PY >= 3.12" >&2; exit 1; }
modprobe nft_tproxy 2>/dev/null || true

# 1. Stage the new version and check it with the interpreter the service uses.
rm -rf /opt/v6race/lib.new
mkdir -p /opt/v6race/lib.new
cp -r src/v6race /opt/v6race/lib.new/
find /opt/v6race/lib.new -name __pycache__ -prune -exec rm -rf {} +
mkdir -p /etc/v6race
[ -e /etc/v6race/config.toml ] || cp packaging/config.toml /etc/v6race/config.toml
rules=$(mktemp)
trap 'rm -f "$rules"' EXIT
if ! PYTHONPATH=/opt/v6race/lib.new "$PY" -s -m v6race print-rules > "$rules"; then
    echo "the new version or /etc/v6race/config.toml is broken; nothing was changed" >&2
    exit 1
fi
nft -c -f "$rules" || { echo "nftables rejected the rules; nothing was changed" >&2; exit 1; }

# 2. Stop the old version (its ExecStopPost removes its rules) and make sure.
if systemctl is-active --quiet v6race; then
    systemctl stop v6race
fi
if nft list table ip6 v6race >/dev/null 2>&1; then
    echo "the old rules are still installed; run 'sudo v6race rules-down' and retry" >&2
    exit 1
fi

# 3. Switch versions, keeping the old one until the new one is up.
rm -rf /opt/v6race/lib.old
if [ -d /opt/v6race/lib ]; then
    mv /opt/v6race/lib /opt/v6race/lib.old
fi
mv /opt/v6race/lib.new /opt/v6race/lib
cp packaging/v6race.service /etc/systemd/system/v6race.service
cat > /usr/local/bin/v6race <<'SH'
#!/bin/sh
PYTHONPATH=/opt/v6race/lib exec /usr/bin/python3 -s -m v6race "$@"
SH
chmod 755 /usr/local/bin/v6race
systemctl daemon-reload
systemctl enable v6race
systemctl start v6race
sleep 3
if v6race status --check; then
    rm -rf /opt/v6race/lib.old
else
    echo "the new version didn't come up (journalctl -u v6race)." >&2
    echo "the previous version is in /opt/v6race/lib.old" >&2
    exit 1
fi
