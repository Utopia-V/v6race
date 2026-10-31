#!/bin/sh
# Remove v6race: service, kernel rules, files. /etc/v6race is kept unless --purge.
# Files are removed only once the kernel rules are confirmed gone, so the
# cleanup tool is never deleted while something is left for it to clean.
set -u
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
systemctl disable --now v6race 2>/dev/null
cleanup_ok=1
if [ -d /opt/v6race/lib ]; then
    PYTHONPATH=/opt/v6race/lib /usr/bin/python3 -s -m v6race.cleanup || cleanup_ok=0
fi
left=""
nft list table ip6 v6race >/dev/null 2>&1 && left="$left nftables-table"
ip -6 rule show | grep -q 'fwmark 0x767[23]' && left="$left ipv6-rules"
ip -4 rule show | grep -q 'fwmark 0x7673' && left="$left ipv4-rules"
if [ "$cleanup_ok" = 0 ] || [ -n "$left" ]; then
    echo "cleanup incomplete:${left:- (see errors above)}" >&2
    echo "files kept, so 'sudo v6race rules-down' still works; fix that and run this again" >&2
    exit 1
fi
rm -f /etc/systemd/system/v6race.service /usr/local/bin/v6race
rm -rf /opt/v6race /run/v6race
[ "${1:-}" = --purge ] && rm -rf /etc/v6race
systemctl daemon-reload
echo "v6race removed"
