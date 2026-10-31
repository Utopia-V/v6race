"""How v6race's own sockets leave by the physical network, around any proxy TUN.

Without this, a TUN-mode proxy client (Mihomo, Clash, sing-box) would capture
v6race's upstream connections and could hand them straight back to v6race.

- Linux transparent mode: a fwmark that skips interception and selects the
  main routing table (needs CAP_NET_ADMIN).
- Linux proxy mode: bind to the Wi-Fi/Ethernet device (no privileges needed).
- Windows: IP_UNICAST_IF / IPV6_UNICAST_IF, the per-socket interface choice
  proxy clients themselves use to avoid loops.
"""

import socket
import struct
import sys
from dataclasses import dataclass, field

from .dns import system_upstreams

IP_UNICAST_IF = 31
IPV6_UNICAST_IF = 31


@dataclass
class Egress:
    mark: int = 0
    device: str = ""
    ifindex: int = 0  # Windows interface index
    # DNS servers reachable on this network (e.g. the campus DNS from DHCP).
    # Empty: systemd-resolved's upstreams, read at each lookup.
    dns: list[str] = field(default_factory=list)
    fallback_dns: list[str] = field(default_factory=list)

    def prepare(self, sock: socket.socket) -> None:
        if self.mark:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, self.mark)
        if self.device:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.device.encode())
        if self.ifindex and sys.platform == "win32":
            if sock.family == socket.AF_INET:
                # IPv4 takes the index in network byte order, IPv6 in host order.
                # Pass bytes: htonl() of an index >= 128 overflows a signed int.
                sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, struct.pack("!I", self.ifindex))
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, IPV6_UNICAST_IF, self.ifindex)

    def dns_servers(self) -> list[str]:
        """The network's own resolvers; `fallback_dns` is asked only if they fail."""
        return self.dns or system_upstreams()
