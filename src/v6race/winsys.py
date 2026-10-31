"""Windows integration: find the physical network adapter, detect proxy
clients, and set/restore the system proxy.

The decision helpers are plain functions so they can be tested anywhere;
only `query_network`, the registry functions and the console handler touch
Windows APIs.
"""

import ipaddress
import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

# One PowerShell call at start-up: adapters with their gateways, IPv6
# addresses and DNS servers, plus running proxy clients.
PS_QUERY = r"""
$ErrorActionPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
# -All: without it, virtual (TUN) adapters are left out and can't be detected.
$adapters = foreach ($c in Get-NetIPConfiguration -All) {
  $v6 = @(Get-NetIPAddress -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv6 |
          Where-Object { $_.IPAddress -match '^[23]' })
  [pscustomobject]@{
    index = [int]$c.InterfaceIndex
    name = [string]$c.InterfaceAlias
    description = [string]$c.InterfaceDescription
    up = ($c.NetAdapter.Status -eq 'Up')
    hardware = [bool]$c.NetAdapter.HardwareInterface
    gateway4 = [bool]$c.IPv4DefaultGateway
    gateway6 = [bool]$c.IPv6DefaultGateway
    global6 = ($v6.Count -gt 0)
    dns = @($c.DNSServer | ForEach-Object { $_.ServerAddresses })
  }
}
$clients = @(Get-Process | Where-Object { $_.ProcessName -match $env:V6RACE_CLIENTS } |
             Select-Object -ExpandProperty ProcessName -Unique)
ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{ adapters = @($adapters); clients = $clients })
"""

# Process names of common proxy clients (regex, case-insensitive).
CLIENT_PATTERN = r"clash|mihomo|verge|sing-box|v2ray|xray|nekoray|nekobox|hiddify|shadowsocks|flclash|karing"
# Descriptions of TUN adapters those clients create.
# Specific names only: a bare "tun" would also match Windows' own Teredo adapter.
TUN_PATTERN = ("wintun", "meta tunnel", "mihomo", "clash", "sing-tun", "singbox", "tap-windows", "wireguard")

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
# Local and campus-internal addresses (login portals) never go through the proxy.
PROXY_BYPASS = ";".join(["<local>", "localhost", "127.*", "10.*", "192.168.*"] + [f"172.{n}.*" for n in range(16, 32)])


@dataclass
class Adapter:
    index: int
    name: str
    description: str = ""
    up: bool = False
    hardware: bool = False
    gateway4: bool = False
    gateway6: bool = False
    global6: bool = False
    dns: list[str] = field(default_factory=list)


@dataclass
class Network:
    adapters: list[Adapter]
    clients: list[str]


def parse_network(text: str) -> Network:
    data = json.loads(text or "{}")
    adapters = []
    for a in data.get("adapters") or []:
        dns = a.get("dns") or []
        adapters.append(Adapter(
            index=int(a.get("index") or 0), name=a.get("name") or "", description=a.get("description") or "",
            up=bool(a.get("up")), hardware=bool(a.get("hardware")), gateway4=bool(a.get("gateway4")),
            gateway6=bool(a.get("gateway6")), global6=bool(a.get("global6")),
            dns=[dns] if isinstance(dns, str) else list(dns)))
    clients = data.get("clients") or []
    return Network(adapters, [clients] if isinstance(clients, str) else list(clients))


def choose_adapter(adapters: list[Adapter]) -> Adapter | None:
    """The physical adapter that carries Internet traffic, preferring one with
    working IPv6. Virtual adapters (TUN, VPN, Hyper-V) are never chosen."""
    candidates = [a for a in adapters if a.up and a.hardware and (a.gateway4 or a.gateway6)]
    candidates.sort(key=lambda a: (not (a.gateway6 and a.global6), not a.gateway4))
    return candidates[0] if candidates else None


def tun_adapters(adapters: list[Adapter]) -> list[Adapter]:
    return [a for a in adapters if a.up and not a.hardware
            and any(p in a.description.lower() or p in a.name.lower() for p in TUN_PATTERN)]


def usable_dns(servers: list[str]) -> list[str]:
    """Drop loopback, fake-ip ranges and link-local addresses (which need a
    scope id); keep the network's real resolvers."""
    out = []
    for s in servers:
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or getattr(ip, "is_site_local", False):
            continue
        if ip.version == 4 and ip in ipaddress.ip_network("198.18.0.0/15"):
            continue
        out.append(str(ip))
    return out


@dataclass
class ProxyState:
    enable: int = 0
    server: str = ""
    override: str = ""
    autoconfig: str = ""


def proxy_taken(state: ProxyState, ours: str) -> bool:
    """Whether something else (a proxy client, a PAC script) owns the system proxy."""
    return bool(state.autoconfig) or bool(state.enable and state.server and state.server != ours)


# --- Windows-only below -------------------------------------------------------

def query_network() -> Network:
    import base64

    env = dict(os.environ, V6RACE_CLIENTS=CLIENT_PATTERN)
    # -EncodedCommand: no quoting problems on the way through CreateProcess.
    encoded = base64.b64encode(PS_QUERY.encode("utf-16-le")).decode("ascii")
    out = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if out.returncode != 0 or not out.stdout.strip().startswith("{"):
        raise RuntimeError(f"PowerShell exit {out.returncode}: {out.stderr.strip()[:200]}")
    return parse_network(out.stdout.strip())


def read_proxy() -> ProxyState:
    import winreg

    state = ProxyState()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
        for attr, name in (("enable", "ProxyEnable"), ("server", "ProxyServer"),
                           ("override", "ProxyOverride"), ("autoconfig", "AutoConfigURL")):
            try:
                setattr(state, attr, winreg.QueryValueEx(key, name)[0])
            except FileNotFoundError:
                pass
    return state


def write_proxy(state: ProxyState) -> None:
    """Write the proxy settings so that a failure part-way never leaves the
    proxy switched on towards an address it shouldn't use: turning the proxy
    on, the switch is written last; turning it off, first."""
    import ctypes
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
        def switch():
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(state.enable))

        if not state.enable:
            switch()
        for name, value in (("ProxyServer", state.server), ("ProxyOverride", state.override)):
            if value:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
            else:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
        if state.enable:
            switch()
    # Tell running programs the settings changed (SETTINGS_CHANGED, REFRESH).
    # The registry is already right if this fails; programs pick it up later.
    wininet = ctypes.windll.wininet
    if not (wininet.InternetSetOptionW(None, 39, None, 0) and wininet.InternetSetOptionW(None, 37, None, 0)):
        print(f"（通知其他程序代理设置已变更时出错：{ctypes.GetLastError()}；重新打开浏览器后生效）")


RUN_ONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
# "!": Windows keeps the entry until the command succeeds, so a failed
# restore is tried again at the next logon.
RUN_ONCE_NAME = "!v6race-restore-proxy"


def restore_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" restore-proxy'
    return f'"{sys.executable}" -m v6race restore-proxy'


def _set_run_once(command: str | None) -> None:
    """Restore at next logon if v6race never gets to: logoff, shutdown, power
    loss and a killed process all skip our own cleanup."""
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_ONCE) as key:
        if command:
            winreg.SetValueEx(key, RUN_ONCE_NAME, 0, winreg.REG_SZ, command)
        else:
            try:
                winreg.DeleteValue(key, RUN_ONCE_NAME)
            except FileNotFoundError:
                pass


def backup_path() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "v6race" / "proxy-backup.json"


def recover() -> bool:
    """Undo an earlier run that didn't clean up. Needs no network and no
    configuration; call it holding the instance lock. Returns whether the
    system proxy was put back. Raises if putting it back failed, leaving the
    backup and the RunOnce entry for another try."""
    path = backup_path()
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        endpoint, saved = data["endpoint"], ProxyState(**data["saved"])
    except (ValueError, KeyError, TypeError):
        # Unreadable: keep it for a person to look at, stop retrying.
        path.replace(path.with_suffix(".unreadable.json"))
        _set_run_once(None)
        return False
    restored = False
    if read_proxy().server == endpoint:  # still ours: nobody changed it since
        write_proxy(saved)
        restored = True
    path.unlink(missing_ok=True)
    _set_run_once(None)
    return restored


class SystemProxy:
    """Point the system proxy at v6race and put the old setting back. Before
    changing anything, the old setting goes to disk and a RunOnce entry is
    registered, so a run that never reaches `release` is undone by `recover`
    at the next start or the next logon, whichever comes first.

    The console close handler calls `release` from another thread, so `take`
    and `release` share a lock, and nothing is taken once release has begun."""

    def __init__(self, ours: str):
        self.ours = ours
        self.saved: ProxyState | None = None
        self._lock = threading.Lock()
        self._closing = False

    def take(self) -> bool:
        with self._lock:
            if self._closing:
                return False
            saved = read_proxy()
            path = backup_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"endpoint": self.ours, "saved": saved.__dict__}), encoding="utf-8")
            self.saved = saved
            try:
                _set_run_once(restore_command())
                write_proxy(ProxyState(enable=1, server=self.ours, override=PROXY_BYPASS))
            except BaseException:
                # Part of it may be written: put everything back unconditionally.
                self._restore(force=True)
                raise
            return True

    def release(self) -> None:
        with self._lock:
            self._closing = True
            self._restore(force=False)

    def _restore(self, force: bool) -> None:
        if self.saved is None:
            return
        if force or read_proxy().server == self.ours:
            try:
                write_proxy(self.saved)
            except OSError:
                # Leave the backup and RunOnce in place: the next start or
                # logon tries again.
                print("未能恢复系统代理，下次启动 v6race 或下次登录时将再次尝试。")
                return
        self.saved = None
        backup_path().unlink(missing_ok=True)
        _set_run_once(None)


_mutex = None


def single_instance() -> bool | None:
    """One v6race per user session, whatever the port: the system proxy and
    its backup belong to the user. True: we own the lock (held until exit);
    False: another instance does; None: the lock couldn't be created."""
    import ctypes

    global _mutex
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(None, False, "Local\\v6race")
    if not handle:
        return None
    if ctypes.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(ctypes.c_void_p(handle))  # don't keep it alive for the owner's successor
        return False
    _mutex = handle
    return True


_console_handler = None  # keep a reference: ctypes callbacks must outlive the call


def on_console_close(callback) -> bool:
    """Run `callback` when the console window is closed. Ctrl+C is handled by
    Python as KeyboardInterrupt. Logoff/shutdown may not reach a console
    handler; the RunOnce entry covers those."""
    import ctypes
    from ctypes import wintypes

    global _console_handler

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    def handler(event):
        if event in (2, 5, 6):  # CTRL_CLOSE, CTRL_LOGOFF, CTRL_SHUTDOWN
            callback()
        return False

    _console_handler = handler
    return bool(ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True))
