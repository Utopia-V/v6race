"""What v6race.exe does when double-clicked: proxy mode with a console UI.

No proxy client running: v6race becomes the system proxy until the window
closes. A proxy client running: the system proxy is left alone and the user
is told how to point the client's direct traffic at v6race.
"""

import asyncio
import socket
import time

from . import config, winsys
from .config import Config
from .egress import Egress
from .proxy import Proxy
from .server import run_proxy


# Shown in the console and in README.md; keep the two identical.
CLIENT_SNIPPET = """proxies:
  - {{ name: v6race, type: socks5, server: 127.0.0.1, port: {port}, udp: false }}
proxy-groups:
  - {{ name: 国内加速, type: fallback, proxies: [v6race, DIRECT], url: "http://www.baidu.com", interval: 60 }}
rules:
  - AND,((NETWORK,TCP),(GEOIP,CN)),国内加速"""


def _status_line(proxy: Proxy) -> str:
    s = proxy.stats
    return (f"[{time.strftime('%H:%M')}] 连接 {s.connections}（进行中 {s.active}）"
            f" | IPv6 连接 {s.v6_ok} | IPv4 连接 {s.fallback_ok} | 失败 {s.failed}"
            f" | 下载 {s.bytes_down / 1e6:.0f} MB")


async def _report(proxy: Proxy) -> None:
    last = None
    while True:
        await asyncio.sleep(30)
        line = _status_line(proxy)
        if line[8:] != last:
            print(line, flush=True)
            last = line[8:]


def windows_egress(cfg: Config) -> tuple[Egress, winsys.Network, winsys.Adapter]:
    """Egress bound to the physical adapter, with that adapter's DNS servers.
    Raises SystemExit with a message if there is no usable adapter."""
    try:
        net = winsys.query_network()
    except Exception as e:  # PowerShell missing, blocked, timed out, odd output
        raise SystemExit(f"读取网卡信息失败（{type(e).__name__}）。请确认 PowerShell 可以正常使用后重试。") from e
    adapter = winsys.choose_adapter(net.adapters)
    if adapter is None:
        raise SystemExit("未找到已联网的有线或无线网卡。请联网后重新打开本程序。")
    egress = Egress(ifindex=adapter.index, dns=winsys.usable_dns(adapter.dns), fallback_dns=list(cfg.fallback_dns))
    return egress, net, adapter


def listen(port: int) -> socket.socket:
    """Bind now and keep the socket: the port is ours before the system proxy
    is pointed at it."""
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
        sock.listen(256)
    except OSError:
        sock.close()
        raise
    return sock


def _pause_exit(message: str) -> int:
    print(message)
    input("按回车键退出")
    return 1


def run(config_path, port: int) -> int:
    print("v6race：并发建立多路 IPv6 连接，选用最先建立成功的一路，以绕开 IPv4 限速。\n")
    owner = winsys.single_instance()
    if owner is False:
        return _pause_exit("已有一个 v6race 窗口在运行。")
    if owner is None:
        # Without the lock, recovering or taking the proxy could undo the
        # backup of an instance that is running.
        return _pause_exit("无法确认是否已有 v6race 在运行（创建实例锁失败），程序将退出。")
    # Undo an earlier run that didn't clean up, before anything that can
    # fail (network, configuration): a stale system proxy keeps us offline.
    recovered = True
    try:
        if winsys.recover():
            print("上次未正常退出，已将系统代理恢复为原来的设置。")
    except OSError:
        recovered = False
        print("未能恢复上次的系统代理设置。请在“Windows 设置 → 网络和 Internet → 代理”中手动关闭“使用代理服务器”。")
    try:
        cfg = config.load(config_path)
    except (OSError, ValueError) as e:
        return _pause_exit(f"配置文件 {config_path} 有误：{e}")
    cfg.status_path = ""  # the console shows the statistics instead

    try:
        egress, net, adapter = windows_egress(cfg)
    except SystemExit as e:
        return _pause_exit(str(e))
    print(f"网卡：{adapter.name}")
    if not adapter.global6:
        print("注意：该网卡没有 IPv6 地址，连接将照常使用 IPv4，v6race 无法提速。")

    try:
        sock = listen(port)
    except OSError:
        return _pause_exit(f"端口 {port} 已被其他程序占用。")
    ours = f"127.0.0.1:{port}"

    clients = net.clients or [a.description or a.name for a in winsys.tun_adapters(net.adapters)]
    taken = winsys.proxy_taken(winsys.read_proxy(), ours)
    system_proxy = winsys.SystemProxy(ours)
    if clients or taken:
        who = "、".join(clients) if clients else "其他程序"
        print(f"\n检测到代理软件（{who}），因此不修改系统代理。")
        print("如使用 Clash / Mihomo 系客户端，请在配置（或“覆写”）中加入以下三段，并将规则放在所有规则的最前面：\n")
        print(CLIENT_SNIPPET.format(port=port))
        print("加入后，只有访问国内网站的 TCP 连接经过 v6race，UDP 流量和其他规则保持不变。")
        print("v6race 关闭后，代理软件会在一分钟内自动改用直连，配置无需改回。\n")
        set_proxy = False
    elif not recovered:
        # Taking now would save the stale setting as "the original" and
        # overwrite the backup that still holds the real one.
        print(f"\n上次的系统代理设置尚未恢复，本次不自动修改系统代理。如有需要，请手动设为 {ours}。\n")
        set_proxy = False
    elif not winsys.on_console_close(system_proxy.release):
        print("\n无法监听窗口关闭事件。为避免关闭窗口后无法上网，本次不自动修改系统代理。")
        print(f"如有需要，请手动将系统代理设为 {ours}，并在退出前改回。\n")
        set_proxy = False
    else:
        set_proxy = True

    def started(proxy: Proxy) -> None:
        print("已就绪。统计信息每 30 秒更新一次，有变化时显示。", flush=True)
        proxy.reporter = asyncio.get_running_loop().create_task(_report(proxy))

    try:
        if set_proxy and system_proxy.take():
            print(f"\n已将系统代理设为 v6race（{ours}）。关闭本窗口或按 Ctrl+C 后，系统代理将自动恢复为原来的设置。\n")
        asyncio.run(run_proxy(cfg, ours, egress, on_start=started, sock=sock))
    except KeyboardInterrupt:
        pass
    finally:
        if system_proxy.saved is not None:
            system_proxy.release()
            print("已退出，系统代理已恢复。" if system_proxy.saved is None else "已退出，但系统代理未能恢复，下次启动时将再次尝试。")
    return 0
