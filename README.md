# v6race

v6race 用于绕开校园网的 IPv4 限速。以笔者所在高校的宿舍 Wi-Fi 为例，IPv4 被限制在约 1.2 MB/s，IPv6 不受限速，但约一半新建的 IPv6 连接会被网络设备随机丢弃。v6race 对同一目标并发建立多路 IPv6 连接，选用最先建立成功的一路，使连接成功率从约 50% 提高到接近 100%。2026 年 10 月在宿舍 Wi-Fi 上实测，经 v6race 从清华大学镜像站下载的速度为 12–23 MB/s，随时段变化。

如果你所在的网络同样表现为 `ping -6` 基本不丢包、而 IPv6 的 TCP 连接时通时断，也可以使用 v6race。

## Windows（测试中）

Windows 版正在实机测试，尚未发布 exe。如需提前试用，请安装 Python 3.12 或更高版本，在仓库目录下依次运行 `py -m pip install .` 和 `py -m v6race windows`，效果与运行 exe 相同。以下步骤按 exe 的用法说明。

1. 将 `v6race.exe` 放在固定的文件夹中，不要放在可能被清理的下载目录，然后双击运行。程序在窗口打开期间工作，关闭窗口即停止。
2. 如果没有运行代理软件，v6race 会自动将系统代理设为自身，无需其他操作。关闭窗口时，系统代理恢复为原来的设置。
3. 如果正在运行 Clash 等代理软件，v6race 不会修改系统代理。请在代理软件的配置（或“覆写”）中加入以下三段，并将规则放在所有规则的最前面：

```yaml
proxies:
  - { name: v6race, type: socks5, server: 127.0.0.1, port: 10800, udp: false }
proxy-groups:
  - { name: 国内加速, type: fallback, proxies: [v6race, DIRECT], url: "http://www.baidu.com", interval: 60 }
rules:
  - AND,((NETWORK,TCP),(GEOIP,CN)),国内加速
```

加入后，只有访问国内网站的 TCP 连接经过 v6race，UDP 流量和其他规则保持不变。判断目标是否位于国内，需要代理软件先在本机解析域名。v6race 关闭后，代理软件会在一分钟内自动改用直连，配置无需改回。

窗口每 30 秒显示一次统计。“IPv6 连接”一项的数字持续增加，说明 v6race 正在工作。

如果 v6race 意外退出后无法上网，可以重新打开并关闭一次 v6race，或运行 `v6race.exe restore-proxy`，系统代理都会恢复为原来的设置。也可以在“Windows 设置 → 网络和 Internet → 代理”中手动关闭“使用代理服务器”。

exe 没有代码签名，Windows 可能提示“未知发布者”。如有顾虑，可以按上文的方法从源码运行。

## Linux

Linux 版以系统服务的形式运行，在内核中透明接管本机发往公网 IPv6 的全部 TCP 连接，无需为任何程序单独配置。

```sh
sudo ./install.sh          # 检查新版本与规则，安装到 /opt/v6race 并启用 systemd 服务
v6race status              # 查看运行状态、成功率和回退次数
sudo systemctl stop v6race # 停止服务，同时删除全部内核规则
sudo systemctl disable --now v6race   # 停止服务，并取消开机启动
sudo ./uninstall.sh        # 完全卸载；加 --purge 同时删除 /etc/v6race
```

配置文件为 `/etc/v6race/config.toml`，样例见 [packaging/config.toml](packaging/config.toml)。修改后运行 `sudo systemctl restart v6race` 生效。

不想安装系统服务时，可以使用代理模式。`uv run v6race proxy` 在 `127.0.0.1:10800` 提供 SOCKS5 和 HTTP 代理，不需要 root 权限，工作方式与 Windows 版相同。命令行工具需要把域名交给代理解析，例如 `curl -x socks5h://127.0.0.1:10800`，注意使用 `socks5h` 而不是 `socks5`。

## 原理

`ping -6` 基本不丢包，TCP 连接却约有一半失败，并且各个连接的成败互不相关。这说明链路本身正常，是路径上的一台有状态设备在随机丢弃新建的连接。既然每次尝试成功与否相互独立，同时发起 4 个连接，全部失败的概率约为 1/16；1 秒内仍未成功时再补充 4 个，全部失败的概率降至约 1/256。最先建立的连接用于转发数据，其余连接随即关闭。所有尝试都失败时，v6race 根据域名改用 IPv4 连接。

Linux 版通过 nftables 和 TPROXY 在内核中接管连接，Windows 版以本机代理的方式工作。实现细节、遇到的问题和设计取舍见 [docs/原理.md](docs/原理.md)。

## Linux 版对系统的改动

| 改动 | 作用 | 查看方式 |
|---|---|---|
| nftables 表 `ip6 v6race` | output 链为新建的公网 IPv6 TCP 连接设置标记 0x7672；prerouting 链通过 TPROXY 将其交给 15300 端口；启用 `reject_quic` 时拒绝发往公网 IPv6 的 UDP 443 | `sudo nft list table ip6 v6race` |
| ip rule 4990、4992（IPv6、IPv4 各一条） | 带标记 0x7673 的数据包（v6race 自身的连接，包括回退的 IPv4 连接和 DNS 查询）先查询 main 表，优先于 Mihomo 的策略路由（5210、9000 等），直接从网卡发出；main 表中没有路由时（例如 Wi-Fi 重连期间），由 4992 判为不可达，不会进入代理软件的 TUN | `ip -6 rule`、`ip -4 rule` |
| ip rule 4991 与路由表 7672 | 带标记 0x7672 的数据包查询表 7672。表中有两条 `local ::/0` 路由，分别位于 lo 和默认 IPv6 网卡（metric 100），使数据包回到本机。后者供绑定网卡的 socket 使用：Mihomo 的直连会绑定 Wi-Fi 网卡，只匹配该网卡上的路由。服务每 10 秒按当前默认 IPv6 网卡核对一次 | `ip -6 route show table 7672` |
| systemd 服务 `v6race` | 以 DynamicUser 运行，主进程只具有 CAP_NET_ADMIN 和 CAP_NET_RAW；无论正常退出还是崩溃，都由 root 运行 `v6race.cleanup` 删除上述全部规则 | `systemctl status v6race`、`journalctl -u v6race` |
| 文件 | `/opt/v6race/lib`、`/etc/v6race/config.toml`、`/usr/local/bin/v6race`，以及记录运行状态和已安装规则的 `/run/v6race/` | |

## Linux 排错

网络出现异常时，请先按以下步骤排除 v6race 的影响：

1. 运行 `v6race status`，确认服务是否运行、规则是否存在、状态文件是否及时更新（超过 30 秒未更新会给出警告）。`v6race status --check` 在状态异常时返回非零值。
2. 运行 `sudo systemctl stop v6race` 后，如果问题仍然存在，则与 v6race 无关。
3. 如果服务已停止，`ip -6 rule` 或 `ip -4 rule` 中仍有 4990–4992 的规则，请运行 `sudo v6race rules-down` 清除。规则残留期间 IPv6 TCP 连接会失败，程序会改用 IPv4，表现为可以上网但速度较慢。
4. 如果某个网站需要固定使用 IPv4（例如账号风控严格的网站），请将其域名加入配置中的 `v4_only` 名单（按域名后缀匹配），然后重启服务。默认名单见 `src/v6race/config.py`。
5. 如果某些 IPv6 网站访问较慢，通常是其所在的 /64 地址段被判定为不可达（`dead_prefixes`），10 分钟内改用 IPv4。在配置中设置 `log_addresses = true` 后，可以在 `journalctl -u v6race` 中看到具体地址。
6. 如果浏览器无法使用 HTTP/3，这是 `reject_quic` 将 IPv6 上的 QUIC 改为 TCP 的结果，属于预期行为，可以在配置中关闭。
7. 更换上网网卡（例如改用有线网络）后，服务会在 10 秒内将回环路由移到新的默认 IPv6 网卡上。如需固定使用某块网卡，请在配置中设置 `interface`。

## Linux 版与 Mihomo / Clash 配合使用

Mihomo 开启 TUN 时，程序得到的是 fake-ip 地址，连接全部进入 Mihomo，再由 Mihomo 连接直连的网站。要让这部分直连使用 IPv6，需要以下设置：

1. 将 Mihomo 的 `dns.ipv6` 设为 `true`。在 fake-ip 模式下，程序仍然只得到 fake-ip 形式的 IPv4 地址，规则不受影响；改变的只是 Mihomo 自身直连时也会查询 IPv6 地址。
2. 设置 `tcp-concurrent: true`。Mihomo 会同时连接目标的 IPv4 和 IPv6 地址，并使用最先建立的连接。由于 v6race 在本机立即接受连接，IPv6 通常最先建立，随后 v6race 再与真正的目标竞速建立连接。未安装 v6race 时，IPv6 只在恰好连通时胜出，效果不会比原来差。
3. 账号风控严格的网站（支付、银行、购物等）建议固定使用 IPv4，使网站看到的出口地址与以前相同。做法是添加一个只使用 IPv4 的直连出站，并将相关规则放在最前面：

```yaml
proxies:
  - { name: DIRECT-IPv4, type: direct, ip-version: ipv4 }
rules:
  - DOMAIN-SUFFIX,alipay.com,DIRECT-IPv4
  - DOMAIN-SUFFIX,taobao.com,DIRECT-IPv4
  # 其余域名见 src/v6race/config.py 中的 DEFAULT_V4_ONLY
```

这份名单写在 Mihomo 中更为可靠。Mihomo 在建立连接之前就知道域名，可以直接只使用 IPv4；v6race 的 `v4_only` 名单则需要从程序发出的首个数据包中读取域名，读取失败或数据包到达过晚时无法生效。

Mihomo 的直连会绑定网卡（`auto-detect-interface`）。为此，v6race 在默认 IPv6 网卡上也添加了回环路由，Mihomo 的 TUN 设置无需修改。

## 开发

```sh
uv sync
uv run pytest
uv run v6race print-rules
```

运行时代码只使用 Python 标准库，Linux 服务直接使用 `/usr/bin/python3`（3.12 或更高版本）。Windows 版在 Windows 上运行 `packaging\windows\build.ps1`，生成 `dist\v6race.exe`。
