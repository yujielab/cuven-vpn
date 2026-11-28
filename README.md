# Cuven VPN

Cuven IP 将 iPhone 或 iPad 的原始 IPv4、IPv6 包转发到自有 Linux 网关。QUIC 与 TLS 1.3 强制协商混合后量子密钥交换 X25519 + ML-KEM-768。客户端验证网关的标准 TLS 证书。Cuven 的应用协议负责接入令牌校验、经认证的地址族协商，以及有界的 IP 分片和重组。设备到网关是隧道的两个加密端点，访问网站的内容仍由 HTTPS 等应用协议保护。 [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) · [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)

旧版 HY2 和 WireGuard 配置需要换为 Cuven IP 网关和接入令牌。更新后的 App 不再提供旧协议的连接入口。

## Cuven 封锁模式

如果你面临定向网络威胁，可以在「连接设置」开启 Cuven 封锁模式。它默认为关闭。开启后，Cuven 只拨号到手动填写的网关 IP，使用全隧道路由与加密 DNS，并阻止局域网访问。每次握手都会验证网关证书的信任链、名称和固定的公钥指纹。部分必要系统流量仍由 iOS 处理。

1. 通过自己信任的管理连接登录 VPS，用本版安装器运行 `sudo bash ./cuven-vps-install.sh --show-pin`，复制输出的一行 Base64 指纹。
2. 在 App 中填写网关 IP。使用域名证书时，将证书上的域名填入「TLS 证书域名」。
3. 开启「Cuven 封锁模式」，粘贴指纹，保存并连接。关闭此开关后可恢复普通连接设置。

证书沿用同一公钥续签时指纹保持有效。更换网关密钥时，须从管理终端重新取得指纹。Cuven 封锁模式保护 VPN 网络连接。iOS 自带的「锁定模式」可在「设置 → 隐私与安全性」中单独开启。

## 一键部署 Linux 网关

在 Debian 或 Ubuntu 的 x86_64、ARM64 VPS 上启用 systemd 和 TUN 后，可以直接安装。以下命令下载固定版本、校验 SHA-256，然后启动交互式安装器。

```sh
wget -O cuven-vps-install.sh https://raw.githubusercontent.com/yujielab/cuven-vpn/44c7d302bc5edab8c374a62e6f525e91f3e9b27f/downloads/cuven-vps-install.sh && echo '32ce3db7fafed622f0cb159d4efb6d51034b252faa53cf82d8ba749d34a67fe9  cuven-vps-install.sh' | sha256sum -c - && sudo bash ./cuven-vps-install.sh
```

安装器自带网关二进制。启动前会检查证书有效期、匹配的私钥和 TLS 服务端用途，并按客户端的规则核对网关域名或 IP 与证书主题备用名称（SAN）。使用 IPv6 地址作为证书身份时，须提供含该 IP 的证书和私钥。iPhone 会在实际连接时验证证书链。已有标准路径的 Let's Encrypt 证书会自动复用。省略证书时，可在提示中同意通过 HTTP-01 签发。网关子域名应指向 VPS，Cloudflare 普通代理用户可为此子域名选择「仅 DNS」。签发与续签需要公网 TCP 80，隧道默认使用 UDP 4433。首次安装中断后可用相同参数重试。已安装时，重复指定原来的证书、端口和地址族会沿用现有配置和令牌。变更这些设置需要显式传入 `--reconfigure`。首次安装和更改 UDP 端口时会先试绑定目标端口。端口已占用时，现有网关继续运行。如果新配置通过预检后仍启动失败，安装器会恢复之前的配置、防火墙及服务运行状态，原接入令牌仍可使用。更改配置或升级网关程序时若安装进程被中断，可用同一新版安装器加 `--upgrade` 重试。安装器会先恢复上次运行状态。新程序仍无法启动时，原先运行的网关会重新使用旧程序接入。遇到旧版留下的无安装标记目录时，安装器会保留现场并提示检查。对于 Certbot 托管的证书，续签成功后，安装器配置的钩子会重启正在使用这份证书的网关，使新连接能看到新证书。已停用的网关会保持停用。无人值守安装可在最后的脚本命令后加 `--domain vpn.example.com --accept-terms`，将示例域名换成本机域名。

已有网关可在上方命令末尾加 `--upgrade`。新安装会记住网关名称，用于以后升级时复核证书。升级旧安装时可加 `--domain vpn.example.com` 校验客户端预期的名称。安装器只更新程序，沿用已部署的令牌、证书、端口和防火墙设置。更新会短暂重启服务。同一版本重复执行会复用现有进程。如果新版启动失败，安装器会恢复原程序。首次部署时也可直接使用 `--upgrade`。

新安装按隧道和出口路径中较小的 MTU 限制 TCP 分段，并保留对端通告的较小 MSS。已有网关可在安装命令末尾加 `--update-mss` 在线更新 Cuven 生成的 MSS 规则，也可与 `--upgrade` 合用。若检测到自定义 MSS 规则，安装器会提示核对。

已有网关的接入令牌丢失、内容无效或文件权限过宽时，安装器会在重启服务前退出。可从自己的备份恢复原令牌到 `/etc/cuven-gateway/token`，将所有者设为 root、权限设为 `0600` 后重试。首次安装若在 Certbot 签发阶段中断，可直接重跑上方命令；令牌会在证书通过检查后创建。

使用 Certbot 自动续签时，网关会检查接入令牌、新证书及对应私钥，并核对已保存的网关域名或 IP。若检查失败，当前进程继续使用原证书。修正日志指出的问题后，重新运行上方安装命令即可载入新证书。安装器会识别已经重启过的服务，避免重复断开连接。

从源码安装需要 Go 1.26.11 或更高版本。运行 `sudo bash deploy/setup-gateway.sh` 进入相同的交互流程。在 Linux 构建机运行 `bash scripts/package-gateway-installer.sh cuven-vps-install.sh` 可重新构建两个架构的安装包。

在 VPS 的仓库目录执行，下例使用 UDP 4433：

```sh
sudo ./deploy/install-gateway.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

安装程序会构建网关、生成一个客户端接入令牌并启动 systemd 服务。接入令牌保存在 `/etc/cuven-gateway/token`，仅 root 可读。通过私有管理连接读取，并录入 Cuven 的「网关接入令牌」字段。IPv4 客户端地址固定为 `10.66.0.2`。VPS 有原生 IPv6 出口时，可传入 `--ipv6`，并在客户端启用「网关支持 IPv6」。网关会在认证时声明双栈能力。当前网关支持一个已认证客户端。等待令牌验证的握手最多并行 8 个。网关在验证成功后才分配转发会话。另一台设备尝试连接时，已接入的设备可以继续传输；待验证名额已满时，新连接需要稍后重试。

两端均支持 Cuven IP v2 时，TLS 握手会协商 1500 字节的内层 MTU。较大的 IP 包可拆成多个外层 QUIC 数据报。新版客户端和网关将各自发送的外层 UDP 负载限制在 1200 字节，使已连接的会话能适应 IPv6 或 NAT64 路径降至 1280 字节的情况。较宽路径上发送相同数据可能需要更多数据报。已有部署应同时更新客户端和网关。任一端使用 v1 时沿用 1280 字节的内层 MTU，部分 HTTP/3 服务在此 MTU 下可能握手超时。

网关进行源地址检查，并使用独立的 nftables 表限制转发。网关阻止客户端访问主机服务、内网与链路本地地址。更新或续签证书后重启服务，已有接入令牌会保留。主机全局防火墙在重载时清空规则表的部署，需要重启网关服务恢复专用规则。

QUIC Retry 在握手前验证源地址，接入令牌的证明绑定到当前 TLS 会话。客户端和网关都会校验认证消息的长度及 QUIC 流结束标记，认证超时或消息不完整时关闭连接。网关对未建立的 UDP 连接限速。已知客户端网络出口时，可以重复指定 `--allow-source CIDR`，只对这些来源开放网关 UDP 端口。启用后如需从 IPv4 和 IPv6 接入，应分别填写允许的网段。 [RFC 9000 地址验证](https://www.rfc-editor.org/rfc/rfc9000.html#section-8)

```sh
sudo systemctl status cuven-gateway
sudo journalctl -u cuven-gateway -n 50
```

## 路由和 DNS

Cuven IP 在 iOS 中安装 IPv4、IPv6 默认路由，使用全流量策略。IPv4 单栈部署会捕获并丢弃 IPv6 包。系统保留 DHCP、网络门户等例外。接入网关使用域名时，iOS 可在首次连接前解析该域名。若此时切换网络，Cuven 会使用新网络重查。首次解析共等待最多 12 秒，超时后可重新连接。已连接的设备切换网络后，若缓存地址连接失败，Cuven 会在保留路由的同时再次请求系统解析网关域名。同一路径上两次重查至少间隔一分钟。设备使用数值 IP 和对应的证书域名时，重连会沿用配置的地址。 [Apple VPN 路由文档](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)

隧道默认使用 DoH。可以在「连接设置」配置自有 DoH 或 DoT 和解析器的公网 IP。Packet Tunnel 拦截隧道里的明文 DNS 和 LLMNR。应用的 TLS、HTTP 和 WebRTC 流量按 IP 包原样通过，网关只执行转发与地址转换。

验收时，在已连接的设备上分别访问自有的仅 IPv4 和仅 IPv6 HTTPS 测试站。双栈应看到 VPS 的 IPv4 与 IPv6 出口。单栈配置下，仅 IPv6 的测试站应无法建立连接。网关也会过滤明文 DNS。用自有递归解析器同时核对 DNS 请求来源。时区、语言、设备信息和登录状态仍由实际客户端提供。

在独立于 VPN 出口的自有测试服务器上，可运行以下工具核对出口。为 IPv6 重复启动一次，使用只有 AAAA 记录的测试域名和 IPv6 监听地址。把程序输出的地址在已连接的 iPhone 上打开。结果来自 HTTPS 套接字实际对端。测试工具不记录访问日志。

```sh
python3 deploy/check-egress.py --listen 0.0.0.0 \
  --url https://verify4.example.com:9443 \
  --cert /path/to/fullchain.pem --key /path/to/privkey.pem \
  --expect-ip 203.0.113.10
```

## 链路测量和模型

网关可加载基于链路统计量的模型。它使用实际测量的 QUIC RTT、RTT 变化和丢包率。持续异常时，服务日志输出链路级评分。认证、加密和转发规则独立生效。

客户端首页显示手机到 VPS 的实测 RTT。VPS 到自有测量站的 RTT 可在 VPS 上单独测量。手机发起的端到端请求耗时包含手机到 VPS 的链路。

用合成样本验证训练到部署的流程：

```sh
python3 deploy/train-link-model.py --demo --output /tmp/cuven-link-model.json
```

本地真实测量可通过 `--csv` 传入。表头为 `rtt_ms,min_rtt_ms,variation_ms,loss_ratio,degraded`，最后一列为 0 或 1。合成样本结果只能说明训练流程可用。部署验证后的模型时，在安装命令中添加 `--model /绝对路径/模型.json`。实际文件路径使用英文字母、数字、斜杠、句点、连字符或下划线。

## 构建 iOS 客户端

使用 Xcode 27.2、XcodeGen 2.44.1 和 `core/go.mod` 中声明的 Go 工具链。CI 使用 iOS 27.2 SDK，最低部署版本为 iOS 17，测试目标包括 iPhone Duo 和 iPhone 17。 [Apple iPhone Duo 测试指南](https://developer.apple.com/iphone-duo/prepare/)

```sh
./scripts/build-core.sh
xcodegen generate
open Cuven.xcodeproj
```

用同一 Apple Developer 团队为主 App 和嵌入的隧道扩展签名，两个目标均需要 Packet Tunnel 授权。手动保存令牌时，由 iOS 按主 App 的实际签名选择钥匙串访问组。按需连接需要在两个目标的签名中声明同一个由各自描述文件授权的具体组名，可由签名者选择。重签若改变了钥匙串授权，可能需要重新输入令牌。 [Apple 钥匙串错误说明](https://developer.apple.com/documentation/security/errsecmissingentitlement)

重签后可以在安装前检查两个目标的授权字段：

```sh
python3 scripts/check-signed-ipa.py ./Cuven-signed.ipa
```

若两份描述文件都限定了注册设备，工具会核对它们是否至少授权同一台设备。需要检查指定 iPhone 的直装授权时，加上 `--check-device`，按提示在本机输入 UDID。

macOS 使用系统自带的 `codesign`、`security` 和 OpenSSL。Linux 使用支持 `-arch arm64` 的 `ldid` 与 OpenSSL。工具在本机读取最终 IPA 的两个目标，核对 Bundle ID、Packet Tunnel、钥匙串和调试权限的描述文件授权。它会验证各 arm64 可执行文件的 CodeDirectory 签名，并核对实际签名证书的有效期和它在该目标描述文件 `DeveloperCertificates` 中的授权。退出码 0 表示所检查字段匹配，1 表示身份、描述文件或 Packet Tunnel 字段冲突，2 表示未完成检查，3 表示两个目标的手动连接签名字段匹配，但缺少可供按需连接使用的共享组。若签名本身声明了描述文件未授权的钥匙串或 App Group，工具会指出具体目标和权限字段并返回 1。完整安装校验、Apple 证书信任、设备授权和 VPN 连接仍需在真机验证。

## 验证

```sh
cd core
go test -race ./...
go vet ./...
go build ./cmd/cuven-gateway
```

公开发布前需要在签名真机核对 IPv4、IPv6 和 DNS 出口，覆盖 Wi-Fi 与蜂窝网切换、休眠和扩展退出。网关也需要在实际 VPS 验证防火墙、证书轮换和稳定性。
