# Cuven VPN

面向 iOS 17 及以上的 VPN 客户端。Cuven 使用原生 SwiftUI 和 Network Extension，在 Packet Tunnel 扩展中批量收发 IP 包。CI 使用 iOS 27.2 SDK，并在 iPhone Duo 和 iPhone 17 上运行模拟器测试。

| 协议 | 客户端管线 | 服务端 |
| --- | --- | --- |
| Hysteria 2 | 使用 quic-go 和 gVisor 转发 TCP 流与 UDP 会话 | Hysteria 2 服务端，支持标准 QUIC 和 Salamander |
| WireGuard 直连 | 使用内存 TUN 转发原始 IPv4 和 IPv6 包 | 标准 WireGuard，默认 UDP 51820 |
| WireGuard 经 Cuven 中继 | 使用内存 TUN，WireGuard 报文经 Cuven 中继转发 | Cuven 中继和同机 WireGuard 服务端，默认 UDP 51821 |

两种协议各保存一份配置。启用自动回退后，首选协议在启动阶段连接失败时会尝试另一份配置。HY2 的严格后量子模式要求服务端支持 TLS 1.3 的 X25519MLKEM768，并保持使用 HY2。Wi-Fi、蜂窝网络和所有网络可分别作为 iOS 按需连接条件。手动断开会暂停自动连接，保存设置或手动连接可恢复。

自定义 DNS 随隧道生效。阻止局域网访问使用 iOS 路由与客户端过滤，仅在隧道期间生效。防绕过使用 iOS 的 `includeAllNetworks`，连接中断时保留已安装的路由并退避重连。系统定义的流量例外仍适用。应用编辑服务器设置时需要先断开连接。私钥、封装密钥、HY2 凭据和 Salamander 密码保存在共享钥匙串。 [Apple VPN 路由文档](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)

## 高安全模式

高安全模式启用 iOS 全流量策略、局域网阻止和隧道内加密 DNS。默认使用 Cloudflare DoH。已建立的高安全隧道断线后保留路由并退避重连，直到恢复、用户断开或 iOS 结束扩展。

VPN 服务器需填写数值 IP，以免在连接前解析服务器域名。HY2 和 Cuven WG 的 HTTPS/3 载体可单独填写证书域名。高安全模式使用所选协议，可选的跨协议回退暂停。

WebRTC 的 STUN/TURN 和普通应用 UDP 随 VPN 路由。站点获得的是实际出口映射。浏览器仍可能公开本机候选地址，VPN 无法更改第三方浏览器的候选列表。DHCP、部分运营商及伴随设备流量仍适用 iOS 系统例外。应用与目标站之间的内容加密由 HTTPS 等应用协议负责。 [Apple 全流量路由文档](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks)

### Cuven WG 的 HTTPS/3 载体

高安全 Cuven WG 使用 v2 封装，将报文类型、长度与随机填充一并加密。普通 UDP 中继可用 `-envelope-version 2` 启动。开启「HTTPS/3 载体」后，客户端通过校验证书的 TLS 1.3 和 HTTP/3 CONNECT-UDP 承载 v2 报文。客户端配置中继公网 IP、端口和证书域名。

```sh
./cuven-wg-relay -https3 -listen :443 -upstream 127.0.0.1:51820   -tls-cert /path/to/fullchain.pem -tls-key /path/to/privkey.pem
```

接入网络仍能观察连接目标、流量时序和总量。目标网站能观察 VPN 出口 IP，并结合 IP 归属及浏览器信号识别访问。 [HTTP CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298)

## 链路隐私

- **分档随机填充。** Cuven v2 把相近长度的包归入同一长度区间，并在区间内随机填充。UDP 与 HTTPS/3 载体共用这套编码，沿用 v2 的 128 字节填充上限和 1452 字节帧长上限。更新客户端覆盖上行，更新中继覆盖下行，混合版本仍可互通。
- **中继探测防重放。** 更新后的 UDP 中继验证探测报文，并为最近 4096 个已认证的探测 nonce 单独保留窗口。重复探测被丢弃。正常超时重试会重新封装并生成新的 nonce。
- **隧道内加密 DNS。** 在「连接设置」中启用「加密 DNS」，选择 DoH 或 DoT 并填写解析器 IP。DoH 使用 HTTPS URL，DoT 使用证书域名和 TCP 853。开启后使用全流量路由并拦截隧道内明文 DNS 与 LLMNR。自动回退要求两份配置使用同一解析器。普通模式使用域名时，网关域名可能在隧道建立前由系统解析。 [Apple DoT 文档](https://developer.apple.com/documentation/networkextension/nednsovertlssettings/servername)

## 构建 iOS 客户端

在 macOS 上安装 Xcode 27.2、XcodeGen 2.44.1 和 `core/go.mod` 声明的 Go 工具链。在 Xcode 安装支持 iPhone Duo 的 iOS 27.2 模拟器运行时。 [Xcode 27.2 发布说明](https://developer.apple.com/documentation/xcode-release-notes/xcode-27_2-release-notes) · [XcodeGen 2.44.1](https://github.com/yonaskolb/XcodeGen/releases/tag/2.44.1) · [Apple iPhone Duo 测试指南](https://developer.apple.com/iphone-duo/prepare/)

```sh
./scripts/build-core.sh
xcodegen generate
open Cuven.xcodeproj
```

在 Xcode 为 `Cuven` 和 `CuvenTunnel` 选择同一个开发团队。真机签名需要两套可启用 Packet Tunnel Provider 的 App ID、对应的描述文件和同一个钥匙串访问组。默认标识符为 `dev.cuven.vpn` 和 `dev.cuven.vpn.tunnel`。若更换标识符，同时更新 `project.yml` 和 `ios/Shared/VPNProfile.swift`。选真机运行 `Cuven` scheme，并在首次连接时批准系统 VPN 配置。

如果出现钥匙串错误 `-34018`，请核对签名后的主 App 和 `CuvenTunnel.appex`。两者的 `keychain-access-groups` 都应包含相同的 `<App ID 前缀>.dev.cuven.vpn.shared`，并保留 `packet-tunnel-provider` 权限。重签时应用会根据当前签名解析前缀。更换开发团队后可能需要重新输入连接凭据。 [Apple 钥匙串错误说明](https://developer.apple.com/documentation/security/errsecmissingentitlement)

## 配置 Hysteria 2

输入服务器地址、端口、认证凭据及可选的 TLS 服务器名称，或在「导入 HY2 链接」中粘贴 `hysteria2://`、`hy2://` 链接。支持 `sni`、`peer`、`obfs=salamander`、`obfs-password` 和 `insecure=0/1`。同时提供 `sni` 与 `peer` 时使用 `sni`。服务端需启用 UDP。Cuven 默认验证 TLS 证书。导入 `insecure=1` 后界面会标示该配置关闭了校验。高安全模式和严格后量子模式要求验证证书，自动回退只选择开启证书校验的 HY2 配置。 [Hysteria 2 URI 规范](https://v2.hysteria.network/docs/developers/URI-Scheme/)

官方服务端 v2.14.0 在任一 TCP 方向结束时关闭连接。依赖发送端半关闭后继续收结果的应用可使用 WireGuard。

## 配置 WireGuard

在标准 WireGuard 网关为每个客户端分配独立的公钥和隧道地址。启用所需地址族的内核转发，配置出口路由及防火墙，在公网开放网关的 WireGuard UDP 端口。iOS 选择「WireGuard」和「直连」，填写网关地址、UDP 端口、服务端公钥、客户端私钥、隧道地址与可选的预共享密钥。只配置一个地址族时，客户端会捕获并丢弃另一地址族的流量。

### Cuven 中继

1. 在服务端配置 WireGuard，服务端设置 `ListenPort = 51820`，接口 MTU 设置为 `1280`（使用 `wg-quick` 时在 `[Interface]` 中填写 `MTU = 1280`）。为客户端生成独立的 WireGuard 密钥对，在服务端 Peer 中填入客户端公钥和客户端分配地址，例如 `AllowedIPs = 10.66.0.2/32, fd66::2/128`。为启用的 IP 家族配置服务端转发和出口路由。私有客户端地址应由服务端 NAT 至所选公网出口。使用原生路由 IPv6 时，确保地址属于 VPN 分配的前缀。通过防火墙限制原始 WireGuard 端口至本机，并向客户端开放中继 UDP 端口。
2. 用 `openssl rand -base64 32` 生成部署专用的随机封装密钥。用你的服务管理器向 `CUVEN_RELAY_KEY` 注入标准 Base64 密钥，勿把密钥写入仓库。配置完成后启动中继。

   ```sh
   cd core
   go build -o cuven-wg-relay ./cmd/cuven-wg-relay
   ./cuven-wg-relay -listen :51821 -upstream 127.0.0.1:51820
   ```

3. 在 iOS 选择「WireGuard」和「Cuven 中继」，输入中继地址和端口、客户端隧道地址、服务端 WireGuard 公钥、客户端私钥和封装密钥。若服务端 Peer 配置了 WireGuard 预共享密钥，客户端使用相同值。

如需让 DNS 使用与应用相同的运营方出口，可在出口部署自建 HTTPS 递归解析器，并在 Cuven 填写其 URL 和公网地址。权威 DNS 通常看到递归解析器的地址。使用公共递归 DNS 时，这一地址可能与网站看到的 VPN 出口不同。

Cuven 封装使用带版本的 UDP 报文、按方向派生的 XChaCha20-Poly1305 密钥和随机 nonce。中继只有在认证外层报文后才会转发到本机 WireGuard。客户端先确认中继可达，再等待 WireGuard 完成对端认证。标准 WireGuard 客户端需要连接原生 WireGuard 端口。v1 的 UDP 额外开销为 45 字节。v2 增加 43 字节和最多 128 字节填充，总 UDP 负载限制为 1452 字节。低路径 MTU 的网络可能需要使用 HY2。 [WireGuard 协议](https://www.wireguard.com/protocol/)

## 测试

```sh
cd core
go test -race ./...
go vet ./...
```

通过 `CUVEN_HYSTERIA_BIN` 提供官方 Hysteria 2 二进制文件后，Go 测试会在回环地址上验证标准 HY2 与 Salamander 的 TCP、UDP、认证与证书校验。WireGuard 测试验证直连及 Cuven 中继的 IPv4 和 IPv6 原始包往返。GitHub Actions 使用固定版本和校验和，并构建设备目标及运行 iOS 模拟器测试。

### P0 正式发布验收

| 领域 | 待完成的实现或验证 |
| --- | --- |
| iOS 与路由 | 在签名真机验证 IPv4、IPv6、DNS 和断线保护。覆盖仅 IPv6、Wi-Fi 与蜂窝切换、休眠唤醒和扩展被系统结束。iPhone Duo 另外检查折叠与展开时的界面和连接状态。 |
| 传输与诊断 | 实现自适应 MTU、经自有服务的 RTT、抖动、丢包、IPv4/IPv6 公网出口和 DNS 完整性探测。分别测试 WireGuard 的原生转发和 HY2 的代理语义。 |
| 账户与密钥 | 实现账户认证、会话和令牌轮换、签名配置验证与密钥撤销。 |
| 网关与隐私 | 部署自有网关及 DoH 解析器。验收 nftables 转发隔离、反欺骗、限速、自动补丁和最小权限。审计网关、解析器和控制平面实际保存的数据。 |
| App Store 与质量 | 使用组织开发账户完成签名、隐私政策和首次使用前的数据声明。验证隐私清单覆盖归档依赖，完成安全与供应链检查、长时间稳定性、功耗及吞吐基准。 |

App Store 的 VPN 隐私披露以正式运营环境的数据路径为准。 [Apple App Review Guidelines §5.4](https://developer.apple.com/app-store/review/guidelines/#vpn-apps)

WireGuard® 是 Jason A. Donenfeld 的注册商标。
