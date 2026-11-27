# Cuven VPN

面向 iOS 17 及以上的双协议 VPN 客户端。Cuven 使用原生 SwiftUI 和 Network Extension，在 Packet Tunnel 扩展中批量收发 IP 包。

| 协议 | 客户端管线 | 服务端 |
| --- | --- | --- |
| Hysteria 2 | Cuven 实现 HTTP/3 认证、TCP 流和 UDP 会话封装，使用 quic-go 和 gVisor TCP/IP 栈 | 标准 Hysteria 2 服务端，需有受信任的 TLS 证书 |
| Cuven WG | Cuven 的 UDP 封装承载 WireGuard 报文，使用内存 TUN 直接转发 IP | Cuven 中继和同机 WireGuard 服务端 |

两种协议各保存一份配置。启用自动回退后，首选协议在启动阶段连接失败时会尝试另一份配置。HY2 的严格后量子模式要求服务端支持 TLS 1.3 的 X25519MLKEM768，并保持使用 HY2。Wi-Fi、蜂窝网络和所有网络可分别作为 iOS 按需连接条件。手动断开会暂停自动连接，保存设置或手动连接可恢复。

自定义 DNS 随隧道生效。阻止局域网访问使用 iOS 路由与客户端过滤，仅在隧道期间生效。防绕过使用 iOS 的 `includeAllNetworks`，系统定义的流量例外仍适用。应用编辑服务器设置时需要先断开连接。私钥、封装密钥和 HY2 凭据保存在共享钥匙串。 [Apple VPN 路由文档](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)

## 高安全模式

高安全模式启用 iOS 全流量策略、局域网阻止和隧道内 HTTPS DNS。默认使用 Cloudflare，可填写自建 HTTPS 解析器 URL 和该解析器的公网 IPv4 或 IPv6 地址。解析器身份由 HTTPS 证书校验。Cuven 拦截应用直接发送的明文 DNS 和 LLMNR。已建立的高安全隧道断线后保留路由并退避重连，直到恢复、用户断开或 iOS 结束扩展。

VPN 服务器需填写数值 IP，以免在连接前解析服务器域名。HY2 和 Cuven WG 的 HTTPS/3 载体可单独填写证书域名。高安全模式使用所选协议，可选的跨协议回退暂停。

WebRTC 的 STUN/TURN 和普通应用 UDP 随 VPN 路由。站点获得的是实际出口映射。浏览器仍可能公开本机候选地址，VPN 无法更改第三方浏览器的候选列表。DHCP、部分运营商及伴随设备流量仍适用 iOS 系统例外。应用与目标站之间的内容加密由 HTTPS 等应用协议负责。 [Apple 全流量路由文档](https://developer.apple.com/documentation/networkextension/nevpnprotocol/includeallnetworks)

### Cuven WG 的 HTTPS/3 载体

高安全 Cuven WG 使用 v2 封装，将报文类型、长度与随机填充一并加密。普通 UDP 中继可用 `-envelope-version 2` 启动。开启「HTTPS/3 载体」后，客户端通过校验证书的 TLS 1.3 和 HTTP/3 CONNECT-UDP 承载 v2 报文。客户端配置中继公网 IP、端口和证书域名。

```sh
./cuven-wg-relay -https3 -listen :443 -upstream 127.0.0.1:51820   -tls-cert /path/to/fullchain.pem -tls-key /path/to/privkey.pem
```

接入网络仍能观察连接目标、流量时序和总量。目标网站能观察 VPN 出口 IP，并结合 IP 归属及浏览器信号识别访问。 [HTTP CONNECT-UDP](https://www.rfc-editor.org/rfc/rfc9298)

## 构建 iOS 客户端

在 macOS 上安装带 iOS SDK 的 Xcode、[XcodeGen 2.44.1](https://github.com/yonaskolb/XcodeGen/releases/tag/2.44.1) 和 `core/go.mod` 声明的 Go 工具链。

```sh
./scripts/build-core.sh
xcodegen generate
open Cuven.xcodeproj
```

在 Xcode 为 `Cuven` 和 `CuvenTunnel` 选择同一个开发团队。真机签名需要两套可启用 Packet Tunnel Provider 的 App ID、对应的描述文件和同一个钥匙串访问组。默认标识符为 `dev.cuven.vpn` 和 `dev.cuven.vpn.tunnel`。若更换标识符，同时更新 `project.yml` 和 `ios/Shared/VPNProfile.swift`。选真机运行 `Cuven` scheme，并在首次连接时批准系统 VPN 配置。

## 配置 Hysteria 2

输入服务器地址、端口、认证凭据及可选的 TLS 服务器名称，或导入 `hysteria2://`、`hy2://` 链接。首版支持标准 HY2、TCP、UDP 和证书校验，服务端需启用 UDP 以承载隧道 DNS。含混淆、端口跳跃或跳过证书校验的链接会被拒绝。官方服务端 v2.14.0 在任一 TCP 方向结束时关闭连接，依赖发送端半关闭后继续收结果的应用可选择 Cuven WG。 [Hysteria 2 协议规范](https://v2.hysteria.network/docs/developers/Protocol/)

## 配置 Cuven WG

1. 在服务端配置 WireGuard，服务端设置 `ListenPort = 51820`，接口 MTU 设置为 `1280`（使用 `wg-quick` 时在 `[Interface]` 中填写 `MTU = 1280`）。为客户端生成独立的 WireGuard 密钥对，在服务端 Peer 中填入客户端公钥和客户端分配地址，例如 `AllowedIPs = 10.66.0.2/32, fd66::2/128`。为启用的 IP 家族配置服务端转发和出口路由。私有客户端地址应由服务端 NAT 至所选公网出口。使用原生路由 IPv6 时，确保地址属于 VPN 分配的前缀。通过防火墙限制原始 WireGuard 端口至本机，并向客户端开放中继 UDP 端口。
2. 用 `openssl rand -base64 32` 生成部署专用的随机封装密钥。用你的服务管理器向 `CUVEN_RELAY_KEY` 注入标准 Base64 密钥，勿把密钥写入仓库。配置完成后启动中继。

   ```sh
   cd core
   go build -o cuven-wg-relay ./cmd/cuven-wg-relay
   ./cuven-wg-relay -listen :51821 -upstream 127.0.0.1:51820
   ```

3. 在 iOS 选择 Cuven WG，输入中继地址和端口、客户端隧道地址、服务端 WireGuard 公钥、客户端私钥和封装密钥。若服务端 Peer 配置了 WireGuard 预共享密钥，客户端使用相同值。可只配置一种 IP 家族，另一种家族的流量在隧道期间被丢弃。重连时需要能访问中继的 UDP 端口。

如需让 DNS 使用与应用相同的运营方出口，可在出口部署自建 HTTPS 递归解析器，并在 Cuven 填写其 URL 和公网地址。权威 DNS 通常看到递归解析器的地址。使用公共递归 DNS 时，这一地址可能与网站看到的 VPN 出口不同。

Cuven 封装使用带版本的 UDP 报文、按方向派生的 XChaCha20-Poly1305 密钥和随机 nonce。中继只有在认证外层报文后才会转发到本机 WireGuard。客户端先确认中继可达，再等待 WireGuard 完成对端认证。标准 WireGuard 客户端需要连接原生 WireGuard 端口。v1 的 UDP 额外开销为 45 字节。v2 增加 43 字节和最多 128 字节填充，总 UDP 负载限制为 1452 字节。低路径 MTU 的网络可能需要使用 HY2。 [WireGuard 协议](https://www.wireguard.com/protocol/)

## 测试

```sh
cd core
go test -race ./...
go vet ./...
```

若提供官方 Hysteria 2 二进制文件，Go 测试还会拉起回环地址上的官方服务端验证互操作。GitHub Actions 使用固定版本与校验和，并另行构建设备目标及运行 iOS 模拟器测试。

签名、系统 VPN 权限、Wi-Fi 和蜂窝切换、后台重连及应用兼容性需要在 iPhone 上验证。核心回环测试的握手时间无法代表公网首连或移动网络吞吐。

WireGuard® 是 Jason A. Donenfeld 的注册商标。
