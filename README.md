# Cuven VPN

Cuven IP 将 iPhone 或 iPad 的原始 IPv4、IPv6 包转发到自有 Linux 网关。传输层使用 QUIC 与 TLS 1.3。Cuven 的应用协议负责接入令牌校验、经认证的地址族协商，以及有界的 IP 分片和重组。QUIC 使用标准认证加密与密钥更新机制。iOS 客户端验证网关证书。设备到网关是隧道的两个加密端点，访问网站的内容仍由 HTTPS 等应用协议保护。 [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) · [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)

旧版 HY2 和 WireGuard 配置需要换为 Cuven IP 网关和接入令牌。更新后的 App 不再提供旧协议的连接入口。

## 一键部署 Linux 网关

在 Debian 或 Ubuntu VPS 上保留 systemd、TUN 设备和 Go 1.26.3 或更高版本。先准备指向 VPS 的域名、受客户端信任的 TLS 证书和对应私钥。VPS 安全组和已有主机防火墙需要允许网关 UDP 端口，以及从 `cuven0` 到公网接口的转发。

在 VPS 的仓库目录执行，下例使用 UDP 4433：

```sh
sudo ./deploy/install-gateway.sh \
  --domain vpn.example.com \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

安装程序会构建网关、生成一个客户端接入令牌并启动 systemd 服务。接入令牌保存在 `/etc/cuven-gateway/token`，仅 root 可读。通过私有管理连接读取，并录入 Cuven 的「网关接入令牌」字段。IPv4 客户端地址固定为 `10.66.0.2`。VPS 有原生 IPv6 出口时，可传入 `--ipv6`，并在客户端启用「网关支持 IPv6」。网关会在认证时声明双栈能力。当前网关支持一个已认证客户端。

网关进行源地址检查，并使用独立的 nftables 表限制转发。网关阻止客户端访问主机服务、内网与链路本地地址。更新或续签证书后重启服务，已有接入令牌会保留。主机全局防火墙在重载时清空规则表的部署，需要重启网关服务恢复专用规则。

```sh
sudo systemctl status cuven-gateway
sudo journalctl -u cuven-gateway -n 50
```

## 路由和 DNS

Cuven IP 在 iOS 中安装 IPv4、IPv6 默认路由，使用全流量策略。IPv4 单栈部署会捕获并丢弃 IPv6 包。系统保留 DHCP、网络门户等例外。接入网关使用域名时，连接前可能需要由系统解析该域名。配置数值 IP 和对应的证书域名可避免启动时的网关域名查询。 [Apple VPN 路由文档](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)

隧道默认使用 DoH。可以在「连接设置」配置自有 DoH 或 DoT 和解析器的公网 IP。Packet Tunnel 拦截隧道里的明文 DNS 和 LLMNR。应用的 TLS、HTTP 和 WebRTC 流量按 IP 包原样通过，网关只执行转发与地址转换。

验收时，在已连接的设备上分别访问自有的仅 IPv4 和仅 IPv6 HTTPS 测试站，核对服务端记录的连接源 IP。双栈应看到 VPS 的 IPv4 与 IPv6 出口。单栈配置下，仅 IPv6 的测试站应无法建立连接。用自有递归解析器同时核对 DNS 请求来源。时区、语言、设备信息和登录状态仍由实际客户端提供。

## 链路测量和模型

网关可加载基于链路统计量的模型。它使用实际测量的 QUIC RTT、RTT 变化和丢包率。持续异常时，服务日志输出链路级评分。认证、加密和转发规则独立生效。

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

用同一 Apple Developer 团队签名 `dev.cuven.vpn` 和 `dev.cuven.vpn.tunnel`，两者都应保留 Packet Tunnel 能力和同一个共享钥匙串组 `<App ID 前缀>.dev.cuven.vpn.shared`。出现 `-34018` 时，核对安装包中两个目标的签名授权。更换签名团队后可能需要重新录入令牌。 [Apple 钥匙串错误说明](https://developer.apple.com/documentation/security/errsecmissingentitlement)

## 验证

```sh
cd core
go test -race ./...
go vet ./...
go build ./cmd/cuven-gateway
```

公开发布前需要在签名真机核对 IPv4、IPv6 和 DNS 出口，覆盖 Wi-Fi 与蜂窝网切换、休眠和扩展退出。网关也需要在实际 VPS 验证防火墙、证书轮换和稳定性。
