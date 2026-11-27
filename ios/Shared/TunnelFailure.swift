import Foundation

enum TunnelFailure: Int, LocalizedError, CustomNSError {
    case configuration = 1, resolution, connection, settings, disconnected, packetFormat, cancelled
    case strictRouting
    case credentialUnavailable, credentialEntitlement, manualCredential
    case gatewayIPv6, certificateName, certificateTime, certificateTrust, gatewayTimeout

    static func fromStartupCode(_ code: String) -> Self? {
        switch code {
        case "": nil
        case "gateway-ipv6": .gatewayIPv6
        case "certificate-name": .certificateName
        case "certificate-time": .certificateTime
        case "certificate": .certificateTrust
        case "timeout": .gatewayTimeout
        case "cancelled": .cancelled
        default: .connection
        }
    }

    static let errorDomain = "dev.cuven.vpn.tunnel"
    var errorCode: Int { rawValue }
    var errorUserInfo: [String: Any] { [NSLocalizedDescriptionKey: errorDescription ?? "隧道错误。"] }

    var errorDescription: String? {
        switch self {
        case .configuration: "VPN 配置无效，请在 Cuven 中重新保存。"
        case .resolution: "无法解析 VPN 服务器地址。"
        case .connection: "无法连接 VPN 服务器，请检查地址、凭据和服务端配置。"
        case .settings: "无法应用系统 VPN 路由或 DNS 设置。"
        case .disconnected: "VPN 连接已断开，且无法恢复。"
        case .packetFormat: "隧道核心返回了无效的数据包。"
        case .cancelled: "VPN 连接已取消。"
        case .credentialUnavailable: "隧道扩展无法读取已保存的凭据。请在 Cuven 内重新输入令牌。"
        case .credentialEntitlement: "隧道扩展读取凭据时收到 -34018。请核对扩展和主 App 签名中的共享钥匙串组。"
        case .manualCredential: "本次启动缺少匹配的手动连接凭据。请从 Cuven 内输入令牌并连接。"
        case .strictRouting: "系统 VPN 全流量路由配置不完整，请在 Cuven 中重新保存。"
        case .gatewayIPv6: "网关仅支持 IPv4。请在网关启用 IPv6 转发，或在 Cuven 中关闭「网关支持 IPv6」。"
        case .certificateName: "网关证书与配置的服务器名称不匹配。请核对证书域名。"
        case .certificateTime: "网关证书当前不在有效期内。请核对设备时间和网关证书有效期。"
        case .certificateTrust: "无法验证网关证书，请检查网关提供的证书链及设备的信任设置。"
        case .gatewayTimeout: "连接网关超时。请检查网络、网关服务及 UDP 端口。"
        }
    }
}
