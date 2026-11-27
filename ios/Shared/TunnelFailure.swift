import Foundation

enum TunnelFailure: Int, LocalizedError, CustomNSError {
    case configuration = 1, resolution, connection, settings, disconnected, packetFormat, cancelled
    case strictRouting
    case credentialUnavailable, credentialEntitlement, manualCredential

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
        }
    }
}
