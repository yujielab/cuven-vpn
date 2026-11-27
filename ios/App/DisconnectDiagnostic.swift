import Foundation
import NetworkExtension

enum DisconnectDiagnostic {
    static func message(for error: NSError) -> String? {
        var cause: NSError? = error
        var systemError: NSError?
        // Apple may wrap a provider error in a generic plug-in failure.
        for _ in 0..<5 {
            guard let current = cause else { break }
            if current.domain == TunnelFailure.errorDomain, let failure = TunnelFailure(rawValue: current.code) {
                return failure.errorDescription
            }
            if current.domain == NEVPNConnectionErrorDomain, systemError == nil { systemError = current }
            cause = current.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        guard let systemError else { return nil }
        let message: String
        switch NEVPNConnectionError(rawValue: systemError.code) {
        case .noNetworkAvailable: message = "iOS 当前没有可用网络。"
        case .unrecoverableNetworkChange: message = "iOS 无法在网络切换后恢复连接。"
        case .serverAddressResolutionFailed: message = "iOS 无法解析 VPN 网关域名。"
        case .serverNotResponding, .serverDead: message = "VPN 网关没有响应，请检查 UDP 端口和服务状态。"
        case .serverDisconnected: message = "VPN 网关已断开连接。"
        case .authenticationFailed: message = "VPN 认证失败，请核对接入凭据。"
        case .serverCertificateExpired: message = "网关证书已过期。"
        case .serverCertificateNotYetValid: message = "网关证书尚未生效，请检查证书和设备时间。"
        case .serverCertificateInvalid: message = "网关证书验证失败，请核对证书域名和证书链。"
        case .configurationFailed, .configurationNotFound: message = "iOS 无法使用此 VPN 配置，请在 Cuven 内重新保存。"
        case .pluginDisabled: message = "iOS 已停用隧道扩展，请检查 VPN 配置和扩展授权。"
        case .pluginFailed: message = "iOS 报告隧道扩展运行失败。"
        default: message = "iOS 报告 VPN 连接已中断。"
        }
        return "\(message)（iOS VPN 错误码 \(systemError.code)）"
    }
}
