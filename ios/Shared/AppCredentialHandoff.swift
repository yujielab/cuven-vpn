import Foundation

enum AppCredentialHandoff {
    static let modeKey = "RequiresAppStart"
    private static let tokenKey = "CuvenStartToken"
    private static let referenceKey = "CuvenStartReference"

    // Only used in startVPNTunnel(options:). Preferences carry the opaque reference.
    static func options(token: String, reference: Data) throws -> [String: NSObject] {
        try VPNProfile.validateAccessToken(token)
        return [tokenKey: token as NSString, referenceKey: reference as NSData]
    }

    static func token(options: [String: NSObject]?, reference: Data, autoConnect: AutoConnect) throws -> String {
        guard autoConnect == .off, let referenceInOptions = options?[referenceKey] as? Data,
              referenceInOptions == reference, let token = options?[tokenKey] as? String else {
            throw StartError.openApp
        }
        try VPNProfile.validateAccessToken(token)
        return token
    }

    private enum StartError: LocalizedError {
        case openApp
        var errorDescription: String? { "当前签名使用 App 钥匙串。请从 Cuven 内点「连接 VPN」。" }
    }
}
