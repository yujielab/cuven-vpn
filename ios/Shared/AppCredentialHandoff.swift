import Foundation

enum AppCredentialHandoff {
    static let modeKey = "RequiresAppStart"
    static let sessionIDKey = "CuvenManualSessionID"
    private static let tokenKey = "CuvenStartToken"
    private static let referenceKey = "CuvenStartReference"

    // Only used in startVPNTunnel(options:). Preferences carry the opaque reference.
    static func options(token: String, reference: Data) throws -> [String: NSObject] {
        try VPNProfile.validateAccessToken(token)
        return [tokenKey: token as NSString, referenceKey: reference as NSData]
    }

    static func token(options: [String: NSObject]?, storedReference: Data?, sessionID: Data?, autoConnect: AutoConnect) throws -> String {
        switch (storedReference, sessionID) {
        case let (binding?, nil), let (nil, binding?):
            return try token(options: options, reference: binding, autoConnect: autoConnect)
        default:
            throw StartError.openApp
        }
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
        var errorDescription: String? { "此配置需要从 Cuven 内手动连接。" }
    }
}
