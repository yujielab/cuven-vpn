import Foundation
import Security

enum KeychainCredential {
    private static let service = "dev.cuven.vpn.credential"

    static func store(_ credential: String) throws -> Data {
        try VPNProfile.validateCredential(credential, maximumBytes: 8192)
        let configured = TunnelConfiguration.keychainAccessGroup
        let configuredGroup = KeychainAccessGroup.resolve(configured)
        let group = try configuredGroup ?? accessGroupForCurrentSignature(configured)
        do {
            return try add(credential, group: group)
        } catch CredentialError.keychain(errSecMissingEntitlement) where configuredGroup != nil {
            let current = try accessGroupForCurrentSignature(configured)
            guard current != group else { throw CredentialError.keychain(errSecMissingEntitlement) }
            return try add(credential, group: current)
        }
    }

    static func storeForApp(_ credential: String) throws -> Data {
        try VPNProfile.validateAccessToken(credential)
        do {
            // Omit kSecAttrAccessGroup so Security selects the signed default group.
            return try add(credential, group: nil)
        } catch CredentialError.keychain(let status) {
            throw CredentialError.appKeychain(status)
        }
    }

    private static func add(_ credential: String, group: String?) throws -> Data {
        var identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: UUID().uuidString
        ]
        if let group { identity[kSecAttrAccessGroup as String] = group }
        var item = identity
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        item[kSecValueData as String] = Data(credential.utf8)
        item[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(item as CFDictionary, &result)
        guard status == errSecSuccess else { throw CredentialError.keychain(status) }
        guard let reference = result as? Data else {
            SecItemDelete(identity as CFDictionary)
            throw CredentialError.missing
        }
        return reference
    }

    static func load(reference: Data) throws -> String {
        var query = query(for: reference)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw CredentialError.keychain(status) }
        guard let data = result as? Data, let credential = String(data: data, encoding: .utf8) else {
            throw CredentialError.missing
        }
        try VPNProfile.validateCredential(credential, maximumBytes: 8192)
        return credential
    }

    static func remove(reference: Data) {
        SecItemDelete(query(for: reference) as CFDictionary)
    }

    private static func query(for reference: Data) -> [String: Any] {
        [kSecValuePersistentRef as String: reference]
    }

    private static func accessGroupForCurrentSignature(_ configured: String) throws -> String {
        // The plist in an unsigned IPA can lack the App ID prefix. Read the
        // default group granted by the active signature using a non-secret item.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service + ".signing",
            kSecAttrAccount as String: UUID().uuidString
        ]
        var item = query
        item[kSecValueData as String] = Data([0])
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        item[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(item as CFDictionary, &result)
        guard status == errSecSuccess else { throw CredentialError.keychain(status) }
        defer { SecItemDelete(query as CFDictionary) }
        guard let attributes = result as? [String: Any],
              let defaultGroup = attributes[kSecAttrAccessGroup as String] as? String,
              let shared = KeychainAccessGroup.resolve(configured, defaultGroup: defaultGroup) else {
            throw CredentialError.unresolvedSharedGroup
        }
        return shared
    }
}

enum CredentialError: LocalizedError {
    case missing
    case keychain(OSStatus)
    case appKeychain(OSStatus)
    case sharedRequired
    case unresolvedSharedGroup
    case providerMissing

    var sharedGroupUnavailable: Bool {
        switch self {
        case .unresolvedSharedGroup, .keychain(errSecMissingEntitlement): true
        default: false
        }
    }

    var errorDescription: String? {
        switch self {
        case .appKeychain(let status):
            "系统默认钥匙串写入失败（SecItemAdd，\(status)）。" +
                (status == errSecMissingEntitlement ? "请核对重签后主 App 的 application-identifier 和描述文件。" : "")
        case .unresolvedSharedGroup:
            "无法从当前签名确定共享钥匙串组。请检查主 App 和扩展的 keychain-access-groups，或关闭自动连接后从 Cuven 内连接。"
        case .sharedRequired:
            "按需连接需要共享钥匙串（-34018）。请在连接设置中关闭自动连接以手动使用，或为 Cuven 和 CuvenTunnel 签入同一个 <App ID 前缀>.dev.cuven.vpn.shared 组。"
        case .providerMissing:
            "无法识别内嵌的 CuvenTunnel 扩展。请检查扩展的打包和签名。"
        case .missing: "找不到连接凭据，请重新输入。"
        case .keychain(let status) where status == errSecItemNotFound: "找不到连接凭据，请重新输入。"
        case .keychain(let status) where status == errSecMissingEntitlement:
            "签名缺少共享钥匙串权限（-34018）。请用同一开发者团队为 Cuven 与 CuvenTunnel 签名。"
        case .keychain(let status): "无法访问连接凭据（\(status)）。"
        }
    }
}
