import Foundation
import Security

enum KeychainCredential {
    private static let service = "dev.cuven.vpn.credential"

    static func storeShared(_ credential: String, groups: [String]) throws -> Data {
        try VPNProfile.validateAccessToken(credential)
        for group in groups {
            do {
                return try add(credential, group: group)
            } catch CredentialError.keychain(errSecMissingEntitlement) {
                continue
            }
        }
        throw CredentialError.sharedRequired
    }

    static func storeForApp(_ credential: String) throws -> Data {
        try VPNProfile.validateAccessToken(credential)
        do {
            // Without kSecAttrAccessGroup the installed signature determines the destination.
            return try add(credential, group: nil)
        } catch CredentialError.keychain(let status) {
            throw CredentialError.appKeychain(status)
        }
    }

    static func isShared(_ reference: Data, with groups: [String]) -> Bool {
        guard !groups.isEmpty, let attributes = try? credentialAttributes(for: reference),
              let group = attributes[kSecAttrAccessGroup as String] as? String else { return false }
        return groups.contains(group)
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
        _ = try credentialAttributes(for: reference)
        var query: [String: Any] = [kSecValuePersistentRef as String: reference]
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
        guard (try? credentialAttributes(for: reference)) != nil else { return }
        SecItemDelete([kSecValuePersistentRef as String: reference] as CFDictionary)
    }

    private static func credentialAttributes(for reference: Data) throws -> [String: Any] {
        // Saved VPN preferences can outlive the item that Cuven originally wrote.
        // Check the credential namespace before requesting a value or deleting it.
        guard !reference.isEmpty else { throw CredentialError.missing }
        let query: [String: Any] = [kSecValuePersistentRef as String: reference]
        var lookup = query
        lookup[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        guard status == errSecSuccess else { throw CredentialError.keychain(status) }
        guard let attributes = result as? [String: Any],
              attributes[kSecAttrService as String] as? String == service,
              let account = attributes[kSecAttrAccount as String] as? String,
              UUID(uuidString: account) != nil else { throw CredentialError.missing }
        return attributes
    }
}

enum CredentialError: LocalizedError {
    case missing
    case keychain(OSStatus)
    case appKeychain(OSStatus)
    case sharedRequired
    case providerMissing

    var errorDescription: String? {
        switch self {
        case .keychain(errSecInteractionNotAllowed), .appKeychain(errSecInteractionNotAllowed):
            "钥匙串暂时不可访问（-25308）。请解锁设备后重试。"
        case .appKeychain(let status):
            "iOS 未能写入签名授权的钥匙串（SecItemAdd，\(status)）。" +
                (status == errSecMissingEntitlement ? "请核对重签后主 App 的 application-identifier 和描述文件。" : "")
        case .sharedRequired:
            "按需连接需要主 App 与 CuvenTunnel 签入同一个可用的钥匙串访问组。也可以关闭自动连接，从 Cuven 手动连接。"
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
