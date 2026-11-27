import Foundation
import Security

enum KeychainCredential {
    private static let service = "dev.cuven.vpn.credential"

    static func store(_ credential: String) throws -> Data {
        try VPNProfile.validateCredential(credential, maximumBytes: 8192)
        let account = UUID().uuidString
        var item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(credential.utf8),
            kSecReturnPersistentRef as String: true
        ]
        let configured = TunnelConfiguration.keychainAccessGroup
        let configuredGroup = KeychainAccessGroup.resolve(configured)
        var group = try configuredGroup ?? accessGroupForCurrentSignature(configured)
        item[kSecAttrAccessGroup as String] = group
        var result: CFTypeRef?
        var status = SecItemAdd(item as CFDictionary, &result)
        if status == errSecMissingEntitlement, configuredGroup != nil {
            let current = try accessGroupForCurrentSignature(configured)
            if current != group {
                group = current
                item[kSecAttrAccessGroup as String] = group
                status = SecItemAdd(item as CFDictionary, &result)
            }
        }
        guard status == errSecSuccess else { throw CredentialError.keychain(status) }
        guard let reference = result as? Data else {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
                kSecAttrAccessGroup as String: group
            ]
            SecItemDelete(query as CFDictionary)
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
            throw CredentialError.keychain(errSecMissingEntitlement)
        }
        return shared
    }
}

enum CredentialError: LocalizedError {
    case missing
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .missing: "找不到连接凭据，请重新输入。"
        case .keychain(let status) where status == errSecItemNotFound: "找不到连接凭据，请重新输入。"
        case .keychain(let status) where status == errSecMissingEntitlement:
            "签名缺少共享钥匙串权限（-34018）。请用同一开发者团队为 Cuven 与 CuvenTunnel 签名。"
        case .keychain(let status): "无法访问连接凭据（\(status)）。"
        }
    }
}
