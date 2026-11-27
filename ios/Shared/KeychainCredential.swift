import Foundation
import Security

enum KeychainCredential {
    private static let service = "dev.cuven.vpn.credential"

    static func store(_ credential: String) throws -> Data {
        try VPNProfile.validateCredential(credential)
        let group = accessGroup()
        let account = UUID().uuidString
        var item: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(credential.utf8),
            kSecReturnPersistentRef as String: true
        ]
        if let group { item[kSecAttrAccessGroup as String] = group }
        var result: CFTypeRef?
        let status = SecItemAdd(item as CFDictionary, &result)
        guard status == errSecSuccess else { throw CredentialError.keychain(status) }
        guard let reference = result as? Data else {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            if let group { query[kSecAttrAccessGroup as String] = group }
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
        try VPNProfile.validateCredential(credential)
        return credential
    }

    static func remove(reference: Data) {
        SecItemDelete(query(for: reference) as CFDictionary)
    }

    private static func query(for reference: Data) -> [String: Any] {
        [kSecValuePersistentRef as String: reference]
    }

    private static func accessGroup() -> String? {
        let group = TunnelConfiguration.keychainAccessGroup
        return group.isEmpty || group.contains("$(") ? nil : group
    }
}

enum CredentialError: LocalizedError {
    case missing
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .missing: "找不到连接凭据，请重新输入。"
        case .keychain(let status) where status == errSecItemNotFound: "找不到连接凭据，请重新输入。"
        case .keychain(let status): "无法访问连接凭据（\(status)）。"
        }
    }
}
