#if targetEnvironment(simulator)
import Foundation
import Security
import XCTest
@testable import Cuven

final class SimulatorKeychainTests: XCTestCase {
    func testSavedReferenceReadsAndRemovesOnlyTheSelectedCredential() throws {
        let service = "dev.cuven.vpn.credential"
        try withItem(service: service, account: UUID().uuidString) { selected in
            try withItem(service: service, account: UUID().uuidString) { retained in
                XCTAssertEqual(try KeychainCredential.load(reference: selected), "fixture", "Read the selected credential")
                KeychainCredential.remove(reference: selected)
                XCTAssertEqual(itemStatus(selected), errSecItemNotFound, "Retired the selected credential")
                XCTAssertEqual(try KeychainCredential.load(reference: retained), "fixture", "Read the second credential after retirement")
            }
        }
    }

    func testNonCredentialReferencesLeaveTheOriginalItemsIntact() throws {
        let service = "dev.cuven.vpn.credential"
        for (name, account) in [(service + ".signing", UUID().uuidString),
                                (service, "probe-" + UUID().uuidString)] {
            try withItem(service: name, account: account) { reference in
                XCTAssertThrowsError(try KeychainCredential.load(reference: reference)) { error in
                    guard case CredentialError.missing = error else {
                        return XCTFail("Expected a missing credential")
                    }
                }
                KeychainCredential.remove(reference: reference)
                XCTAssertEqual(itemStatus(reference), errSecSuccess)
            }
        }
    }

    private func withItem(service: String, account: String, _ body: (Data) throws -> Void) throws {
        let identity: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                      kSecAttrService as String: service, kSecAttrAccount as String: account]
        var item = identity
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        item[kSecValueData as String] = Data("fixture".utf8)
        item[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(item as CFDictionary, &result)
        if status == errSecMissingEntitlement { throw XCTSkip("Simulator denied the keychain fixture") }
        guard status == errSecSuccess else { return XCTFail("Keychain fixture creation failed (\(status))") }
        defer { SecItemDelete(identity as CFDictionary) }
        try body(XCTUnwrap(result as? Data))
    }

    private func itemStatus(_ reference: Data) -> OSStatus {
        let query: [String: Any] = [kSecValuePersistentRef as String: reference,
                                    kSecReturnAttributes as String: true]
        var result: CFTypeRef?
        return SecItemCopyMatching(query as CFDictionary, &result)
    }

    func testAppCredentialFollowsSystemKeychainGrant() throws {
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "dev.cuven.vpn.tests.keychain-probe",
            kSecAttrAccount as String: UUID().uuidString
        ]
        var probe = identity
        probe[kSecValueData as String] = Data([0])
        probe[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        probe[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(probe as CFDictionary, &result)
        defer {
            if status == errSecSuccess {
                XCTAssertEqual(SecItemDelete(identity as CFDictionary), errSecSuccess)
            }
        }
        let group = (result as? [String: Any])?[kSecAttrAccessGroup as String] as? String
        let fixture = String(Data(repeating: 1, count: 32).base64EncodedString().dropLast())

        guard status == errSecSuccess || status == errSecMissingEntitlement else {
            return XCTFail("Unexpected system keychain probe status \(status)")
        }
        if status == errSecSuccess {
            try XCTContext.runActivity(named: "Cuven app keychain round trip") { _ in
                let reference = try KeychainCredential.storeForApp(fixture)
                let lookup: [String: Any] = [
                    kSecValuePersistentRef as String: reference,
                    kSecReturnAttributes as String: true
                ]
                defer {
                    KeychainCredential.remove(reference: reference)
                    var removed: CFTypeRef?
                    XCTAssertEqual(SecItemCopyMatching(lookup as CFDictionary, &removed), errSecItemNotFound)
                }
                XCTAssertTrue(try KeychainCredential.load(reference: reference) == fixture)
                var attributes: CFTypeRef?
                XCTAssertEqual(SecItemCopyMatching(lookup as CFDictionary, &attributes), errSecSuccess)
                let item = try XCTUnwrap(attributes as? [String: Any])
                XCTAssertEqual(item[kSecAttrAccessGroup as String] as? String, group)
                XCTAssertEqual(item[kSecAttrAccessible as String] as? String,
                               kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
            }
        } else {
            XCTContext.runActivity(named: "Cuven app keychain entitlement denied") { _ in
                do {
                    let reference = try KeychainCredential.storeForApp(fixture)
                    KeychainCredential.remove(reference: reference)
                    XCTFail("Expected iOS to reject the write")
                } catch CredentialError.appKeychain(errSecMissingEntitlement) {
                    XCTAssertEqual(status, errSecMissingEntitlement)
                } catch {
                    XCTFail("Unexpected app keychain error")
                }
            }
        }
    }
}
#endif
