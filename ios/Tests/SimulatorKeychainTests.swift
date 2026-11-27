#if targetEnvironment(simulator)
import Foundation
import Security
import XCTest
@testable import Cuven

final class SimulatorKeychainTests: XCTestCase {
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
        if status == errSecSuccess && KeychainAccessGroup.isApplicationGroup(group, bundleID: Bundle.main.bundleIdentifier) {
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
            let label = status == errSecMissingEntitlement ? "Cuven app keychain entitlement denied" : "Cuven app keychain group unconfirmed"
            XCTContext.runActivity(named: label) { _ in
                do {
                    let reference = try KeychainCredential.storeForApp(fixture)
                    KeychainCredential.remove(reference: reference)
                    XCTFail("Stored a test credential without a confirmed app-scoped group")
                } catch CredentialError.appKeychain(errSecMissingEntitlement) {
                    XCTAssertEqual(status, errSecMissingEntitlement)
                } catch CredentialError.unexpectedDefaultGroup {
                    XCTAssertEqual(status, errSecSuccess)
                } catch {
                    XCTFail("Unexpected app keychain error")
                }
            }
        }
    }
}
#endif
