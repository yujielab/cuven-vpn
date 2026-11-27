import Foundation
import XCTest
@testable import Cuven

final class VPNProfileTests: XCTestCase {
    func testHY2ImportPreservesPercentEncodedCredentialsAndIPv6() throws {
        let result = try VPNProfile.importURI("hy2://alice:pa%40ss%3Aword@[2001:db8::1]:8443/?sni=edge.example.com")
        XCTAssertEqual(result.profile.transport, .hy2)
        XCTAssertEqual(result.profile.endpoint, "[2001:db8::1]:8443")
        XCTAssertEqual(result.profile.serverName, "edge.example.com")
        XCTAssertEqual(result.credential, "alice:pa@ss:word")
    }

    func testHY2ImportRejectsUnsupportedSecuritySettings() {
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?insecure=1"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://key@edge.example.com?obfs=salamander"))
        XCTAssertThrowsError(try VPNProfile.importURI("hy2://a%0Ab@edge.example.com"))
    }

    func testWireGuardProfileAndCredentialValidation() throws {
        let publicKey = Data(repeating: 1, count: 32).base64EncodedString()
        let relayKey = Data(repeating: 2, count: 32).base64EncodedString()
        let wireGuard = try WireGuardProfile(
            tunnelAddresses: ["10.66.0.2/32", "fd00::2/128"], peerPublicKey: publicKey
        ).validated()
        let profile = try VPNProfile(
            host: "edge.example.com", transport: .cuvenWG, wireGuard: wireGuard,
            port: 51821, customDNSServers: ["9.9.9.9"], useCustomDNS: true,
            autoConnect: .wifi, requirePostQuantum: true, blockLAN: true, preventBypass: true
        )
        let roundTrip = try VPNProfile.decode(JSONEncoder().encode(profile))
        XCTAssertEqual(profile, roundTrip)
        XCTAssertFalse(roundTrip.requirePostQuantum)
        XCTAssertEqual(roundTrip.dnsServers, ["9.9.9.9"])

        let credentials = WireGuardCredential(privateKey: publicKey, relayKey: relayKey, presharedKey: nil)
        XCTAssertEqual(try WireGuardCredential.decode(credentials.encoded()).relayKey, relayKey)
        XCTAssertThrowsError(try WireGuardProfile(
            tunnelAddresses: ["10.66.0.2/32", "10.66.0.3/32"], peerPublicKey: publicKey
        ).validated())
    }
}
