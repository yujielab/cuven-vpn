import Foundation
import NetworkExtension
import XCTest
@testable import Cuven

final class DisconnectDiagnosticTests: XCTestCase {
    func testStartupCodesReachAppWithoutEndpointOrCredentialDetails() {
        XCTAssertNil(TunnelFailure.fromStartupCode(""))
        let cases: [(String, TunnelFailure)] = [
            ("gateway-busy", .gatewayBusy), ("gateway-rejected", .gatewayRejected),
            ("gateway-ipv6", .gatewayIPv6), ("certificate-name", .certificateName),
            ("certificate-time", .certificateTime), ("certificate", .certificateTrust),
            ("timeout", .gatewayTimeout), ("cancelled", .cancelled),
            ("unknown private details", .connection)
        ]
        for (code, expected) in cases {
            let failure = TunnelFailure.fromStartupCode(code)
            XCTAssertEqual(failure, expected)
            let wrapper = NSError(domain: NEVPNConnectionErrorDomain, code: NEVPNConnectionError.pluginFailed.rawValue,
                                  userInfo: [NSUnderlyingErrorKey: expected as NSError])
            XCTAssertEqual(DisconnectDiagnostic.message(for: wrapper), expected.errorDescription)
        }
    }

    func testUnderlyingProviderReasonWinsOverGenericPluginFailure() {
        let cause = NSError(domain: TunnelFailure.errorDomain, code: TunnelFailure.credentialEntitlement.rawValue)
        let wrapper = NSError(domain: NEVPNConnectionErrorDomain, code: NEVPNConnectionError.pluginFailed.rawValue,
                              userInfo: [NSUnderlyingErrorKey: cause, NSLocalizedDescriptionKey: "private data"])
        XCTAssertEqual(DisconnectDiagnostic.message(for: wrapper), TunnelFailure.credentialEntitlement.errorDescription)
    }

    func testLockedKeychainReportsUnlockThroughSystemWrapper() {
        let wrapped = NSError(domain: NEVPNConnectionErrorDomain, code: NEVPNConnectionError.pluginFailed.rawValue,
                              userInfo: [NSUnderlyingErrorKey: TunnelFailure.credentialLocked as NSError])
        let message = DisconnectDiagnostic.message(for: wrapped)
        XCTAssertTrue(message?.contains("-25308") == true)
        XCTAssertTrue(message?.contains("解锁") == true)
        XCTAssertNotEqual(message, TunnelFailure.credentialEntitlement.errorDescription)
        XCTAssertNotEqual(message, TunnelFailure.credentialUnavailable.errorDescription)
    }

    func testSystemCodeAndUnknownErrorsDoNotExposeErrorDetails() {
        let system = NSError(domain: NEVPNConnectionErrorDomain, code: NEVPNConnectionError.noNetworkAvailable.rawValue,
                             userInfo: [NSLocalizedDescriptionKey: "private data"])
        let message = DisconnectDiagnostic.message(for: system)
        XCTAssertTrue(message?.contains("没有可用网络") == true)
        XCTAssertFalse(message?.contains("private data") == true)
        let unknown = NSError(domain: "unknown", code: 1, userInfo: [NSLocalizedDescriptionKey: "private data"])
        XCTAssertNil(DisconnectDiagnostic.message(for: unknown))
    }
}
