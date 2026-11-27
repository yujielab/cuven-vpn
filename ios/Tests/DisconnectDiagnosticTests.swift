import Foundation
import NetworkExtension
import XCTest
@testable import Cuven

final class DisconnectDiagnosticTests: XCTestCase {
    func testUnderlyingProviderReasonWinsOverGenericPluginFailure() {
        let cause = NSError(domain: TunnelFailure.errorDomain, code: TunnelFailure.credentialEntitlement.rawValue)
        let wrapper = NSError(domain: NEVPNConnectionErrorDomain, code: NEVPNConnectionError.pluginFailed.rawValue,
                              userInfo: [NSUnderlyingErrorKey: cause, NSLocalizedDescriptionKey: "private data"])
        XCTAssertEqual(DisconnectDiagnostic.message(for: wrapper), TunnelFailure.credentialEntitlement.errorDescription)
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
