import XCTest
@testable import Cuven

final class BrowserAddressTests: XCTestCase {
    func testHTTPSAddressSupportsNamesAndNumericAddresses() throws {
        for (typed, result) in [
            ("example.test/path?a=1#part", "https://example.test/path?a=1#part"),
            (" 192.0.2.5 ", "https://192.0.2.5"),
            ("2001:db8::3", "https://[2001:db8::3]"),
            ("[2001:db8::3]:9443/path", "https://[2001:db8::3]:9443/path")
        ] {
            XCTAssertEqual(try XCTUnwrap(BrowserAddress.httpsURL(typed)).absoluteString, result)
        }
    }

    func testRejectsUnsafeSchemesEmbeddedCredentialsAndBadPorts() {
        for value in ["http://example.test", "javascript:alert(1)", "file:///tmp/page", "data:text/plain,test",
                      "//other.test", "https://a:b@example.test", "https://example.test:99999",
                      "example.test:0", "example.test\\@else.test", "example.test\n/path"] {
            XCTAssertNil(BrowserAddress.httpsURL(value), value)
        }
    }

    func testProxyKeepsCredentialsOutOfAddressAndChecksItsEndpoint() throws {
        let endpoint = try XCTUnwrap(BrowserProxy(address: "[2001:db8::4]:8443", username: "test", password: "example"))
        XCTAssertEqual(endpoint.host, "2001:db8::4")
        XCTAssertEqual(endpoint.port, 8443)
        XCTAssertEqual(BrowserProxy(address: "proxy.test", username: "", password: "")?.port, 443)
        for value in ["https://user:pass@proxy.test", "https://proxy.test/path", "https://proxy.test/?arg", "http://proxy.test"] {
            XCTAssertNil(BrowserProxy(address: value, username: "", password: ""))
        }
        XCTAssertNil(BrowserProxy(address: "proxy.test", username: "test", password: ""))
    }

    func testPreviewOnlyAcceptsAddressLiterals() {
        XCTAssertEqual(BrowserAddress.ip(" [2001:db8::5] "), "2001:db8::5")
        XCTAssertEqual(BrowserAddress.ip("192.0.2.8"), "192.0.2.8")
        for value in ["example.test", "192.0.2.1:443", "1.2.3.256", "<script>", "192.0.2.1\u{0}x"] {
            XCTAssertNil(BrowserAddress.ip(value))
        }
    }
}
