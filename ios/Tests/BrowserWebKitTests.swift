import Network
import WebKit
import XCTest
@testable import Cuven

final class BrowserWebKitTests: XCTestCase {
    @MainActor
    func testDisconnectedBrowserMakesNoNavigationAndPreviewIsIsolated() throws {
        let site = try XCTUnwrap(URL(string: "https://browser-test.invalid/"))
        let live = BrowserTab(page: .website(site, nil), permit: { false })
        live.start()
        XCTAssertNil(live.webView.url)
        XCTAssertFalse(live.webView.isLoading)
        XCTAssertFalse(live.webView.configuration.websiteDataStore.isPersistent)
        let preview = BrowserTab(page: .preview("192.0.2.7"), permit: { false })
        XCTAssertFalse(preview.webView.configuration.defaultWebpagePreferences.allowsContentJavaScript)
        XCTAssertFalse(preview.webView.configuration.websiteDataStore.isPersistent)
        XCTAssertFalse(preview.webView.configuration.websiteDataStore === live.webView.configuration.websiteDataStore)
    }

    @MainActor
    func testTrustedProxyLoadsTheHTTPSOrigin() async throws {
        let config = FileManager.default.temporaryDirectory.appendingPathComponent("cuven-browser-proxy")
        try XCTSkipUnless(FileManager.default.fileExists(atPath: config.path), "The private simulator proxy fixture is required")
        let address = try String(contentsOf: config, encoding: .utf8)
        let proxy = try XCTUnwrap(BrowserProxy(address: address, username: "", password: ""))
        let destination = try XCTUnwrap(URL(string: "https://cuven-browser.test/proof"))
        let tab = BrowserTab(page: .website(destination, proxy), permit: { true })
        defer { tab.close() }
        tab.start()
        let deadline = ContinuousClock.now + .seconds(15)
        while tab.webView.title != "Cuven HTTPS fixture", tab.error == nil, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertEqual(tab.webView.title, "Cuven HTTPS fixture", tab.error ?? "Expected the private origin through CONNECT")
        XCTAssertEqual(tab.webView.url, destination)
        tab.close()
        let closeDeadline = ContinuousClock.now + .seconds(5)
        while tab.webView.title != "浏览已结束", ContinuousClock.now < closeDeadline {
            try await Task.sleep(for: .milliseconds(50))
        }
        XCTAssertEqual(tab.webView.title, "浏览已结束")
        XCTAssertNotEqual(tab.webView.url, destination)
    }

    @MainActor
    func testWebKitConnectsToCustomProxyUsingTLS() async throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: params)
        defer { listener.cancel() }
        let listening = expectation(description: "Local proxy fixture ready")
        let clientHello = expectation(description: "WebKit reached the configured proxy over TLS")
        listener.stateUpdateHandler = { state in
            if case .ready = state { listening.fulfill() }
        }
        listener.newConnectionHandler = { connection in
            connection.start(queue: DispatchQueue(label: "test.browser.proxy.connection"))
            connection.receive(minimumIncompleteLength: 3, maximumLength: 3) { data, _, _, _ in
                if let data, data.starts(with: [0x16, 0x03]) { clientHello.fulfill() }
                connection.cancel()
            }
        }
        clientHello.assertForOverFulfill = false
        listener.start(queue: DispatchQueue(label: "test.browser.proxy.listener"))
        await fulfillment(of: [listening], timeout: 8)
        let port = try XCTUnwrap(listener.port)
        let proxy = try XCTUnwrap(BrowserProxy(address: "127.0.0.1:\(port.rawValue)", username: "", password: ""))
        let site = try XCTUnwrap(URL(string: "https://browser-test.invalid/"))
        let tab = BrowserTab(page: .website(site, proxy), permit: { true })
        defer { tab.close() }
        let configured = try XCTUnwrap(tab.webView.configuration.websiteDataStore.proxyConfigurations.first)
        XCTAssertFalse(configured.allowFailover)
        tab.start()
        await fulfillment(of: [clientHello], timeout: 15)
    }
}
