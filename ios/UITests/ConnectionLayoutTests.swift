import XCTest

final class ConnectionLayoutTests: XCTestCase {
    @MainActor
    func testConnectionSettingsStayReachableAfterRotation() {
        let device = XCUIDevice.shared
        device.orientation = .portrait
        defer { device.orientation = .portrait }

        let app = XCUIApplication()
        app.launch()
        XCTAssertFalse(app.textFields["服务器地址"].exists)
        XCTAssertFalse(app.secureTextFields["Cuven IP 接入令牌"].exists)
        let settings = app.descendants(matching: .any).matching(identifier: "connection-settings").firstMatch
        if !settings.waitForExistence(timeout: 3) || !settings.isHittable { app.swipeUp() }
        XCTAssertTrue(settings.isHittable)
        settings.tap()

        let title = app.navigationBars["连接设置"]
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        XCTAssertTrue(app.textFields["服务器地址"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.secureTextFields["Cuven IP 接入令牌"].exists)
        let lockdown = app.switches["cuven-lockdown"]
        for _ in 0..<4 where !lockdown.isHittable { app.swipeUp() }
        XCTAssertTrue(lockdown.isHittable)
        XCTAssertEqual(lockdown.value as? String, "0")
        device.orientation = .landscapeLeft
        XCTAssertTrue(title.waitForExistence(timeout: 5))
    }

    @MainActor
    func testBrowserCanPreviewCustomIPv6WithoutConnecting() {
        let app = XCUIApplication()
        app.launch()
        let browser = app.descendants(matching: .any).matching(identifier: "private-browser").firstMatch
        if !browser.isHittable { app.swipeUp() }
        XCTAssertTrue(browser.waitForExistence(timeout: 5))
        browser.tap()
        XCTAssertFalse(app.buttons["打开网页"].isEnabled)
        app.buttons["本地预览"].tap()
        let ip = app.textFields["模拟 IPv4 或 IPv6"]
        ip.tap()
        ip.typeText("2001:db8::27")
        app.buttons["预览 IP"].tap()
        XCTAssertTrue(app.webViews.staticTexts["2001:db8::27"].waitForExistence(timeout: 12))
        app.buttons["关闭"].tap()
        XCTAssertTrue(app.buttons["预览 IP"].waitForExistence(timeout: 5))
    }
}
