import XCTest

final class ConnectionLayoutTests: XCTestCase {
    @MainActor
    func testConnectionSettingsStayReachableAfterRotation() {
        let device = XCUIDevice.shared
        device.orientation = .portrait
        defer { device.orientation = .portrait }

        let app = XCUIApplication()
        app.launch()
        let settings = app.descendants(matching: .any).matching(identifier: "connection-settings").firstMatch
        if !settings.waitForExistence(timeout: 3) || !settings.isHittable { app.swipeUp() }
        XCTAssertTrue(settings.isHittable)
        settings.tap()

        let title = app.navigationBars["连接设置"]
        XCTAssertTrue(title.waitForExistence(timeout: 5))
        device.orientation = .landscapeLeft
        XCTAssertTrue(title.waitForExistence(timeout: 5))
    }
}
