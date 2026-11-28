import XCTest
@testable import Cuven

final class GatewayBusyRetryTests: XCTestCase {
    func testColdAndWarmRetriesAreBounded() {
        for (installed, count) in [(false, 3), (true, 8)] {
            var policy = GatewayBusyRetry()
            let start = ContinuousClock.now
            for i in 0..<count {
                XCTAssertEqual(policy.delay(for: .gatewayBusy, routesInstalled: installed, now: start + .seconds(2 * i)), 2)
            }
            XCTAssertNil(policy.delay(for: .gatewayBusy, routesInstalled: installed, now: start + .seconds(2 * count)))
        }
    }

    func testSleepDoesNotExtendTheBusyWindow() {
        for (installed, seconds) in [(false, 8), (true, 20)] {
            var policy = GatewayBusyRetry()
            let start = ContinuousClock.now
            XCTAssertEqual(policy.delay(for: .gatewayBusy, routesInstalled: installed, now: start), 2)
            XCTAssertNil(policy.delay(for: .gatewayBusy, routesInstalled: installed, now: start + .seconds(seconds)))
        }
    }

    func testOnlyABusyGatewayStartsTheShortRetryWindow() {
        var policy = GatewayBusyRetry()
        let start = ContinuousClock.now
        for failure in [TunnelFailure.gatewayRejected, .certificatePin, .certificateName, .certificateTime,
                        .certificateTrust, .gatewayIPv6, .connection, .gatewayTimeout, .settings] {
            XCTAssertNil(policy.delay(for: failure, routesInstalled: true, now: start))
        }
        XCTAssertEqual(policy.delay(for: .gatewayBusy, routesInstalled: true, now: start + .seconds(60)), 2)
    }
}
