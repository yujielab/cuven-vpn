import XCTest
@testable import Cuven

final class TunnelSleepIntervalTests: XCTestCase {
    func testWakeOnlyRenewsOnceForTheSameLongSuspension() {
        let start = ContinuousClock.now
        var interval = TunnelSleepInterval()
        XCTAssertFalse(interval.needsReconnectOnWake(at: start))
        interval.begin(at: start)
        interval.begin(at: start + .seconds(70))
        XCTAssertTrue(interval.needsReconnectOnWake(at: start + .seconds(90)))
        XCTAssertFalse(interval.needsReconnectOnWake(at: start + .seconds(91)))
    }

    func testShortSleepAndReplacedEngineDoNotReconnect() {
        let start = ContinuousClock.now
        var interval = TunnelSleepInterval()
        interval.begin(at: start)
        XCTAssertFalse(interval.needsReconnectOnWake(at: start + .seconds(89)))
        interval.begin(at: start + .seconds(90))
        interval = TunnelSleepInterval()
        XCTAssertFalse(interval.needsReconnectOnWake(at: start + .seconds(180)))
    }
}
