import XCTest
@testable import Cuven

final class TunnelRTTMeasurementTests: XCTestCase {
    func testOlderAndPreviousConnectionRepliesCannotReplaceANewSample() {
        var sample = TunnelRTTMeasurement()
        let beforeReconnect = sample.begin()
        sample = TunnelRTTMeasurement()
        let earlier = sample.begin()
        let latest = sample.begin()
        sample.finish(latest, reply: Data("20".utf8))
        sample.finish(earlier, reply: Data("90".utf8))
        sample.finish(beforeReconnect, reply: Data("999".utf8))
        XCTAssertEqual(sample.milliseconds, 20)
    }

    func testClearingForBackgroundDropsLastValueAndPendingReply() {
        var sample = TunnelRTTMeasurement()
        let measured = sample.begin()
        sample.finish(measured, reply: Data("12".utf8))
        let pending = sample.begin()
        sample = TunnelRTTMeasurement()
        sample.finish(pending, reply: Data("98".utf8))
        XCTAssertNil(sample.milliseconds)
        let resumed = sample.begin()
        sample.finish(resumed, reply: Data("17".utf8))
        XCTAssertEqual(sample.milliseconds, 17)
    }

    func testUnansweredPollExpiresAndNextValidSampleRecovers() {
        var sample = TunnelRTTMeasurement()
        let first = sample.begin()
        sample.finish(first, reply: Data("42".utf8))
        _ = sample.begin()
        XCTAssertEqual(sample.milliseconds, 42)
        let fresh = sample.begin()
        XCTAssertNil(sample.milliseconds)
        sample.finish(fresh, reply: Data("0".utf8))
        XCTAssertEqual(sample.milliseconds, 0)
    }

    func testMissingMalformedAndNegativeRepliesClearLastSample() {
        for reply in [nil, Data(), Data("-1".utf8), Data("invalid".utf8)] as [Data?] {
            var sample = TunnelRTTMeasurement()
            let first = sample.begin()
            sample.finish(first, reply: Data("20".utf8))
            let next = sample.begin()
            sample.finish(next, reply: reply)
            XCTAssertNil(sample.milliseconds)
        }
    }
}
