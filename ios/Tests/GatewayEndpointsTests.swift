import XCTest
@testable import Cuven

final class GatewayEndpointsTests: XCTestCase {
    func testLookupFailureAndRepeatedDNSAnswerKeepWorkingRotation() throws {
        var endpoints = GatewayEndpoints()
        XCTAssertNil(endpoints.next())
        endpoints.replace(with: ["v6", "v4", "backup", "extra"])
        XCTAssertEqual(endpoints.next(), "v6")
        let now = DispatchTime(uptimeNanoseconds: 1_000)
        let first = try XCTUnwrap(endpoints.beginRefresh(now: now))
        endpoints.finishRefresh(first, with: [])
        XCTAssertNil(endpoints.beginRefresh(now: now + .seconds(59)))
        XCTAssertEqual(endpoints.next(), "v4")
        let second = try XCTUnwrap(endpoints.beginRefresh(now: now + .seconds(60)))
        XCTAssertNotEqual(first, second)
        endpoints.finishRefresh(first, with: ["stale"])
        endpoints.finishRefresh(second, with: ["v6", "v4", "backup", "extra"])
        XCTAssertEqual(endpoints.next(), "backup")
        XCTAssertFalse(endpoints.hasUntriedAddress)
        XCTAssertEqual(endpoints.next(), "v6")
    }

    func testNewPathCanFinishBeforeStaleLookupWithoutLosingItsEndpoints() throws {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["old"])
        let oldLookup = try XCTUnwrap(endpoints.beginRefresh())
        endpoints.pathChanged()
        let newLookup = try XCTUnwrap(endpoints.beginRefresh())
        XCTAssertNil(endpoints.beginRefresh())
        XCTAssertEqual(endpoints.next(), "old")
        endpoints.finishRefresh(newLookup, with: ["new-primary", "new-secondary"])
        endpoints.finishRefresh(oldLookup, with: ["obsolete"])
        // A successful attempt on the old address can race the new DNS answer.
        endpoints.prefer("old")
        XCTAssertEqual(endpoints.next(), "new-primary")
        XCTAssertEqual(endpoints.next(), "new-secondary")
        endpoints.prefer("new-secondary")
        XCTAssertEqual(endpoints.next(), "new-secondary")
    }

    func testRepeatedHandoversBoundPendingLookupsAndDiscardBothOldAnswers() throws {
        var endpoints = GatewayEndpoints()
        let first = try XCTUnwrap(endpoints.beginRefresh())
        endpoints.pathChanged()
        let second = try XCTUnwrap(endpoints.beginRefresh())
        for _ in 0..<5 {
            endpoints.pathChanged()
            XCTAssertNil(endpoints.beginRefresh())
        }
        endpoints.finishRefresh(second, with: ["obsolete"])
        XCTAssertNil(endpoints.next())
        let current = try XCTUnwrap(endpoints.beginRefresh())
        endpoints.finishRefresh(first, with: ["older"])
        XCTAssertNil(endpoints.next())
        endpoints.finishRefresh(current, with: ["current"])
        XCTAssertEqual(endpoints.next(), "current")
    }
}
