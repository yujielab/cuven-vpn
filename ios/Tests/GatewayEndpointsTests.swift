import XCTest
@testable import Cuven

final class GatewayEndpointsTests: XCTestCase {
    func testColdDialRefreshesOnceAfterPathChangeAndRetriesIdenticalAnswersFromTheStart() {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["primary", "secondary"])
        XCTAssertEqual(endpoints.next(), "primary")
        XCTAssertFalse(endpoints.retryStartupResolution(after: .gatewayTimeout))
        endpoints.pathChanged()
        for failure in [TunnelFailure.gatewayRejected, .gatewayBusy, .certificateTrust, .cancelled, .settings] {
            XCTAssertFalse(endpoints.retryStartupResolution(after: failure))
        }
        XCTAssertTrue(endpoints.retryStartupResolution(after: .gatewayTimeout))
        XCTAssertNil(endpoints.next())
        endpoints.replace(with: ["primary", "secondary"])
        XCTAssertEqual(endpoints.next(), "primary")
        endpoints.pathChanged()
        XCTAssertFalse(endpoints.retryStartupResolution(after: .connection))
        XCTAssertEqual(endpoints.next(), "secondary")
    }

    func testColdConnectionFailureDropsUntriedAddressesFromTheOldPath() {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["old", "old-backup"])
        XCTAssertEqual(endpoints.next(), "old")
        endpoints.pathChanged()
        XCTAssertTrue(endpoints.retryStartupResolution(after: .connection))
        XCTAssertFalse(endpoints.hasUntriedAddress)
        endpoints.replace(with: ["new"])
        XCTAssertEqual(endpoints.next(), "new")
    }

    func testReachableGatewayDiagnosisSurvivesAnUnreachableFallback() {
        for cause: TunnelFailure in [.certificateName, .certificateTime, .certificateTrust,
                                     .gatewayRejected, .gatewayBusy, .gatewayIPv6] {
            var endpoints = GatewayEndpoints()
            XCTAssertEqual(endpoints.recordStartupFailure(.gatewayTimeout), .gatewayTimeout)
            XCTAssertEqual(endpoints.recordStartupFailure(cause), cause)
            XCTAssertEqual(endpoints.recordStartupFailure(.connection), cause)
            XCTAssertEqual(endpoints.recordStartupFailure(.gatewayTimeout), cause)
            XCTAssertEqual(endpoints.recordStartupFailure(.cancelled), .cancelled)
            XCTAssertEqual(endpoints.recordStartupFailure(.settings), .settings)
        }
    }

    func testStartupDiagnosisIsScopedToTheCurrentPathAndAddressList() {
        var endpoints = GatewayEndpoints()
        _ = endpoints.recordStartupFailure(.certificateTrust)
        XCTAssertEqual(endpoints.recordStartupFailure(.gatewayRejected), .gatewayRejected)
        XCTAssertEqual(endpoints.recordStartupFailure(.connection), .gatewayRejected)
        endpoints.pathChanged()
        XCTAssertEqual(endpoints.recordStartupFailure(.gatewayTimeout), .gatewayTimeout)
        _ = endpoints.recordStartupFailure(.certificateName)
        XCTAssertTrue(endpoints.retryStartupResolution(after: .connection))
        XCTAssertEqual(endpoints.recordStartupFailure(.connection), .connection)
    }

    func testExhaustedSamePathAttemptsOnlyNewAnswersAndRetainsWarmRotation() {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["old", "backup"])
        XCTAssertEqual(endpoints.next(), "old")
        XCTAssertFalse(endpoints.retryStartupResolution(after: .connection))
        XCTAssertEqual(endpoints.next(), "backup")
        XCTAssertTrue(endpoints.retryStartupResolution(after: .connection))
        XCTAssertEqual(endpoints.exhaustedStartupFailure, .connection)
        XCTAssertNil(endpoints.installStartupAnswers(["backup", "new", "old"]))
        XCTAssertEqual(endpoints.next(), "new")
        XCTAssertFalse(endpoints.hasUntriedAddress)
        XCTAssertFalse(endpoints.retryStartupResolution(after: .connection))
        XCTAssertEqual(endpoints.next(), "backup")
    }

    func testRepeatedOrReorderedStartupAnswerReturnsOriginalTimeout() {
        for answer in [["first", "second"], ["second", "first"], ["second"]] {
            var endpoints = GatewayEndpoints()
            endpoints.replace(with: ["first", "second"])
            _ = endpoints.next()
            _ = endpoints.next()
            XCTAssertTrue(endpoints.retryStartupResolution(after: .gatewayTimeout))
            XCTAssertEqual(endpoints.installStartupAnswers(answer), .gatewayTimeout)
            XCTAssertFalse(endpoints.hasUntriedAddress)
        }
    }

    func testPathSwitchDuringFinalLookupCanRetryPreviouslyUnreachableAddress() {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["ip"])
        _ = endpoints.next()
        XCTAssertTrue(endpoints.retryStartupResolution(after: .connection))
        endpoints.pathChanged(whileResolving: true)
        XCTAssertNil(endpoints.exhaustedStartupFailure)
        XCTAssertNil(endpoints.installStartupAnswers(["ip"]))
        XCTAssertEqual(endpoints.next(), "ip")
        XCTAssertFalse(endpoints.retryStartupResolution(after: .connection))
    }

    func testReachableGatewayErrorAvoidsAnExtraSamePathLookup() {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["reachable", "unreachable"])
        _ = endpoints.next()
        _ = endpoints.recordStartupFailure(.gatewayRejected)
        _ = endpoints.next()
        XCTAssertFalse(endpoints.retryStartupResolution(after: .connection))
        XCTAssertEqual(endpoints.recordStartupFailure(.connection), .gatewayRejected)
    }

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

    func testNewAnswerIsTriedFirstEvenWhenDNSListsItLast() throws {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["old", "backup"])
        let lookup = try XCTUnwrap(endpoints.beginRefresh())
        XCTAssertTrue(endpoints.finishRefresh(lookup, with: ["old", "new"]))
        XCTAssertEqual(endpoints.next(), "new")
        XCTAssertEqual(endpoints.next(), "old")
        XCTAssertFalse(endpoints.finishRefresh(lookup, with: ["stale"]))
    }

    func testReorderedOrReducedAnswersDoNotWakeBackoff() throws {
        var endpoints = GatewayEndpoints()
        endpoints.replace(with: ["a", "b", "c"])
        XCTAssertEqual(endpoints.next(), "a")
        let now = DispatchTime.now()
        let reordered = try XCTUnwrap(endpoints.beginRefresh(now: now))
        XCTAssertFalse(endpoints.finishRefresh(reordered, with: ["b", "c", "a"]))
        XCTAssertEqual(endpoints.next(), "b")
        let reduced = try XCTUnwrap(endpoints.beginRefresh(now: now + .seconds(60)))
        XCTAssertFalse(endpoints.finishRefresh(reduced, with: ["c"]))
        XCTAssertEqual(endpoints.next(), "c")
    }

    func testBusyAddressSurvivesUnreachableFallbackButNeverOverridesSecurityFailure() {
        for failure in [TunnelFailure.gatewayRejected, .certificateTrust, .certificatePin] {
            var endpoints = GatewayEndpoints()
            XCTAssertEqual(endpoints.recordStartupFailure(.gatewayBusy, at: "busy"), .gatewayBusy)
            XCTAssertEqual(endpoints.recordStartupFailure(.gatewayTimeout, at: "offline"), .gatewayBusy)
            XCTAssertEqual(endpoints.startupBusyEndpoint, "busy")
            XCTAssertEqual(endpoints.recordStartupFailure(failure, at: "denied"), failure)
            XCTAssertEqual(endpoints.recordStartupFailure(.gatewayBusy, at: "busy"), failure)
            XCTAssertNil(endpoints.startupBusyEndpoint)
            endpoints.pathChanged()
            XCTAssertEqual(endpoints.recordStartupFailure(.gatewayBusy, at: "other"), .gatewayBusy)
            endpoints.pathChanged()
            XCTAssertNil(endpoints.startupBusyEndpoint)
        }
    }
}
