import XCTest
@testable import Cuven

final class GatewayStartupResolverTests: XCTestCase {
    func testOfflineRetryWaitsForAnAvailablePathBeforeResolving() {
        let state = DispatchQueue(label: "test.resolver.offline-start")
        let entered = DispatchSemaphore(value: 0)
        let completed = expectation(description: "resolver resumed")
        let resolver = GatewayStartupResolver(state: state) { _, _ in
            entered.signal()
            return ["new"]
        }
        state.sync {
            resolver.start(host: "gateway.example", port: 4433, available: false) { result in
                XCTAssertEqual(try? result.get(), ["new"])
                completed.fulfill()
            }
        }
        XCTAssertEqual(entered.wait(timeout: .now() + .milliseconds(100)), .timedOut)
        state.sync { resolver.pathChanged(available: true) }
        wait(for: [completed], timeout: 2)
        XCTAssertEqual(entered.wait(timeout: .now()), .success)
    }

    func testOneDeadlineWhilePathIsUnavailable() {
        let state = DispatchQueue(label: "test.resolver.state")
        let completed = expectation(description: "startup reported DNS timeout")
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let resolver = GatewayStartupResolver(state: state, budget: .milliseconds(100)) { _, _ in
            _ = gate.wait(timeout: .now() + .seconds(3))
            return ["old"]
        }

        state.sync {
            resolver.start(host: "gateway.example", port: 4433) { result in
                guard case .failure(.resolutionTimeout) = result else {
                    XCTFail("Expected the startup DNS timeout")
                    return
                }
                completed.fulfill()
            }
            resolver.pathChanged(available: false)
        }
        wait(for: [completed], timeout: 2)
        XCTAssertFalse(state.sync { resolver.isPending })
    }

    func testNewPathCanAnswerWhileFirstLookupIsBlocked() {
        let state = DispatchQueue(label: "test.resolver.state")
        let calls = DispatchQueue(label: "test.resolver.call-count")
        let firstEntered = expectation(description: "first resolver entered")
        let completed = expectation(description: "new path answered")
        let release = DispatchSemaphore(value: 0)
        defer { release.signal() }
        var count = 0
        let resolver = GatewayStartupResolver(state: state) { _, _ in
            let index = calls.sync {
                count += 1
                return count
            }
            if index == 1 {
                firstEntered.fulfill()
                _ = release.wait(timeout: .now() + .seconds(3))
                return ["old"]
            }
            return ["new"]
        }
        state.sync {
            resolver.start(host: "gateway.example", port: 4433) { result in
                XCTAssertEqual(try? result.get(), ["new"])
                completed.fulfill()
            }
        }
        wait(for: [firstEntered], timeout: 2)
        state.sync { resolver.pathChanged(available: true) }
        wait(for: [completed], timeout: 2)
        XCTAssertFalse(state.sync { resolver.isPending })
        XCTAssertEqual(calls.sync { count }, 2)
    }

    func testCancelAndImmediateRetryIgnoreOldAnswer() {
        let state = DispatchQueue(label: "test.resolver.state")
        let firstEntered = expectation(description: "old lookup started")
        let oldReturned = expectation(description: "old worker returned")
        let nextReturned = expectation(description: "new lookup finished")
        let release = DispatchSemaphore(value: 0)
        let resolver = GatewayStartupResolver(state: state) { host, _ in
            if host == "old.example" {
                firstEntered.fulfill()
                _ = release.wait(timeout: .now() + .seconds(3))
                oldReturned.fulfill()
                return ["old"]
            }
            return []
        }
        state.sync { resolver.start(host: "old.example", port: 4433) { _ in XCTFail("Cancelled lookup replied") } }
        wait(for: [firstEntered], timeout: 2)
        state.sync {
            resolver.cancel()
            resolver.start(host: "new.example", port: 4433) { result in
                guard case .failure(.resolution) = result else {
                    XCTFail("Expected an empty DNS answer")
                    return
                }
                nextReturned.fulfill()
            }
        }
        wait(for: [nextReturned], timeout: 2)
        release.signal()
        wait(for: [oldReturned], timeout: 2)
        XCTAssertFalse(state.sync { resolver.isPending })
    }
}
