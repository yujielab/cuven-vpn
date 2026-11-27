import Foundation

/// The provider owns this state on its serial queue. A lookup may finish after
/// the active path changed or after an attempt using the old list succeeded.
struct GatewayEndpoints {
    private var addresses: [String] = []
    private var nextIndex = 0
    private var pathID = UUID()
    private var lookup: (id: UUID, path: UUID)?
    private var nextLookup: DispatchTime?

    var hasUntriedAddress: Bool { nextIndex < addresses.count }

    mutating func replace(with resolved: [String]) {
        let fresh = Array(resolved.prefix(3))
        guard !fresh.isEmpty, fresh != addresses else { return }
        addresses = fresh
        nextIndex = 0
    }

    mutating func next() -> String? {
        guard !addresses.isEmpty else { return nil }
        let address = addresses[nextIndex % addresses.count]
        nextIndex += 1
        return address
    }

    mutating func prefer(_ address: String) {
        if let index = addresses.firstIndex(of: address) { nextIndex = index }
    }

    mutating func pathChanged() {
        pathID = UUID()
        nextLookup = nil
    }

    mutating func beginRefresh(now: DispatchTime = .now()) -> UUID? {
        guard lookup == nil else { return nil }
        if let nextLookup, now < nextLookup { return nil }
        let id = UUID()
        lookup = (id, pathID)
        nextLookup = now + .seconds(60)
        return id
    }

    mutating func finishRefresh(_ id: UUID, with resolved: [String]) {
        guard let active = lookup, active.id == id else { return }
        lookup = nil
        if pathID == active.path { replace(with: resolved) }
    }
}
