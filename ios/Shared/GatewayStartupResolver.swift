import Foundation

/// The provider calls this on its serial state queue. A cancelled system lookup
/// can still be inside getaddrinfo, so bound the number of worker threads.
final class GatewayStartupResolver {
    typealias Reply = (Result<[String], TunnelFailure>) -> Void

    private let state: DispatchQueue
    private let budget: DispatchTimeInterval
    private let lookup: (String, Int) -> [String]
    private let workers = OperationQueue()
    private var request: (host: String, port: Int, reply: Reply)?
    private var operation: BlockOperation?
    private var deadline: DispatchWorkItem?

    var isPending: Bool { request != nil }

    init(state: DispatchQueue, budget: DispatchTimeInterval = .seconds(12),
         lookup: @escaping (String, Int) -> [String]) {
        self.state = state
        self.budget = budget
        self.lookup = lookup
        workers.name = "dev.cuven.vpn.startup-dns"
        workers.qualityOfService = .userInitiated
        workers.maxConcurrentOperationCount = 2
    }

    func start(host: String, port: Int, reply: @escaping Reply) {
        cancel()
        request = (host, port, reply)
        let expiry = DispatchWorkItem { [weak self] in self?.finish(.failure(.resolutionTimeout)) }
        deadline = expiry
        state.asyncAfter(deadline: .now() + budget, execute: expiry)
        pathChanged(available: true)
    }

    func pathChanged(available: Bool) {
        operation?.cancel()
        operation = nil
        guard available, let request else { return }
        let host = request.host, port = request.port
        let work = BlockOperation()
        work.addExecutionBlock { [weak self, weak work, lookup, state] in
            guard work?.isCancelled == false else { return }
            let addresses = lookup(host, port)
            state.async { [weak self, weak work] in
                guard let self, let work, self.operation === work, !work.isCancelled else { return }
                self.finish(addresses.isEmpty ? .failure(.resolution) : .success(addresses))
            }
        }
        operation = work
        workers.addOperation(work)
    }

    func cancel() {
        deadline?.cancel()
        deadline = nil
        operation?.cancel()
        operation = nil
        request = nil
    }

    private func finish(_ result: Result<[String], TunnelFailure>) {
        let reply = request?.reply
        cancel()
        reply?(result)
    }
}
