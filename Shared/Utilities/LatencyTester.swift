//
//  LatencyTester.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LatencyTester")

enum LatencyResult: Sendable {
    case testing
    case success(Int)  // milliseconds
    case failed
    case insecure
}

private enum LatencyTestError: Error, LocalizedError {
    case unexpectedStatus(String)

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status): return "Unexpected status: \(status)"
        }
    }
}

/// Tests full proxy round-trip latency by establishing a proxy connection
/// and sending an HTTP request through the proxy chain.
nonisolated enum LatencyTester {

    /// Per-test timeout.
    private static let timeout: Duration = .seconds(3)

    /// Latency test endpoint
    private static let latencyHost = "captive.apple.com"
    private static let latencyPort: UInt16 = 80

    /// Test a single configuration's proxy round-trip latency.
    ///
    /// Measures data transfer RTT: the HTTP request is sent untimed (triggering
    /// the proxy-to-target connection and protocol handshake), then only the
    /// receive is timed — capturing the actual network round-trip through the
    /// full proxy chain. DNS resolution is excluded via pre-warming.
    nonisolated static func test(_ configuration: ProxyConfiguration) async -> LatencyResult {
        let testConfiguration = resolvedConfiguration(configuration)

        do {
            let ms = try await withThrowingTaskGroup(of: Int.self) { group in
                group.addTask {
                    try await Self.performTest(testConfiguration)
                }
                group.addTask {
                    try await Task.sleep(for: Self.timeout)
                    throw CancellationError()
                }

                let result = try await group.next()!
                group.cancelAll()
                return result
            }
            return .success(ms)
        } catch let error as TLSError {
            if case .certificateValidationFailed = error {
                logger.error("Latency test insecure for \(configuration.name): \(error.localizedDescription)")
                return .insecure
            }
            logger.error("Latency test failed for \(configuration.name): \(error.localizedDescription)")
            return .failed
        } catch {
            logger.error("Latency test failed for \(configuration.name): \(error.localizedDescription)")
            return .failed
        }
    }

    /// Maximum number of latency tests running at the same time. High enough that
    /// unavailable proxies (which sit on the per-test timeout) do not starve out
    /// working proxies further down the list.
    private static let maxConcurrentTests = 16

    /// Test all configurations concurrently (capped), emitting results as each test finishes.
    nonisolated static func testAll(_ configurations: [ProxyConfiguration]) -> AsyncStream<(UUID, LatencyResult)> {
        AsyncStream { continuation in
            let task = Task {
                await withTaskGroup(of: (UUID, LatencyResult).self) { group in
                    var iterator = configurations.makeIterator()

                    for _ in 0..<min(Self.maxConcurrentTests, configurations.count) {
                        if let config = iterator.next() {
                            group.addTask { (config.id, await Self.test(config)) }
                        }
                    }

                    for await pair in group {
                        continuation.yield(pair)
                        if let config = iterator.next() {
                            group.addTask { (config.id, await Self.test(config)) }
                        }
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    // MARK: - Private

    /// Resolves each proxy hop ahead of time so latency tests can dial the same
    /// first-hop IPs the tunnel expects, without depending on in-tunnel DNS timing.
    nonisolated static func resolvedConfiguration(_ configuration: ProxyConfiguration) -> ProxyConfiguration {
        let resolvedChain = configuration.chain?.map(resolvedConfiguration)
        return ProxyConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            resolvedIP: configuration.resolvedIP ?? VPNViewModel.resolveServerAddress(configuration.serverAddress),
            subscriptionId: configuration.subscriptionId,
            outbound: configuration.outbound,
            chain: resolvedChain
        )
    }

    /// Resolves a batch of configurations in parallel. `resolvedConfiguration`
    /// makes blocking `getaddrinfo` calls for any hop without a cached IP, so
    /// running a serial map over a list with several unresolvable hosts can
    /// stall a latency-test batch for many seconds before any test starts.
    nonisolated static func resolvedConfigurations(_ configurations: [ProxyConfiguration]) async -> [ProxyConfiguration] {
        await withTaskGroup(of: (Int, ProxyConfiguration).self) { group in
            for (index, configuration) in configurations.enumerated() {
                group.addTask { (index, resolvedConfiguration(configuration)) }
            }
            var results = [ProxyConfiguration?](repeating: nil, count: configurations.count)
            for await (index, resolved) in group {
                results[index] = resolved
            }
            return results.compactMap { $0 }
        }
    }

    private static func performTest(_ configuration: ProxyConfiguration) async throws -> Int {
        // Pre-warm DNS cache so resolution is excluded from timing
        ProxyDNSCache.shared.prewarm(configuration.serverAddress)
        if let chain = configuration.chain {
            for proxy in chain {
                ProxyDNSCache.shared.prewarm(proxy.serverAddress)
            }
        }

        let client = ProxyClient(configuration: configuration, useResolvedAddressForDirectDial: true)
        let resumer = LatencyTester.PendingResumer()

        return try await withTaskCancellationHandler {
            defer { client.cancel() }

            // Phase 1 (untimed): Establish proxy connection.
            // TCP + TLS/Reality + VLESS/SS handshake.
            let proxyConnection: ProxyConnection = try await awaitCallback(resumer: resumer) { complete in
                client.connect(to: Self.latencyHost, port: Self.latencyPort) { complete($0) }
            }

            // Phase 2 (untimed warmup): Send a first request to prime the
            // proxy-to-target connection.
            let warmupRequest = "HEAD / HTTP/1.1\r\nHost: \(Self.latencyHost)\r\n\r\n".data(using: .utf8)!

            try await awaitCallback(resumer: resumer) { (complete: @escaping (Result<Void, Error>) -> Void) in
                proxyConnection.send(data: warmupRequest) { error in
                    if let error { complete(.failure(error)) } else { complete(.success(())) }
                }
            }

            let warmupData: Data? = try await awaitCallback(resumer: resumer) { (complete: @escaping (Result<Data?, Error>) -> Void) in
                proxyConnection.receive { data, error in
                    if let error { complete(.failure(error)) } else { complete(.success(data)) }
                }
            }

            // Validate warmup response
            let warmupStatus = warmupData.flatMap { String(data: $0, encoding: .utf8) }?
                .split(separator: "\r\n", maxSplits: 1).first.map(String.init)
            guard let warmupStatus, warmupStatus.contains("200") else {
                throw LatencyTestError.unexpectedStatus(warmupStatus ?? "no response")
            }

            // Phase 3 (untimed): Send the timed HTTP request.
            let httpRequest = "HEAD / HTTP/1.1\r\nHost: \(Self.latencyHost)\r\nConnection: close\r\n\r\n".data(using: .utf8)!

            try await awaitCallback(resumer: resumer) { (complete: @escaping (Result<Void, Error>) -> Void) in
                proxyConnection.send(data: httpRequest) { error in
                    if let error { complete(.failure(error)) } else { complete(.success(())) }
                }
            }

            // Phase 4 (timed): Wait for the response.
            // Timer starts after send completes — measures the actual network
            // round-trip: data traverses client → proxy chain → target → back.
            let clock = ContinuousClock()
            let start = clock.now

            let responseData: Data? = try await awaitCallback(resumer: resumer) { (complete: @escaping (Result<Data?, Error>) -> Void) in
                proxyConnection.receive { data, error in
                    if let error { complete(.failure(error)) } else { complete(.success(data)) }
                }
            }

            let elapsed = clock.now - start

            // Validate HTTP 200 response
            let statusLine = responseData.flatMap { String(data: $0, encoding: .utf8) }?
                .split(separator: "\r\n", maxSplits: 1).first.map(String.init)
            guard let statusLine, statusLine.contains("200") else {
                throw LatencyTestError.unexpectedStatus(statusLine ?? "no response")
            }

            let ms = Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
            return ms
        } onCancel: {
            client.cancel()
            resumer.cancel()
        }
    }

    /// Hook that the task-cancellation handler invokes to fail whichever phase
    /// is currently awaiting, in case `client.cancel()` doesn't propagate to
    /// the underlying callback.
    private final class PendingResumer: @unchecked Sendable {
        private let lock = NSLock()
        private var hook: ((Error) -> Void)?

        func install(_ hook: @escaping (Error) -> Void) {
            lock.lock(); defer { lock.unlock() }
            self.hook = hook
        }

        func clear() {
            lock.lock(); defer { lock.unlock() }
            hook = nil
        }

        func cancel() {
            lock.lock()
            let h = hook
            hook = nil
            lock.unlock()
            h?(CancellationError())
        }
    }

    /// One-shot continuation wrapper. Either the operation callback or the
    /// cancellation hook resumes it; the second caller is a no-op. Without
    /// this, a cancel during a hung send/receive leaks the continuation.
    private final class OneShotResumer<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Error>?

        func arm(_ continuation: CheckedContinuation<T, Error>) {
            lock.lock(); defer { lock.unlock() }
            self.continuation = continuation
        }

        func resume(_ result: Result<T, Error>) {
            lock.lock()
            let c = continuation
            continuation = nil
            lock.unlock()
            c?.resume(with: result)
        }
    }

    /// Bridges a callback-style operation to async/await with one-shot cancel
    /// safety: the continuation resumes exactly once, either from the callback
    /// or from the task's cancellation handler.
    private static func awaitCallback<T>(
        resumer pending: PendingResumer,
        operation: (@escaping (Result<T, Error>) -> Void) -> Void
    ) async throws -> T {
        let oneShot = OneShotResumer<T>()
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
            oneShot.arm(continuation)
            pending.install { error in
                oneShot.resume(.failure(error))
            }
            if Task.isCancelled {
                pending.clear()
                oneShot.resume(.failure(CancellationError()))
                return
            }
            operation { result in
                pending.clear()
                oneShot.resume(result)
            }
        }
    }
}
