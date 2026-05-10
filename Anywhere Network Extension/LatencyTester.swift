//
//  LatencyTester.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "LatencyTester")

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

    // MARK: - Private

    /// Resolves each proxy hop ahead of time so latency tests can dial the same
    /// first-hop IPs the tunnel expects, without depending on in-tunnel DNS timing.
    private static func resolvedConfiguration(_ configuration: ProxyConfiguration) -> ProxyConfiguration {
        let resolvedChain = configuration.chain?.map(resolvedConfiguration)
        return ProxyConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            resolvedIP: configuration.resolvedIP ?? ProxyDNSCache.shared.resolveHost(configuration.serverAddress, forceFresh: true),
            subscriptionId: configuration.subscriptionId,
            outbound: configuration.outbound,
            chain: resolvedChain
        )
    }

    private static func performTest(_ configuration: ProxyConfiguration) async throws -> Int {
        // Pre-warm DNS cache so resolution is excluded from timing.
        // forceFresh: tests must measure against a fresh address, never a stale one.
        ProxyDNSCache.shared.prewarm(configuration.serverAddress, forceFresh: true)
        if let chain = configuration.chain {
            for proxy in chain {
                ProxyDNSCache.shared.prewarm(proxy.serverAddress, forceFresh: true)
            }
        }

        let client = ProxyClient(configuration: configuration, useResolvedAddressForDirectDial: true)
        let resumer = LatencyTester.PendingResumer()

        do {
            let ms = try await withTaskCancellationHandler {
                // Phases 1 + 2: connect + warmup, priming the proxy-to-target
                // connection so phase 4 measures only the network round-trip.
                let proxyConnection = try await Self.establishWarmedConnection(client: client, resumer: resumer)

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

                return Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
            } onCancel: {
                // Just unblock the pending awaitCallback so the body throws
                // out. `awaitClientCancel(client)` in the catch block then
                // tears the socket down and waits for the fd to actually
                // close — calling `client.cancel()` here too would race with
                // it (state nilled before the awaitable cancel can attach).
                resumer.cancel()
            }
            await awaitClientCancel(client)
            return ms
        } catch {
            await awaitClientCancel(client)
            throw error
        }
    }

    /// Wraps `ProxyClient.cancel(completion:)` as `async`. The continuation
    /// resumes once the underlying file descriptor is fully closed, so the
    /// next test in the `testAll` task group doesn't reuse resources before
    /// they've been released.
    private static func awaitClientCancel(_ client: ProxyClient) async {
        await withCheckedContinuation { continuation in
            client.cancel { continuation.resume() }
        }
    }

    /// Phases 1 + 2: TCP/TLS/outbound handshake plus a warmup HEAD round-trip
    /// to prime the proxy-to-target connection.
    private static func establishWarmedConnection(client: ProxyClient, resumer: PendingResumer) async throws -> ProxyConnection {
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

        return proxyConnection
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
