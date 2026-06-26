//
//  LatencyTester.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "LatencyTester")

private enum LatencyTestError: Error, LocalizedError {
    case unexpectedStatus(String)

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status): return "Unexpected status: \(status)"
        }
    }
}

nonisolated enum LatencyTester {

    private static let timeout: Duration = .seconds(10)

    private static let latencyHost = "captive.apple.com"
    private static let latencyPort: UInt16 = 80

    /// Only the receive is timed, so the result is the network RTT through the
    /// full proxy chain; DNS is excluded via pre-warming.
    nonisolated static func test(_ configuration: ProxyConfiguration) async -> LatencyResult {
        // Keep probe timings out of the live dial/handshake gauges.
        ConnectionMetrics.shared.suspendRecording()
        defer { ConnectionMetrics.shared.resumeRecording() }

        let testConfiguration = resolvedConfiguration(configuration)

        do {
            let latencyMilliseconds = try await withThrowingTaskGroup(of: Int.self) { group in
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
            return .success(latencyMilliseconds)
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

    /// Re-resolves each hop with NE-process `getaddrinfo` and discards any
    /// main-app `resolvedIP`: while the tunnel is up, main-app DNS returns lwIP
    /// fake IPs (198.18.0.0/15) unroutable from the NE's kernel-bypassed sockets.
    private static func resolvedConfiguration(_ configuration: ProxyConfiguration) -> ProxyConfiguration {
        let resolvedChain = configuration.chain?.map(resolvedConfiguration)
        return ProxyConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            resolvedIP: DNSResolver.shared.resolveHost(configuration.serverAddress, forceFresh: true),
            subscriptionId: configuration.subscriptionId,
            outbound: configuration.outbound,
            chain: resolvedChain
        )
    }

    private static func performTest(_ configuration: ProxyConfiguration) async throws -> Int {
        // forceFresh: tests must measure against a fresh address, never a stale one.
        DNSResolver.shared.prewarm(configuration.serverAddress, forceFresh: true)
        if let chain = configuration.chain {
            for proxy in chain {
                DNSResolver.shared.prewarm(proxy.serverAddress, forceFresh: true)
            }
        }

        let client = ProxyClient(configuration: configuration, useResolvedAddressForDirectDial: true)
        let resumer = LatencyTester.PendingResumer()

        do {
            let ms = try await withTaskCancellationHandler {
                let proxyConnection = try await Self.establishWarmedConnection(client: client, resumer: resumer)

                // Phase 3 (untimed): send the request.
                let httpRequest = "HEAD / HTTP/1.1\r\nHost: \(Self.latencyHost)\r\nConnection: close\r\n\r\n".data(using: .utf8)!

                try await awaitCallback(resumer: resumer) { (complete: @escaping (Result<Void, Error>) -> Void) in
                    proxyConnection.send(data: httpRequest) { error in
                        if let error { complete(.failure(error)) } else { complete(.success(())) }
                    }
                }

                // Phase 4 (timed): timer starts after the send completes.
                let clock = ContinuousClock()
                let start = clock.now

                let responseData: Data? = try await awaitCallback(resumer: resumer) { (complete: @escaping (Result<Data?, Error>) -> Void) in
                    proxyConnection.receive { data, error in
                        if let error { complete(.failure(error)) } else { complete(.success(data)) }
                    }
                }

                let elapsed = clock.now - start

                let statusLine = responseData.flatMap { String(data: $0, encoding: .utf8) }?
                    .split(separator: "\r\n", maxSplits: 1).first.map(String.init)
                guard let statusLine, statusLine.contains("200") else {
                    throw LatencyTestError.unexpectedStatus(statusLine ?? "no response")
                }

                return Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
            } onCancel: {
                // Unblock the awaiting callback. Do NOT call client.cancel()
                // here — it races with awaitClientCancel.
                resumer.cancel()
            }
            await awaitClientCancel(client)
            return ms
        } catch {
            await awaitClientCancel(client)
            throw error
        }
    }

    /// Waits until the underlying fd is fully closed before the next test runs.
    private static func awaitClientCancel(_ client: ProxyClient) async {
        await withCheckedContinuation { continuation in
            client.cancel { continuation.resume() }
        }
    }

    /// Phases 1 + 2 (untimed): proxy handshake plus a warmup HEAD round-trip.
    private static func establishWarmedConnection(client: ProxyClient, resumer: PendingResumer) async throws -> ProxyConnection {
        // Phase 1 (untimed): TCP/TLS/outbound handshake.
        let proxyConnection: ProxyConnection = try await awaitCallback(resumer: resumer) { complete in
            client.connect(to: Self.latencyHost, port: Self.latencyPort) { complete($0) }
        }

        // Phase 2 (untimed): warmup request primes the proxy-to-target connection.
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

        let warmupStatus = warmupData.flatMap { String(data: $0, encoding: .utf8) }?
            .split(separator: "\r\n", maxSplits: 1).first.map(String.init)
        guard let warmupStatus, warmupStatus.contains("200") else {
            throw LatencyTestError.unexpectedStatus(warmupStatus ?? "no response")
        }

        return proxyConnection
    }

    /// Cancellation hook that fails whichever phase is currently awaiting.
    private final class PendingResumer: @unchecked Sendable {
        private let lock = UnfairLock()
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
            let capturedHook = hook
            hook = nil
            lock.unlock()
            capturedHook?(CancellationError())
        }
    }

    /// One-shot continuation wrapper; the second resume is a no-op, so a cancel
    /// during a hung send/receive can't double-resume or leak the continuation.
    private final class OneShotResumer<T>: @unchecked Sendable {
        private let lock = UnfairLock()
        private var continuation: CheckedContinuation<T, Error>?

        func arm(_ continuation: CheckedContinuation<T, Error>) {
            lock.lock(); defer { lock.unlock() }
            self.continuation = continuation
        }

        func resume(_ result: Result<T, Error>) {
            lock.lock()
            let snapshotContinuation = continuation
            continuation = nil
            lock.unlock()
            snapshotContinuation?.resume(with: result)
        }
    }

    /// Bridges a callback to async/await; the continuation resumes exactly
    /// once, from either the callback or the cancellation hook.
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
