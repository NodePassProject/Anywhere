//
//  LatencyTester.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "LatencyTester")

nonisolated enum LatencyTester {

    private static let timeout: Duration = .seconds(10)

    private static let latencyHost = "captive.apple.com"
    private static let latencyPort: UInt16 = 80
    
    nonisolated static func test(_ configuration: ProxyConfiguration) async -> LatencyResult {
        // Keep probe timings out of the live dial/handshake gauges.
        ConnectionMetrics.shared.suspendRecording()
        defer { ConnectionMetrics.shared.resumeRecording() }

        let testConfiguration = await resolvedConfiguration(configuration)

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
        } catch let error as AnywhereError {
            if case .tls(.certificateValidationFailed) = error {
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
    
    private static func resolvedConfiguration(_ configuration: ProxyConfiguration) async -> ProxyConfiguration {
        var resolvedChain: [ProxyConfiguration]?
        if let chain = configuration.chain {
            var hops: [ProxyConfiguration] = []
            hops.reserveCapacity(chain.count)
            for hop in chain {
                hops.append(await resolvedConfiguration(hop))
            }
            resolvedChain = hops
        }
        return ProxyConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            resolvedIP: await DNSResolver.shared.resolveHost(configuration.serverAddress, forceFresh: true),
            subscriptionId: configuration.subscriptionId,
            outbound: configuration.outbound,
            chain: resolvedChain
        )
    }

    private static func performTest(_ configuration: ProxyConfiguration) async throws -> Int {
        await DNSResolver.shared.prewarm(configuration.serverAddress)
        if let chain = configuration.chain {
            for proxy in chain {
                await DNSResolver.shared.prewarm(proxy.serverAddress)
            }
        }

        let client = ProxyClient(configuration: configuration, useResolvedAddressForDirectDial: true)

        do {
            let ms = try await withTaskCancellationHandler {
                let proxyConnection = try await Self.establishWarmedConnection(client: client)

                // Phase 3 (untimed): send the request.
                let httpRequest = "HEAD / HTTP/1.1\r\nHost: \(Self.latencyHost)\r\nConnection: close\r\n\r\n".data(using: .utf8)!
                try await proxyConnection.send(httpRequest)

                // Phase 4 (timed): timer starts after the send completes.
                let clock = ContinuousClock()
                let start = clock.now

                let responseData = try await proxyConnection.receive()

                let elapsed = clock.now - start

                let statusLine = responseData.flatMap { String(data: $0, encoding: .utf8) }?
                    .split(separator: "\r\n", maxSplits: 1).first.map(String.init)
                guard let statusLine, statusLine.contains("200") else {
                    throw AnywhereError.diagnostics(.latencyProbeFailed(status: statusLine ?? "no response"))
                }

                return Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
            } onCancel: {
                client.cancel()
            }
            await client.cancel()
            return ms
        } catch {
            await client.cancel()
            throw error
        }
    }
    
    private static func establishWarmedConnection(client: ProxyClient) async throws -> ProxyConnection {
        // Phase 1 (untimed): TCP/TLS/outbound handshake.
        let proxyConnection = try await client.connect(to: Self.latencyHost, port: Self.latencyPort)

        // Phase 2 (untimed): warmup request primes the proxy-to-target connection.
        let warmupRequest = "HEAD / HTTP/1.1\r\nHost: \(Self.latencyHost)\r\n\r\n".data(using: .utf8)!
        try await proxyConnection.send(warmupRequest)

        let warmupData = try await proxyConnection.receive()

        let warmupStatus = warmupData.flatMap { String(data: $0, encoding: .utf8) }?
            .split(separator: "\r\n", maxSplits: 1).first.map(String.init)
        guard let warmupStatus, warmupStatus.contains("200") else {
            throw AnywhereError.diagnostics(.latencyProbeFailed(status: warmupStatus ?? "no response"))
        }

        return proxyConnection
    }
}
