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
        ConnectionMetrics.shared.suspendRecording()
        defer { ConnectionMetrics.shared.resumeRecording() }

        do {
            let latencyMilliseconds = try await withThrowingTaskGroup(of: Int.self) { group in
                group.addTask {
                    let testConfiguration = await Self.resolvedConfiguration(configuration)
                    return try await Self.performTest(testConfiguration)
                }
                group.addTask {
                    try await Task.sleep(for: Self.timeout, precision: .relaxed)
                    throw CancellationError()
                }

                let result = try await group.next()!
                group.cancelAll()
                return result
            }
            return .success(latencyMilliseconds)
        } catch is CancellationError {
            if !Task.isCancelled {
                logger.error("[Latency] \(configuration.name): Timed out")
            }
            return .failed
        } catch {
            logger.report("[Latency] \(configuration.name)", error: error)
            if case AnywhereError.tls(.certificateValidationFailed) = error {
                return .insecure
            }
            return .failed
        }
    }

    // MARK: - Private

    private static func resolvedConfiguration(_ configuration: ProxyConfiguration) async -> ProxyConfiguration {
        guard let chain = configuration.chain, let entry = chain.first else {
            guard !configuration.isDirect else { return configuration }
            return configuration.withResolvedIP(
                await DNSResolver.proxies.resolveHost(configuration.serverAddress, forceFresh: true)
            )
        }
        let resolvedEntry = entry.withResolvedIP(
            await DNSResolver.proxies.resolveHost(entry.serverAddress, forceFresh: true)
        )
        return configuration.withChain([resolvedEntry] + chain.dropFirst())
    }

    private static func performTest(_ configuration: ProxyConfiguration) async throws -> Int {
        let entry = configuration.chain?.first ?? configuration
        if !entry.isDirect {
            _ = await DNSResolver.proxies.resolveAll(entry.serverAddress)
        }

        let client = ProxyClient(configuration: configuration, useResolvedAddressForDirectDial: true)

        do {
            let ms = try await withTaskCancellationHandler {
                let proxyConnection = try await Self.establishWarmedConnection(client: client)
                
                let httpRequest = "HEAD / HTTP/1.1\r\nHost: \(Self.latencyHost)\r\nConnection: close\r\n\r\n".data(using: .utf8)!
                try await proxyConnection.send(httpRequest)
                
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
        let proxyConnection = try await client.connect(to: Self.latencyHost, port: Self.latencyPort)
        
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
