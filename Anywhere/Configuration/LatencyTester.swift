//
//  LatencyTester.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere", category: "LatencyTester")

enum LatencyResult: Sendable {
    case testing
    case success(Int)  // milliseconds
    case failed
}

/// Tests full proxy round-trip latency by establishing a VLESS connection
/// and sending an HTTP request through the proxy chain.
nonisolated enum LatencyTester {

    /// Per-test timeout.
    private static let timeout: Duration = .seconds(10)

    /// Test a single configuration's proxy round-trip latency.
    ///
    /// Measures only the HTTP request/response time through the VLESS chain,
    /// excluding DNS resolution and connection setup overhead.
    nonisolated static func test(_ configuration: VLESSConfiguration) async -> LatencyResult {
        // Resolve DNS outside the tunnel
        let resolvedIP = await Task.detached {
            VPNViewModel.resolveServerAddress(configuration.serverAddress)
        }.value

        // Create configuration with resolved IP
        let testConfiguration = await VLESSConfiguration(
            id: configuration.id,
            name: configuration.name,
            serverAddress: configuration.serverAddress,
            serverPort: configuration.serverPort,
            uuid: configuration.uuid,
            encryption: configuration.encryption,
            transport: configuration.transport,
            flow: configuration.flow,
            security: configuration.security,
            tls: configuration.tls,
            reality: configuration.reality,
            websocket: configuration.websocket,
            httpUpgrade: configuration.httpUpgrade,
            xhttp: configuration.xhttp,
            testseed: configuration.testseed,
            muxEnabled: configuration.muxEnabled,
            xudpEnabled: configuration.xudpEnabled,
            resolvedIP: resolvedIP,
            subscriptionId: configuration.subscriptionId
        )

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
        } catch {
            logger.debug("Latency test failed for \(configuration.name): \(error.localizedDescription)")
            return .failed
        }
    }

    /// Test multiple configurations sequentially, emitting results one at a time.
    nonisolated static func testAll(_ configurations: [VLESSConfiguration]) -> AsyncStream<(UUID, LatencyResult)> {
        AsyncStream { continuation in
            let task = Task {
                for configuration in configurations {
                    guard !Task.isCancelled else { break }
                    let result = await Self.test(configuration)
                    continuation.yield((configuration.id, result))
                }
                continuation.finish()
            }

            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }

    // MARK: - Private

    private static func performTest(_ configuration: VLESSConfiguration) async throws -> Int {
        let client = VLESSClient(configuration: configuration)

        defer { client.cancel() }

        // Phase 1: Establish VLESS connection (TCP + TLS/Reality + VLESS handshake).
        // This is NOT timed
        let vlessConnection: VLESSConnection = try await withCheckedThrowingContinuation { continuation in
            client.connect(to: "www.gstatic.com", port: 80) { result in
                continuation.resume(with: result)
            }
        }

        // Phase 2: Send HTTP request and measure round-trip through the proxy.
        // Timer starts here — only the request/response through the established
        let httpRequest = "HEAD /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n".data(using: .utf8)!
        let clock = ContinuousClock()
        let requestStart = clock.now

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            vlessConnection.send(data: httpRequest) { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }

        // Wait for any response data
        let _: Data? = try await withCheckedThrowingContinuation { continuation in
            vlessConnection.receive { data, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: data)
                }
            }
        }

        let elapsed = clock.now - requestStart
        let ms = Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
        return ms
    }
}
