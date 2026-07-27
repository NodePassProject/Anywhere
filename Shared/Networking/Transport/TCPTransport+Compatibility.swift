//
//  TCPTransport+Compatibility.swift
//  Anywhere
//
//  Created by NodePassProject on 7/27/26.
//

import Foundation
import Network

nonisolated final class LegacyTCPEngine: TCPTransportEngine, Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.TCPTransport", qos: .userInitiated)

    init(endpoint: NWEndpoint, connectTimeout: UInt32) {
        let tcpOptions = NWProtocolTCP.Options()
        tcpOptions.noDelay = true
        tcpOptions.enableKeepalive = true
        tcpOptions.keepaliveIdle = 30
        tcpOptions.keepaliveCount = 3
        tcpOptions.keepaliveInterval = 10
        tcpOptions.connectionTimeout = Int(connectTimeout)
        connection = NWConnection(to: endpoint, using: NWParameters(tls: nil, tcp: tcpOptions))
        connection.start(queue: queue)
    }

    deinit {
        connection.cancel()
    }

    func send(_ data: Data) async throws {
        let connection = connection
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error {
                        continuation.resume(throwing: error.legacyEngineError(operation: .send))
                    } else {
                        continuation.resume()
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func receive(atMost maxLength: Int) async throws -> (content: Data, endOfStream: Bool) {
        let connection = connection
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<(content: Data, endOfStream: Bool), any Error>) in
                connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) { content, context, isComplete, error in
                    if let error {
                        continuation.resume(throwing: error.legacyEngineError(operation: .receive))
                        return
                    }
                    let endOfStream = isComplete && (context == nil || context?.isFinal == true)
                    continuation.resume(returning: (content ?? Data(), endOfStream))
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }
}
