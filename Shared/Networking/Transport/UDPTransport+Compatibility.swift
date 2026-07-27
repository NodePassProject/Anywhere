//
//  UDPTransport+Compatibility.swift
//  Anywhere
//
//  Created by NodePassProject on 7/27/26.
//

import Foundation
import Network

nonisolated final class LegacyUDPEngine: UDPTransportEngine, Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.argsment.Anywhere.UDPTransport", qos: .userInitiated)

    init(endpoint: NWEndpoint) {
        connection = NWConnection(to: endpoint, using: .udp)
        connection.start(queue: queue)
    }

    deinit {
        connection.cancel()
    }

    func send(_ datagram: Data) async throws {
        let connection = connection
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                connection.send(content: datagram, completion: .contentProcessed { error in
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

    func receive() async throws -> Data {
        let connection = connection
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, any Error>) in
                connection.receiveMessage { content, _, _, error in
                    if let error {
                        continuation.resume(throwing: error.legacyEngineError(operation: .receive))
                    } else {
                        continuation.resume(returning: content ?? Data())
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }
}
