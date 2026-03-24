//
//  DirectUDPRelay.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Network
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "DirectUDP")

class DirectUDPRelay {
    private var connection: NWConnection?
    private var cancelled = false

    init() {}

    /// Creates a UDP connection to the destination.
    ///
    /// The completion is called on `lwipQueue` with nil on success or an error on failure.
    func connect(dstHost: String, dstPort: UInt16, lwipQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        let host = NWEndpoint.Host(dstHost)
        guard let port = NWEndpoint.Port(rawValue: dstPort) else {
            lwipQueue.async { completion(SocketError.connectionFailed("Invalid port")) }
            return
        }

        let connection = NWConnection(host: host, port: port, using: .udp)
        self.connection = connection

        var completed = false
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, !self.cancelled, !completed else { return }
            switch state {
            case .ready:
                completed = true
                connection.stateUpdateHandler = nil
                lwipQueue.async { completion(nil) }
            case .failed(let error):
                completed = true
                connection.stateUpdateHandler = nil
                self.connection = nil
                lwipQueue.async { completion(SocketError.connectionFailed(error.localizedDescription)) }
            default:
                break
            }
        }

        connection.start(queue: .global())
    }

    /// Sends a UDP datagram to the connected destination.
    func send(data: Data) {
        guard let connection, !cancelled else { return }
        connection.send(content: data, completion: .contentProcessed({ _ in }))
    }

    /// Starts receiving datagrams asynchronously.
    /// The handler is called on the connection's internal queue;
    /// callers should dispatch to lwipQueue.
    func startReceiving(handler: @escaping (Data) -> Void) {
        guard let connection, !cancelled else { return }
        receiveNext(connection: connection, handler: handler)
    }

    private func receiveNext(connection: NWConnection, handler: @escaping (Data) -> Void) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, !self.cancelled else { return }
            if let data, !data.isEmpty {
                handler(data)
            }
            // UDP doesn't have EOF, continue receiving
            if error == nil {
                self.receiveNext(connection: connection, handler: handler)
            }
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        connection?.forceCancel()
        connection = nil
    }
}
