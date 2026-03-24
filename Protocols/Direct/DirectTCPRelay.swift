//
//  DirectTCPRelay.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "DirectTCP")

class DirectTCPRelay {
    private let transport: NWTransport
    private var cancelled = false

    init() {
        self.transport = NWTransport()
    }

    /// Connects to the destination host:port asynchronously.
    ///
    /// - Parameters:
    ///   - host: Destination hostname or IP address.
    ///   - port: Destination port.
    ///   - queue: Queue for the completion callback (passed to NWTransport for API compat).
    ///   - completion: Called with `nil` on success or an error on failure.
    func connect(host: String, port: UInt16, queue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        transport.connect(host: host, port: port, queue: queue, completion: completion)
    }

    /// Receives up to 64KB from the transport.
    ///
    /// Completion signature matches ProxyConnection's receive pattern:
    /// - `(data, nil)` — data received
    /// - `(nil, nil)` — EOF (remote closed)
    /// - `(nil, error)` — error
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard !cancelled else {
            completion(nil, SocketError.notConnected)
            return
        }
        transport.receive(maximumLength: 65536) { data, isComplete, error in
            if let error {
                completion(nil, error)
            } else if isComplete {
                completion(nil, nil)
            } else {
                completion(data, nil)
            }
        }
    }

    /// Sends data to the destination.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        guard !cancelled else {
            completion(SocketError.notConnected)
            return
        }
        transport.send(data: data, completion: completion)
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        transport.forceCancel()
    }
}
