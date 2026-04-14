//
//  DirectUDPRelay.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "DirectUDP")

class DirectUDPRelay {
    private let socket = RawUDPSocket()
    private var cancelled = false

    init() {}

    /// Creates a UDP connection to the destination.
    ///
    /// The completion is called on `lwipQueue` with nil on success or an error on failure.
    func connect(dstHost: String, dstPort: UInt16, lwipQueue: DispatchQueue,
                 completion: @escaping (Error?) -> Void) {
        socket.connect(host: dstHost, port: dstPort,
                       completionQueue: lwipQueue) { [weak self] error in
            if let self, self.cancelled { return }
            completion(error)
        }
    }

    /// Sends a UDP datagram to the connected destination.
    func send(data: Data) {
        guard !cancelled else { return }
        socket.send(data: data)
    }

    /// Starts receiving datagrams asynchronously.
    /// The handler is called on the socket's internal queue;
    /// callers should dispatch to lwipQueue.
    func startReceiving(handler: @escaping (Data) -> Void) {
        guard !cancelled else { return }
        socket.startReceiving { [weak self] data in
            guard let self, !self.cancelled else { return }
            handler(data)
        }
    }

    func cancel() {
        guard !cancelled else { return }
        cancelled = true
        socket.cancel()
    }
}
