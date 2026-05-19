//
//  QUICDatagramTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Datagram transport `QUICConnection` can ride in place of a kernel socket.
/// `sendDatagram` is fire-and-forget; `startReceiving` MUST deliver exactly
/// one whole datagram per `handler` call (empty datagrams forbidden — use
/// `errorHandler` to express EOF). Callbacks may fire on any queue.
protocol QUICDatagramTransport: AnyObject {
    func sendDatagram(_ data: Data)

    /// `errorHandler` fires on terminal failure; do not `sendDatagram` after.
    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void)

    /// Tears down the transport. Idempotent.
    func cancel()
}

/// Adapts a `ProxyConnection` (e.g. from a chain's UDP-relay last hop) to
/// `QUICDatagramTransport`. The wrapped connection has already encoded its
/// destination, so each datagram is opaque payload to/from one fixed peer.
final class ProxyConnectionDatagramTransport: QUICDatagramTransport {
    private let connection: ProxyConnection

    init(connection: ProxyConnection) {
        self.connection = connection
    }

    func sendDatagram(_ data: Data) {
        connection.send(data: data) { _ in }
    }

    func startReceiving(handler: @escaping (Data) -> Void,
                        errorHandler: @escaping (Error?) -> Void) {
        connection.startReceiving(handler: handler, errorHandler: errorHandler)
    }

    func cancel() {
        connection.cancel()
    }
}
