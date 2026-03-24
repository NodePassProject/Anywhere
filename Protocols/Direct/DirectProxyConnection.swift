//
//  DirectProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

/// Proxy connection over a direct transport (``NWTransport`` or ``TunneledTransport``).
class DirectProxyConnection: ProxyConnection {
    let connection: any RawTransport

    /// Creates a new direct proxy connection.
    ///
    /// - Parameter connection: The underlying transport.
    init(connection: any RawTransport) {
        self.connection = connection
    }

    override var isConnected: Bool {
        connection.isTransportReady
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        connection.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        connection.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        connection.receive(maximumLength: 65536) { [weak self] data, isComplete, error in
            guard let self else {
                completion(nil, nil)
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                if isComplete {
                    completion(nil, nil)
                } else {
                    self.receive(completion: completion)
                }
                return
            }

            self.processResponseHeader(data: data, completion: completion)
        }
    }

    override func cancel() {
        connection.forceCancel()
    }
}
