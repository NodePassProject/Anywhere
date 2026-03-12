//
//  TunneledTransport.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation

/// Adapts a ``ProxyConnection`` (from a previous chain link) to the ``RawTransport`` interface.
///
/// Used for proxy chaining: the output of one proxy connection becomes the "socket" for the next.
/// Sends and receives bypass the tunnel's traffic statistics (each chain link tracks its own stats).
class TunneledTransport: RawTransport {
    private let tunnel: ProxyConnection

    init(tunnel: ProxyConnection) {
        self.tunnel = tunnel
    }

    var isTransportReady: Bool { tunnel.isConnected }

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        tunnel.sendRaw(data: data, completion: completion)
    }

    func send(data: Data) {
        tunnel.sendRaw(data: data)
    }

    func receive(maximumLength: Int, completion: @escaping (Data?, Bool, Error?) -> Void) {
        tunnel.receiveRaw { data, error in
            if let error {
                completion(nil, true, error)
            } else if let data, !data.isEmpty {
                completion(data, false, nil)
            } else {
                completion(nil, true, nil) // EOF
            }
        }
    }

    func forceCancel() {
        tunnel.cancel()
    }
}
