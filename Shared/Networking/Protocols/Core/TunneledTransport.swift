//
//  TunneledTransport.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

/// Adapts a ``ProxyConnection`` to ``RawTransport`` for proxy chaining: one link's output becomes the next link's socket.
/// Sends/receives bypass the tunnel's traffic stats (each link tracks its own).
nonisolated class TunneledTransport: RawTransport {
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

    func receive(completion: @escaping (Data?, Bool, Error?) -> Void) {
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
