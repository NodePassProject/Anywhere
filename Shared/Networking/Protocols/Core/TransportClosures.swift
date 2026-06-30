//
//  TransportClosures.swift
//  Anywhere
//
//  Created by NodePassProject on 4/14/26.
//

import Foundation

// MARK: - TransportClosures

struct TransportClosures {
    let send: (Data, @escaping (Error?) -> Void) -> Void
    let receive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    let cancel: () -> Void
}

// MARK: - Transport adapters

extension TransportClosures {
    init(tcp transport: NWTCPTransport) {
        self.init(
            send: { data, completion in
                transport.send(data: data, completion: completion)
            },
            receive: { completion in
                transport.receive(completion: completion)
            },
            cancel: {
                transport.forceCancel()
            }
        )
    }

    /// Widens TLS's two-arg callback (EOF = nil data, nil error) to the three-way signal.
    init(tls tlsConnection: TLSRecordConnection) {
        self.init(
            send: { data, completion in
                tlsConnection.send(data: data, completion: completion)
            },
            receive: { completion in
                tlsConnection.receive { data, error in
                    completion(data, false, error)
                }
            },
            cancel: {
                tlsConnection.cancel()
            }
        )
    }

    /// For XHTTP-over-HTTP/3, which multiplexes over QUIC; these closures are never invoked.
    static var unused: TransportClosures {
        TransportClosures(
            send: { _, completion in completion(nil) },
            receive: { completion in completion(nil, true, nil) },
            cancel: {}
        )
    }

    /// Translates empty/nil data on a non-error receive to EOF to match the three-way signal.
    init(tunnel: ProxyConnection) {
        self.init(
            send: { data, completion in
                tunnel.sendRaw(data: data, completion: completion)
            },
            receive: { completion in
                tunnel.receiveRaw { data, error in
                    if let error {
                        completion(nil, true, error)
                    } else if let data, !data.isEmpty {
                        completion(data, false, nil)
                    } else {
                        completion(nil, true, nil)
                    }
                }
            },
            cancel: {
                tunnel.cancel()
            }
        )
    }
}
