//
//  TransportClosures.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/14/26.
//

import Foundation

// MARK: - TransportClosures

/// Closure-based transport adapter used by ``WebSocketConnection``,
/// ``HTTPUpgradeConnection``, and ``XHTTPConnection``.
///
/// These protocols ride on top of different underlying transports — a plain
/// TCP socket, a TLS record connection, or a tunneled proxy chain — each of
/// which exposes a slightly different `send`/`receive`/`cancel` API.
/// Wrapping the transport in a fixed closure triple lets the higher-level
/// protocol stay transport-agnostic without introducing a protocol witness
/// table or forcing every transport to conform to a shared interface.
///
/// Construct with one of the `init(rawTCP:)` / `init(tls:)` / `init(tunnel:)`
/// factories; the raw memberwise init remains available for call sites that
/// need to synthesize closures (e.g. upload transports built at dial time).
struct TransportClosures {
    let send: (Data, @escaping (Error?) -> Void) -> Void
    let receive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    let cancel: () -> Void
}

// MARK: - Transport adapters

extension TransportClosures {
    /// Default receive chunk size. Matches the largest typical TCP segment
    /// aggregation we want from a single `recv(2)` wake-up.
    private static let defaultReceiveChunk = 65536

    /// Adapts a ``RawTCPSocket`` to the closure triple.
    init(rawTCP transport: RawTCPSocket) {
        self.init(
            send: { data, completion in
                transport.send(data: data, completion: completion)
            },
            receive: { completion in
                transport.receive(maximumLength: Self.defaultReceiveChunk, completion: completion)
            },
            cancel: {
                transport.forceCancel()
            }
        )
    }

    /// Adapts a ``TLSRecordConnection`` to the closure triple. The TLS
    /// receive callback signature `(Data?, Error?)` is widened to include
    /// the EOF bit; TLS surfaces EOF as `error == nil && data == nil`, which
    /// the caller handles via its own framing layer.
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

    /// Adapts a tunneled ``ProxyConnection`` (for proxy chaining) to the
    /// closure triple. Empty / nil data on a non-error receive is translated
    /// to EOF so the caller sees the same three-way signal as the direct
    /// transports.
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
