//
//  ProxyConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 1/26/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Proxy")

// MARK: - ProxyConnectionProtocol

/// Defines the interface for all proxy connection types.
protocol ProxyConnectionProtocol: AnyObject {
    var isConnected: Bool { get }

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(completion: @escaping (Data?, Error?) -> Void)
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void)
    func cancel()
}

// MARK: - ProxyConnection

/// TLS version constants matching TLS protocol version numbers.
enum TLSVersion: UInt16, Codable {
    case tls10 = 0x0301
    case tls11 = 0x0302
    case tls12 = 0x0303
    case tls13 = 0x0304
}

/// Abstract base class providing common proxy connection functionality.
///
/// Subclasses must override ``isConnected``, ``sendRaw(data:completion:)``,
/// ``sendRaw(data:)``, ``receiveRaw(completion:)``, and ``cancel()``.
class ProxyConnection: ProxyConnectionProtocol {
    /// Generic per-connection lock. Used by several subclasses for
    /// protocol-specific state (Vision traffic state, SS session keys, HTTP
    /// upgrade framing, …); no base-class invariant depends on it.
    let lock = UnfairLock()

    /// The negotiated TLS version of the outer transport, if applicable.
    /// Returns `nil` for non-TLS transports (raw TCP).
    /// Subclasses should override to report their actual TLS version.
    var outerTLSVersion: TLSVersion? { nil }

    // MARK: Traffic Statistics

    private var _bytesSent: Int64 = 0
    private var _bytesReceived: Int64 = 0
    private let statsLock = UnfairLock()

    var bytesSent: Int64 { statsLock.withLock { _bytesSent } }
    var bytesReceived: Int64 { statsLock.withLock { _bytesReceived } }

    var isConnected: Bool {
        fatalError("Subclass must override isConnected")
    }

    // MARK: Send

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        statsLock.withLock { _bytesSent &+= Int64(data.count) }
        sendRaw(data: data, completion: completion)
    }

    func send(data: Data) {
        statsLock.withLock { _bytesSent &+= Int64(data.count) }
        sendRaw(data: data)
    }

    /// Sends raw data over the underlying transport. Must be overridden by subclasses.
    func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        fatalError("Subclass must override sendRaw")
    }

    /// Sends raw data over the underlying transport without tracking completion.
    func sendRaw(data: Data) {
        fatalError("Subclass must override sendRaw")
    }

    // MARK: Receive

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw { [weak self] data, error in
            if let self, let data, !data.isEmpty {
                self.statsLock.withLock { self._bytesReceived &+= Int64(data.count) }
            }
            completion(data, error)
        }
    }

    /// Receives raw data from the underlying transport. Must be overridden by subclasses.
    func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        fatalError("Subclass must override receiveRaw")
    }

    /// Receives raw data without transport decryption (for Vision direct copy mode).
    ///
    /// The default implementation delegates to ``receiveRaw(completion:)``.
    /// Subclasses can override for special handling.
    func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw(completion: completion)
    }

    /// Sends raw data without transport encryption (for Vision direct copy mode).
    ///
    /// The default implementation delegates to ``sendRaw(data:completion:)``.
    /// Subclasses can override for special handling.
    func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: data, completion: completion)
    }

    func sendDirectRaw(data: Data) {
        sendRaw(data: data)
    }

    // MARK: Receive Loop

    /// Starts a continuous receive loop, delivering data through `handler`.
    ///
    /// - Parameters:
    ///   - handler: Called with each chunk of received data.
    ///   - errorHandler: Called when an error occurs or the connection closes (`nil` error = clean close).
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void) {
        receiveLoop(handler: handler, errorHandler: errorHandler)
    }

    private func receiveLoop(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void) {
        receive { [weak self] data, error in
            guard let self else { return }

            if let error {
                errorHandler(error)
                return
            }

            if let data, !data.isEmpty {
                // Start next receive before processing to enable pipelining
                self.receiveLoop(handler: handler, errorHandler: errorHandler)
                handler(data)
            } else {
                errorHandler(nil)
            }
        }
    }

    // MARK: Cancel

    func cancel() {
        fatalError("Subclass must override cancel")
    }
}

