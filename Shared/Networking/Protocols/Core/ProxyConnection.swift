//
//  ProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation

// MARK: - ProxyConnectionProtocol

protocol ProxyConnectionProtocol: AnyObject {
    var isConnected: Bool { get }

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(completion: @escaping (Data?, Error?) -> Void)
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void)
    func cancel()
}

// MARK: - ProxyConnection

/// Abstract base class for proxy connections.
nonisolated class ProxyConnection: ProxyConnectionProtocol {
    /// Generic per-connection lock for subclass state; no base-class invariant depends on it.
    let lock = UnfairLock()

    /// The negotiated TLS version of the outer transport; `nil` for non-TLS transports.
    var outerTLSVersion: TLSVersion? { nil }

    /// Whether each `send`/`receive` call preserves one UDP datagram boundary.
    var deliversDatagrams: Bool { false }

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
        let span = PerformanceMonitor.span(.proxySend)
        sendRaw(data: data) { error in
            span.stop()
            completion(error)
        }
    }

    func send(data: Data) {
        statsLock.withLock { _bytesSent &+= Int64(data.count) }
        sendRaw(data: data)
    }

    func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        fatalError("Subclass must override sendRaw")
    }

    func sendRaw(data: Data) {
        fatalError("Subclass must override sendRaw")
    }

    // MARK: Receive

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        let span = PerformanceMonitor.span(.proxyReceive)
        receiveRaw { [weak self] data, error in
            span.stop()
            if let self, let data, !data.isEmpty {
                self.statsLock.withLock { self._bytesReceived &+= Int64(data.count) }
            }
            completion(data, error)
        }
    }

    func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        fatalError("Subclass must override receiveRaw")
    }

    /// Bypasses transport decryption; used for Vision direct copy mode.
    func receiveDirectRaw(completion: @escaping (Data?, Error?) -> Void) {
        receiveRaw(completion: completion)
    }

    /// Bypasses transport encryption; used for Vision direct copy mode.
    func sendDirectRaw(data: Data, completion: @escaping (Error?) -> Void) {
        sendRaw(data: data, completion: completion)
    }

    func sendDirectRaw(data: Data) {
        sendRaw(data: data)
    }

    // MARK: Receive Loop

    /// Starts a continuous receive loop. `errorHandler` receives `nil` on a clean close.
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void) {
        receiveLoop(handler: handler, errorHandler: errorHandler)
    }

    private func receiveLoop(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void) {
        receive { [weak self] data, error in
            // Surface EOF on dealloc so the errorHandler-on-close contract holds.
            guard let self else {
                errorHandler(nil)
                return
            }

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
