//
//  ProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 1/26/26.
//

import Foundation
import Synchronization

// MARK: - ProxyConnectionProtocol

protocol ProxyConnectionProtocol: AnyObject {
    var isConnected: Bool { get }

    func send(data: Data, completion: @escaping (Error?) -> Void)
    func send(data: Data)
    func receive(completion: @escaping (Data?, Error?) -> Void)
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void)
    func cancel()
}

/// Optional directional close used by transports that can finish the uplink
/// while keeping the downlink readable.
protocol ProxyConnectionWriteClosable: AnyObject {
    func closeWrite(completion: @escaping (Error?) -> Void)
}

// MARK: - ProxyConnection

nonisolated class ProxyConnection: ProxyConnectionProtocol {
    /// Generic per-connection lock for subclass state; no base-class invariant depends on it.
    let lock = UnfairLock()

    /// The negotiated TLS version of the outer transport; `nil` for non-TLS transports.
    var outerTLSVersion: TLSVersion? { nil }

    /// Whether each `send`/`receive` call preserves one UDP datagram boundary.
    var deliversDatagrams: Bool { false }

    // MARK: Traffic Statistics

    private let _bytesSent = Atomic<Int64>(0)
    private let _bytesReceived = Atomic<Int64>(0)

    var bytesSent: Int64 { _bytesSent.load(ordering: .relaxed) }
    var bytesReceived: Int64 { _bytesReceived.load(ordering: .relaxed) }

    var isConnected: Bool {
        fatalError("Subclass must override isConnected")
    }

    // MARK: Send

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        _bytesSent.wrappingAdd(Int64(data.count), ordering: .relaxed)
        sendRaw(data: data) { error in
            completion(error)
        }
    }

    func send(data: Data) {
        _bytesSent.wrappingAdd(Int64(data.count), ordering: .relaxed)
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
        receiveRaw { [weak self] data, error in
            if let self, let data, !data.isEmpty {
                self._bytesReceived.wrappingAdd(Int64(data.count), ordering: .relaxed)
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

    /// Abortive teardown for error paths. Defaults to `cancel()`; subclasses
    /// owning a raw socket override to close with RST.
    func abort() {
        cancel()
    }
}
