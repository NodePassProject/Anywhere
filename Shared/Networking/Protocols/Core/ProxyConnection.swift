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
    nonisolated func closeWrite(completion: @escaping (Error?) -> Void)
    func receive(completion: @escaping (Data?, Error?) -> Void)
    func startReceiving(handler: @escaping (Data) -> Void, errorHandler: @escaping (Error?) -> Void)
    func cancel()
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

    // MARK: Async Surface

    // An async-native surface over the same primitives. The defaults bridge to the
    // callback methods, so every decorator gains a working async surface for free; a
    // decorator can override the async raw methods to run natively over an async
    // transport, deleting a bridge hop. Task cancellation surfaces as the underlying
    // callback firing with an error (transports complete pending work on cancel).

    /// Sends `data`, tracking traffic stats. Async analogue of `send(data:completion:)`.
    func send(_ data: Data) async throws {
        _bytesSent.wrappingAdd(Int64(data.count), ordering: .relaxed)
        try await sendRaw(data)
    }

    /// Receives once; `nil` signals EOF. Async analogue of `receive(completion:)`.
    func receive() async throws -> Data? {
        let data = try await receiveRaw()
        if let data, !data.isEmpty {
            _bytesReceived.wrappingAdd(Int64(data.count), ordering: .relaxed)
        }
        return data
    }

    /// Async raw send. Defaults to bridging `sendRaw(data:completion:)`.
    func sendRaw(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            sendRaw(data: data) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    /// Async raw receive; `nil` (or empty) == EOF. Defaults to bridging `receiveRaw(completion:)`.
    func receiveRaw() async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            receiveRaw { data, error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume(returning: data) }
            }
        }
    }

    /// Bypasses transport encryption; used for Vision direct copy mode. Async analogue.
    func sendDirectRaw(_ data: Data) async throws {
        try await sendRaw(data)
    }

    /// Bypasses transport decryption; used for Vision direct copy mode. Async analogue.
    func receiveDirectRaw() async throws -> Data? {
        try await receiveRaw()
    }

    /// Async half-close. Defaults to bridging `closeWrite(completion:)`.
    func closeWrite() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            closeWrite { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    // MARK: Half-Close

    /// Finishes the send direction — the streaming analogue of `shutdown(SHUT_WR)`:
    /// signals end-of-stream to the remote while receive stays open. Ordered after
    /// every issued send; called at most once, with no sends afterwards; `completion`
    /// fires exactly once, on an arbitrary queue. The default completes immediately
    /// for protocols that can't express end-of-stream short of a full close.
    func closeWrite(completion: @escaping (Error?) -> Void) {
        completion(nil)
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

            if let data, !data.isEmpty || self.deliversDatagrams {
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
