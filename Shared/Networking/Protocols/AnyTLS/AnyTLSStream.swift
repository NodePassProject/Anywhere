//
//  AnyTLSStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSStream")

nonisolated final class AnyTLSStream: AsyncProxyConnection, MultiplexerStreamSink {

    let sid: UInt32
    private weak var multiplexer: AnyTLSMultiplexer?

    /// Captured at construction so `outerTLSVersion` keeps working after the multiplexer goes away.
    private let cachedTLSVersion: TLSVersion?

    private struct ReceiveState {
        var pendingReceive: ((Data?, Error?) -> Void)?
        var incoming: [Data] = []
        var receiveError: Error?
        var eof: Bool = false
        /// Set by `cancel()` so the multiplexer does not echo a FIN back to itself.
        var locallyCancelled: Bool = false
    }

    private let receiveState = Mutex(ReceiveState())

    /// Set by `cancel()` so the multiplexer does not echo a FIN back to itself.
    var locallyCancelled: Bool {
        receiveState.withLock { $0.locallyCancelled }
    }

    init(sid: UInt32, multiplexer: AnyTLSMultiplexer, outerTLSVersion: TLSVersion?) {
        self.sid = sid
        self.multiplexer = multiplexer
        self.cachedTLSVersion = outerTLSVersion
        super.init()
    }

    override var isConnected: Bool {
        receiveState.withLock { !$0.eof && $0.receiveError == nil } && (multiplexer?.isAlive ?? false)
    }

    override var outerTLSVersion: TLSVersion? { cachedTLSVersion }

    // MARK: - Async Surface

    // Bridges the callback multiplexer sink below for the flipped class; deleted with it later.

    override func sendRaw(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            sendRaw(data: data) { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
        }
    }

    override func receiveRaw() async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            receiveRaw { data, error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume(returning: data) }
            }
        }
    }

    // MARK: - Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard let multiplexer else {
            completion(ProxyError.connectionFailed("AnyTLS multiplexer deallocated"))
            return
        }
        multiplexer.writeData(sid: sid, data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        multiplexer?.writeData(sid: sid, data: data, completion: { _ in })
    }

    // MARK: - Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        enum Action {
            case fail(Error)
            case deliver(Data)
            case eof
            case parked
        }
        let action: Action = receiveState.withLock { state in
            if let error = state.receiveError {
                return .fail(error)
            }
            if !state.incoming.isEmpty {
                return .deliver(state.incoming.removeFirst())
            }
            if state.eof {
                return .eof
            }
            // Stash the callback; the recv loop delivers bytes or EOF/error later.
            state.pendingReceive = completion
            return .parked
        }
        switch action {
        case .fail(let error):
            completion(nil, error)
        case .deliver(let chunk):
            completion(chunk, nil)
        case .eof:
            completion(nil, nil)
        case .parked:
            break
        }
    }

    // MARK: - Cancel

    override func performCancel() {
        let already = receiveState.withLock { state -> Bool in
            let already = state.locallyCancelled
            state.locallyCancelled = true
            return already
        }
        guard !already else { return }
        logger.debug("[AnyTLSStream] cancel sid=\(sid)")
        multiplexer?.removeStream(sid: sid)
        fireOnEndOnce()
    }

    // MARK: - Called by AnyTLSMultiplexer on the recv loop

    /// Delivers a payload chunk from a cmdPSH frame addressed to this stream.
    func deliverData(_ data: Data) {
        let callback: ((Data?, Error?) -> Void)? = receiveState.withLock { state in
            if let callback = state.pendingReceive {
                state.pendingReceive = nil
                return callback
            }
            state.incoming.append(data)
            return nil
        }
        callback?(data, nil)
    }

    /// Delivers a clean EOF (`nil`) or transport failure; further reads are rejected.
    func deliverClose(error: Error?) {
        enum Action {
            case ignore
            case close(((Data?, Error?) -> Void)?)
        }
        let action: Action = receiveState.withLock { state in
            if state.eof || state.receiveError != nil {
                return .ignore
            }
            state.receiveError = error
            state.eof = true
            let callback = state.pendingReceive
            state.pendingReceive = nil
            return .close(callback)
        }
        guard case .close(let callback) = action else { return }
        let kind = error.map { "error=\($0.localizedDescription)" } ?? "EOF"
        logger.debug("[AnyTLSStream] deliverClose sid=\(sid) \(kind) (pendingRead=\(callback != nil))")
        callback?(nil, error)
        fireOnEndOnce()
    }

    private struct EndState {
        var endFired = false
        /// Fires exactly once when the stream ends; used to return the multiplexer to the idle pool.
        var onEnd: (() -> Void)?
    }

    private let endState = Mutex(EndState())

    /// Fires exactly once when the stream ends; used to return the multiplexer to the idle pool.
    var onEnd: (() -> Void)? {
        get { endState.withLock { $0.onEnd } }
        set { endState.withLock { $0.onEnd = newValue } }
    }

    private func fireOnEndOnce() {
        let hook: (() -> Void)? = endState.withLock { state in
            if state.endFired {
                return nil
            }
            state.endFired = true
            let hook = state.onEnd
            state.onEnd = nil
            return hook
        }
        hook?()
    }
}
