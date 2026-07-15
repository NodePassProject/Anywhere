//
//  AnyTLSStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSStream")

nonisolated final class AnyTLSStream: ProxyConnection, MultiplexerStreamSink {

    let sid: UInt32
    private weak var multiplexer: AnyTLSMultiplexer?

    /// Captured at construction so `outerTLSVersion` keeps working after the multiplexer goes away.
    private let cachedTLSVersion: TLSVersion?

    /// Inbound cmdPSH payloads / EOF / error from the multiplexer's demux loop.
    private let inbox = AsyncByteChannel()

    private struct ReceiveState {
        var ended: Bool = false
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
        !receiveState.withLock { $0.ended } && (multiplexer?.isAlive ?? false)
    }

    override var outerTLSVersion: TLSVersion? { cachedTLSVersion }

    // MARK: - Send

    override func sendRaw(_ data: Data) async throws {
        guard let multiplexer else {
            throw ProxyError.connectionFailed("AnyTLS multiplexer deallocated")
        }
        try await multiplexer.writeData(sid: sid, data: data)
    }

    // MARK: - Receive

    override func receiveRaw() async throws -> Data? {
        try await inbox.next()
    }

    // MARK: - Cancel

    override func cancel() {
        let already = receiveState.withLock { state -> Bool in
            let already = state.locallyCancelled
            state.locallyCancelled = true
            return already
        }
        guard !already else { return }
        logger.debug("[AnyTLSStream] cancel sid=\(sid)")
        inbox.cancel()
        multiplexer?.removeStream(sid: sid)
        fireOnEndOnce()
    }

    // MARK: - Called by AnyTLSMultiplexer on the recv loop

    /// Delivers a payload chunk from a cmdPSH frame addressed to this stream.
    func deliverData(_ data: Data) {
        inbox.yield(data)
    }

    /// Delivers a clean EOF (`nil`) or transport failure; further reads are rejected.
    func deliverClose(error: Error?) {
        let shouldClose = receiveState.withLock { state -> Bool in
            guard !state.ended else { return false }
            state.ended = true
            return true
        }
        guard shouldClose else { return }
        let kind = error.map { "error=\($0.localizedDescription)" } ?? "EOF"
        logger.debug("[AnyTLSStream] deliverClose sid=\(sid) \(kind)")
        if let error { inbox.fail(error) } else { inbox.finish() }
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
