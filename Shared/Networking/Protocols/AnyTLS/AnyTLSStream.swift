//
//  AnyTLSStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSStream")

actor AnyTLSStream {

    nonisolated let sid: UInt32
    private weak var multiplexer: AnyTLSMultiplexer?

    /// Captured at construction so `outerTLSVersion` keeps working after the multiplexer goes away.
    private nonisolated let cachedTLSVersion: TLSVersion?

    /// Inbound cmdPSH payloads / EOF / error from the multiplexer's demux loop.
    private nonisolated let inbox: AsyncThrowingStream<Data, Error>.Continuation
    private var inboxIterator: AsyncThrowingStream<Data, Error>.AsyncIterator

    /// Set once `deliverClose` fires; the nonisolated `isConnected` reads it.
    private nonisolated let _ended = Atomic<Bool>(false)
    /// Set by `cancel()` so the multiplexer does not echo a FIN back to itself.
    private nonisolated let _locallyCancelled = Atomic<Bool>(false)

    private struct EndState {
        var endFired = false
        /// Fires exactly once when the stream ends; used to return the multiplexer to the idle pool.
        var onEnd: (() -> Void)?
    }
    private let endState = Mutex(EndState())

    init(sid: UInt32, multiplexer: AnyTLSMultiplexer, outerTLSVersion: TLSVersion?) {
        self.sid = sid
        self.multiplexer = multiplexer
        self.cachedTLSVersion = outerTLSVersion
        let (stream, continuation) = AsyncThrowingStream.makeStream(of: Data.self)
        self.inbox = continuation
        self.inboxIterator = stream.makeAsyncIterator()
    }

    nonisolated var isConnected: Bool { !_ended.load(ordering: .relaxed) }
    nonisolated var outerTLSVersion: TLSVersion? { cachedTLSVersion }

    /// Set by `cancel()` so the multiplexer does not echo a FIN back to itself.
    nonisolated var locallyCancelled: Bool { _locallyCancelled.load(ordering: .relaxed) }

    /// Fires exactly once when the stream ends; used to return the multiplexer to the idle pool.
    nonisolated var onEnd: (() -> Void)? {
        get { endState.withLock { $0.onEnd } }
        set { endState.withLock { $0.onEnd = newValue } }
    }

    // MARK: - Send

    func sendRaw(_ data: Data) async throws {
        guard let multiplexer else {
            throw ProxyError.connectionFailed("AnyTLS multiplexer deallocated")
        }
        try await multiplexer.writeData(sid: sid, data: data)
    }

    // MARK: - Receive

    func receiveRaw() async throws -> Data? {
        var iterator = inboxIterator
        let next = try await iterator.next()
        inboxIterator = iterator
        return next
    }

    // MARK: - Cancel

    nonisolated func cancel() {
        guard !_locallyCancelled.exchange(true, ordering: .relaxed) else { return }
        logger.debug("[AnyTLSStream] cancel sid=\(sid)")
        inbox.finish()
        fireOnEndOnce()
        Task { await self.removeFromMultiplexer() }
    }

    private func removeFromMultiplexer() {
        multiplexer?.removeStream(sid: sid)
    }

    // MARK: - Called by AnyTLSMultiplexer on the recv loop (nonisolated)

    /// Delivers a payload chunk from a cmdPSH frame addressed to this stream.
    nonisolated func deliverData(_ data: Data) {
        inbox.yield(data)
    }

    /// Delivers a clean EOF (`nil`) or transport failure; further reads are rejected.
    nonisolated func deliverClose(error: Error?) {
        guard !_ended.exchange(true, ordering: .relaxed) else { return }
        let kind = error.map { "error=\($0.localizedDescription)" } ?? "EOF"
        logger.debug("[AnyTLSStream] deliverClose sid=\(sid) \(kind)")
        if let error { inbox.finish(throwing: error) } else { inbox.finish() }
        fireOnEndOnce()
    }

    private nonisolated func fireOnEndOnce() {
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

extension AnyTLSStream: ProxyConnection, MultiplexerStreamSink {}
