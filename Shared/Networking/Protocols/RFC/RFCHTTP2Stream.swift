//
//  RFCHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import Foundation
import Synchronization

nonisolated final class RFCHTTP2Stream: ProxyConnection, MultiplexerStreamSink, Sendable {
    let streamID: UInt32
    
    private let cachedTLSVersion: TLSVersion?
    
    private let inbox = AsyncInbox<Data>()

    private enum Phase: PhaseTransitionable {
        case open
        case localCancelled
        case ended

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .localCancelled),
                 (.open, .ended),
                 (.localCancelled, .ended):
                return true
            default:
                return false
            }
        }
    }

    private struct StreamState: PhaseHolding {
        var phase: Phase = .open
        var onEnd: (@Sendable () -> Void)?
        weak var multiplexer: RFCHTTP2Multiplexer?
    }

    private let state: Mutex<StreamState>

    private var multiplexer: RFCHTTP2Multiplexer? { state.withLock { $0.multiplexer } }

    init(
        streamID: UInt32,
        multiplexer: RFCHTTP2Multiplexer,
        outerTLSVersion: TLSVersion?,
        onEnd: (@Sendable () -> Void)? = nil
    ) {
        self.streamID = streamID
        self.cachedTLSVersion = outerTLSVersion
        self.state = Mutex(StreamState(onEnd: onEnd, multiplexer: multiplexer))
    }

    var outerTLSVersion: TLSVersion? { cachedTLSVersion }

    var isConnected: Bool {
        state.withLock { if case .open = $0.phase { true } else { false } }
    }

    func sendRaw(_ data: Data) async throws {
        let multiplexer: RFCHTTP2Multiplexer? = state.withLock { state in
            guard case .open = state.phase else { return nil }
            return state.multiplexer
        }
        guard let multiplexer else {
            throw AnywhereError.proxy(.http2, .connectionClosed(detail: "RFC stream \(streamID) closed"))
        }
        try await multiplexer.sendData(streamID: streamID, data: data)
    }

    func receiveRaw() async throws -> Data? {
        let data = try await inbox.next()
        if let data, !data.isEmpty {
            multiplexer?.streamDidConsume(streamID: streamID, bytes: data.count)
        }
        return data
    }

    func cancel() {
        typealias Outcome = (proceed: Bool, hook: (@Sendable () -> Void)?, multiplexer: RFCHTTP2Multiplexer?)
        let outcome: Outcome = state.withLock { state in
            guard state.transition(to: .localCancelled) else { return (false, nil, nil) }
            let hook = state.onEnd
            state.onEnd = nil
            let multiplexer = state.multiplexer
            state.multiplexer = nil
            return (true, hook, multiplexer)
        }
        guard outcome.proceed else { return }
        inbox.finish()
        outcome.hook?()
        outcome.multiplexer?.resetStream(streamID: streamID, errorCode: RFCProtocol.HTTP2ErrorCode.cancel)
    }
    
    func deliverData(_ data: Data) {
        inbox.yield(data)
    }
    
    func deliverClose(error: Error?) {
        let outcome: (proceed: Bool, hook: (@Sendable () -> Void)?) = state.withLock { state in
            guard state.transition(to: .ended) else { return (false, nil) }
            let hook = state.onEnd
            state.onEnd = nil
            state.multiplexer = nil
            return (true, hook)
        }
        guard outcome.proceed else { return }
        if let error { inbox.finish(throwing: error) } else { inbox.finish() }
        outcome.hook?()
    }
}
