//
//  AnyTLSStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

actor AnyTLSStream {
    static let downlinkHighWaterMark = 64 * 1024
    static let downlinkLowWaterMark  = 32 * 1024

    nonisolated let sid: UInt32

    private struct Owner {
        weak var multiplexer: AnyTLSMultiplexer?
    }
    private nonisolated let owner: Mutex<Owner>
    private nonisolated var multiplexer: AnyTLSMultiplexer? { owner.withLock { $0.multiplexer } }
    
    private nonisolated let cachedTLSVersion: TLSVersion?
    
    private let inbox = AsyncInbox<Data>()
    
    private struct Downlink {
        var queuedBytes = 0
        var ended = false
        var gate = H2FlowGate()
    }
    private nonisolated let downlink = Mutex(Downlink())

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
    }
    private nonisolated let state: Mutex<StreamState>

    init(sid: UInt32, multiplexer: AnyTLSMultiplexer, outerTLSVersion: TLSVersion?,
         onEnd: (@Sendable () -> Void)? = nil) {
        self.sid = sid
        self.owner = Mutex(Owner(multiplexer: multiplexer))
        self.cachedTLSVersion = outerTLSVersion
        self.state = Mutex(StreamState(onEnd: onEnd))
    }

    nonisolated var isConnected: Bool {
        state.withLock { if case .open = $0.phase { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { cachedTLSVersion }

    // MARK: - Send

    func sendRaw(_ data: Data) async throws {
        guard isConnected, let multiplexer else {
            throw AnywhereError.proxy(.anyTLS, .connectionClosed(detail: "AnyTLS stream closed"))
        }
        try await multiplexer.writeData(sid: sid, data: data)
    }

    // MARK: - Receive

    func receiveRaw() async throws -> Data? {
        guard let data = try await inbox.next() else { return nil }
        downlink.withLock { link in
            link.queuedBytes = max(0, link.queuedBytes - data.count)
            if link.queuedBytes <= Self.downlinkLowWaterMark { link.gate.wakeAll() }
        }
        return data
    }

    // MARK: - Cancel

    nonisolated func cancel() {
        let outcome: (proceed: Bool, hook: (@Sendable () -> Void)?) = state.withLock { state in
            guard state.transition(to: .localCancelled) else { return (false, nil) }
            let hook = state.onEnd
            state.onEnd = nil
            return (true, hook)
        }
        guard outcome.proceed else { return }
        releaseDownlink()
        inbox.finish()
        multiplexer?.removeStream(sid: sid)
        outcome.hook?()
    }

    nonisolated func deliverData(_ data: Data) {
        let accepted = downlink.withLock { link -> Bool in
            guard !link.ended else { return false }
            link.queuedBytes += data.count
            return true
        }
        guard accepted else { return }
        inbox.yield(data)
    }
    
    nonisolated func awaitDownlinkCredit(for incoming: Int) async {
        while !Task.isCancelled {
            let gate: AsyncStream<Never>? = downlink.withLock { link in
                guard !link.ended, link.queuedBytes > 0,
                      link.queuedBytes + incoming > Self.downlinkHighWaterMark else { return nil }
                return link.gate.enroll()
            }
            guard let gate else { return }
            for await _ in gate {}
        }
    }
    
    private nonisolated func releaseDownlink() {
        downlink.withLock { link in
            link.ended = true
            link.gate.wakeAll()
        }
    }
    
    nonisolated func deliverClose(error: Error?) {
        let outcome: (proceed: Bool, hook: (@Sendable () -> Void)?) = state.withLock { state in
            guard state.transition(to: .ended) else { return (false, nil) }
            let hook = state.onEnd
            state.onEnd = nil
            return (true, hook)
        }
        guard outcome.proceed else { return }
        releaseDownlink()
        if let error { inbox.finish(throwing: error) } else { inbox.finish() }
        outcome.hook?()
    }
}

extension AnyTLSStream: ProxyConnection, MultiplexerStreamSink {}
