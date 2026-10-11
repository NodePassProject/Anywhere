//
//  RFCMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "RFCMultiplexerPool")

nonisolated final class RFCMultiplexerPool: TransportPool {
    struct Extra {
        var sessionCounter: UInt64 = 0
    }

    private typealias Base = MultiplexerPool<RFCHTTP2Multiplexer, Extra>
    private let pool = Base(extra: Extra())
    
    private static let bucket = "rfc"
    
    private static let idleTimeout: TimeInterval = 180
    private static let idleCheckInterval: TimeInterval = 30

    init() {
        pool.startIdleEviction(MultiplexerPolicy(
            idleTimeout: Self.idleTimeout,
            idleCheckInterval: Self.idleCheckInterval
        ))
    }

    func reclaim() { pool.drainAll() }

    func closeAll() { pool.retire() }
    
    func reserveWarmSession() -> RFCHTTP2Multiplexer? {
        let reused: RFCHTTP2Multiplexer? = pool.state.withLock { state in
            guard state.phase == .open else { return nil }
            guard let reused = state.multiplexers[Self.bucket]?.first(where: { $0.tryReserveStream() }) else {
                return nil
            }
            state.lastActivity[ObjectIdentifier(reused)] = MonotonicClock.now
            return reused
        }
        return reused
    }
    
    func adopt(_ connection: ProxyConnection) async throws -> RFCHTTP2Multiplexer? {
        let adopted: RFCHTTP2Multiplexer? = pool.state.withLock { state in
            guard state.phase == .open else { return nil }
            state.extra.sessionCounter &+= 1
            let multiplexer = RFCHTTP2Multiplexer(
                inner: connection,
                seq: state.extra.sessionCounter,
                onClose: { [weak self] multiplexer in
                    self?.pool.removeMultiplexer(multiplexer, key: Self.bucket)
                }
            )
            _ = multiplexer.tryReserveStream()
            state.multiplexers[Self.bucket, default: []].append(multiplexer)
            state.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            return multiplexer
        }
        if adopted != nil { pool.noteMultiplexersChanged() }

        guard let multiplexer = adopted else {
            return nil
        }
        
        try await multiplexer.start()
        return multiplexer
    }
    
    func idleClockHook(for multiplexer: RFCHTTP2Multiplexer) -> @Sendable () -> Void {
        { [weak self, weak multiplexer] in
            guard let self, let multiplexer else { return }
            self.pool.state.withLock { state in
                if state.lastActivity[ObjectIdentifier(multiplexer)] != nil {
                    state.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
                }
            }
        }
    }
}
