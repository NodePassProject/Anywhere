//
//  AnyTLSMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexerPool")

nonisolated final class AnyTLSMultiplexerPool: TransportPool {

    struct Extra {
        var sessionCounter: UInt64 = 0
    }

    private typealias Base = MultiplexerPool<AnyTLSMultiplexer, Extra>
    private let pool = Base(extra: Extra())

    typealias DialOut = @Sendable () async throws -> ProxyConnection
    
    private static let bucket = "anytls"
    
    private static let defaultIdleSessionSoftCap = 4
    private static let defaultPooledSessionHardCap = 128
    
    private static let minimumIdleInterval: TimeInterval = 5

    private let idleSessionSoftCap: Int
    private let pooledSessionHardCap: Int

    private let dialOut: DialOut
    private let passwordHash: Data

    init(
        password: String,
        idleSessionCheckInterval: TimeInterval,
        idleSessionTimeout: TimeInterval,
        minIdleSession: Int,
        dialOut: @escaping DialOut
    ) {
        self.passwordHash = AnyTLSProtocol.passwordHash(password)
        self.dialOut = dialOut
        let minIdleKeep = max(0, minIdleSession)
        let softCap = max(minIdleKeep, Self.defaultIdleSessionSoftCap)
        self.idleSessionSoftCap = softCap
        self.pooledSessionHardCap = max(softCap, Self.defaultPooledSessionHardCap)
        pool.startIdleEviction(
            MultiplexerPolicy(
                idleTimeout: max(Self.minimumIdleInterval, idleSessionTimeout),
                idleCheckInterval: max(Self.minimumIdleInterval, idleSessionCheckInterval),
                minIdleKeep: minIdleKeep,
                softCapPerKey: softCap,
                hardCapPerKey: pooledSessionHardCap
            )
        )
    }

    func reclaim() { pool.drainAll() }
    
    func acquireStream() async throws -> AnyTLSStream {
        let reused: AnyTLSMultiplexer? = try pool.state.withLock { state throws -> AnyTLSMultiplexer? in
            if state.phase == .closed {
                throw AnywhereError.transport(.terminated)
            }
            if let reused = state.multiplexers[Self.bucket]?.first(where: { $0.tryReserveStream() }) {
                state.lastActivity[ObjectIdentifier(reused)] = MonotonicClock.now
                return reused
            }
            return nil
        }
        if let reused {
            return try await dispatchOpenStream(on: reused, pooled: true)
        }

        let connection = try await dialOut()
        let adopted: (multiplexer: AnyTLSMultiplexer, pooled: Bool)? = pool.state.withLock { state in
            guard state.phase == .open else { return nil }
            state.extra.sessionCounter &+= 1
            let multiplexer = AnyTLSMultiplexer(
                inner: connection,
                passwordHash: passwordHash,
                padding: AnyTLSPaddingScheme.default,
                seq: state.extra.sessionCounter,
                onClose: { [weak self] multiplexer in
                    self?.pool.removeMultiplexer(multiplexer, key: Self.bucket)
                }
            )
            _ = multiplexer.tryReserveStream()
            let tracked = state.multiplexers[Self.bucket]?.count ?? 0
            guard tracked < pooledSessionHardCap else {
                return (multiplexer, false)
            }
            state.multiplexers[Self.bucket, default: []].append(multiplexer)
            state.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            return (multiplexer, true)
        }
        if adopted?.pooled == true { pool.noteMultiplexersChanged() }
        guard let adopted else {
            connection.cancel()
            throw AnywhereError.transport(.terminated)
        }
        await adopted.multiplexer.start()
        return try await dispatchOpenStream(on: adopted.multiplexer, pooled: adopted.pooled)
    }

    func closeAll() {
        pool.retire()
    }

    // MARK: - Private

    private func dispatchOpenStream(on multiplexer: AnyTLSMultiplexer, pooled: Bool) async throws -> AnyTLSStream {
        let onEnd: @Sendable () -> Void = { [weak self, weak multiplexer] in
            guard let multiplexer else { return }
            multiplexer.releaseReservation()
            guard pooled, let self else {
                // Detached, or the pool is gone: the session has nothing left to serve.
                multiplexer.close(error: nil)
                return
            }
            self.retireIfSurplus(multiplexer)
        }
        guard let stream = await multiplexer.openStream(onEnd: onEnd) else {
            if !pooled { multiplexer.close(error: nil) }
            throw AnywhereError.proxy(.anyTLS, .connectionClosed(detail: "Failed to open AnyTLS stream"))
        }
        return stream
    }
    
    private func retireIfSurplus(_ multiplexer: AnyTLSMultiplexer) {
        let identifier = ObjectIdentifier(multiplexer)
        let evict: Bool = pool.state.withLock { state in
            guard state.lastActivity[identifier] != nil else { return false }
            let idleOthers = state.multiplexers[Self.bucket]?.reduce(into: 0) { count, candidate in
                guard candidate !== multiplexer, !candidate.isClosed, candidate.activeStreamCount == 0 else { return }
                count += 1
            } ?? 0
            guard idleOthers >= idleSessionSoftCap else {
                state.lastActivity[identifier] = MonotonicClock.now
                return false
            }
            state.multiplexers[Self.bucket]?.removeAll { $0 === multiplexer }
            state.lastActivity.removeValue(forKey: identifier)
            if state.multiplexers[Self.bucket]?.isEmpty == true {
                state.multiplexers.removeValue(forKey: Self.bucket)
            }
            return true
        }
        if evict { multiplexer.close(error: nil) }
    }
}
