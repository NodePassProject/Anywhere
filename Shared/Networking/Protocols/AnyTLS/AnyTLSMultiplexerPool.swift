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

    /// Single bucket — every mux here shares one endpoint + password.
    private static let bucket = "anytls"

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
        pool.startIdleEviction(MultiplexerPolicy(
            idleTimeout: max(30, idleSessionTimeout),
            idleCheckInterval: max(30, idleSessionCheckInterval),
            minIdleKeep: max(0, minIdleSession)
        ))
    }

    func reclaim() { pool.drainAll() }

    /// The opened stream expects a destination address as its first cmdPSH payload.
    func acquireStream() async throws -> AnyTLSStream {
        let reused: AnyTLSMultiplexer? = try pool.state.withLock { st throws -> AnyTLSMultiplexer? in
            if st.phase == .closed {
                logger.debug("[AnyTLSMultiplexerPool] acquireStream rejected — client closed")
                throw AnywhereError.transport(.terminated)
            }
            if let reused = st.multiplexers[Self.bucket]?.first(where: { $0.tryReserveStream() }) {
                st.lastActivity[ObjectIdentifier(reused)] = MonotonicClock.now
                return reused
            }
            return nil
        }
        if let reused {
            logger.debug("[AnyTLSMultiplexerPool] acquireStream reusing idle multiplexer seq=\(reused.seq)")
            return try await dispatchOpenStream(on: reused)
        }
        logger.debug("[AnyTLSMultiplexerPool] acquireStream — no idle multiplexer, dialing fresh TLS multiplexer")

        let connection = try await dialOut()
        let adopted: AnyTLSMultiplexer? = pool.state.withLock { st -> AnyTLSMultiplexer? in
            guard st.phase == .open else { return nil }
            st.extra.sessionCounter &+= 1
            let multiplexer = AnyTLSMultiplexer(
                inner: connection,
                passwordHash: passwordHash,
                padding: AnyTLSPaddingScheme.default,
                seq: st.extra.sessionCounter,
                onClose: { [weak self] multiplexer in
                    self?.pool.removeMultiplexer(multiplexer, key: Self.bucket)
                }
            )
            // Claim before publishing so a concurrent acquire can't grab it.
            _ = multiplexer.tryReserveStream()
            st.multiplexers[Self.bucket, default: []].append(multiplexer)
            st.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            return multiplexer
        }
        guard let multiplexer = adopted else {
            connection.cancel()
            logger.debug("[AnyTLSMultiplexerPool] dial succeeded but client closed in flight — discarding")
            throw AnywhereError.transport(.terminated)
        }
        logger.debug("[AnyTLSMultiplexerPool] new multiplexer seq=\(multiplexer.seq) — running handshake")
        await multiplexer.start()
        return try await dispatchOpenStream(on: multiplexer)
    }

    func closeAll() {
        pool.retire()
    }

    // MARK: - Private

    private func dispatchOpenStream(on multiplexer: AnyTLSMultiplexer) async throws -> AnyTLSStream {
        // Release the reservation and restart the idle clock at stream end, so a freed mux is
        // kept warm for the full idle timeout (not evicted right after a long transfer).
        // Installed at stream creation, so the stream carries no mutable hook.
        let onEnd: @Sendable () -> Void = { [weak self, weak multiplexer] in
            guard let multiplexer else { return }
            multiplexer.releaseReservation()
            guard let self else { return }
            self.pool.state.withLock { st in
                if st.lastActivity[ObjectIdentifier(multiplexer)] != nil {
                    st.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
                }
            }
        }
        guard let stream = await multiplexer.openStream(onEnd: onEnd) else {
            logger.debug("[AnyTLSMultiplexerPool] openStream failed on multiplexer seq=\(multiplexer.seq)")
            throw AnywhereError.proxy(.anyTLS, .connectionClosed(detail: "Failed to open AnyTLS stream"))
        }
        return stream
    }
}
