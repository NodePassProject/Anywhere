//
//  AnyTLSMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexerPool")

/// Warm pool per `(host, port, password)`. AnyTLS muxes are reused serially — one stream at
/// a time — so each is reserved before its stream opens and released when it ends.
nonisolated final class AnyTLSMultiplexerPool: MultiplexerPool<AnyTLSMultiplexer> {

    typealias DialOut = @Sendable () async throws -> ProxyConnection

    /// Single bucket — every mux here shares one endpoint + password.
    private static let bucket = "anytls"

    private let dialOut: DialOut
    private let passwordHash: Data
    private var sessionCounter: UInt64 = 0
    private var closed: Bool = false

    init(
        password: String,
        idleSessionCheckInterval: TimeInterval,
        idleSessionTimeout: TimeInterval,
        minIdleSession: Int,
        dialOut: @escaping DialOut
    ) {
        self.passwordHash = AnyTLSProtocol.passwordHash(password)
        self.dialOut = dialOut
        super.init()
        startIdleEviction(MultiplexerPolicy(
            idleTimeout: max(30, idleSessionTimeout),
            idleCheckInterval: max(30, idleSessionCheckInterval),
            minIdleKeep: max(0, minIdleSession)
        ))
    }

    /// The opened stream expects a destination address as its first cmdPSH payload.
    func acquireStream() async throws -> AnyTLSStream {
        let reused: AnyTLSMultiplexer? = try lock.withLock { () throws -> AnyTLSMultiplexer? in
            if closed {
                logger.debug("[AnyTLSMultiplexerPool] acquireStream rejected — client closed")
                throw ProxyError.connectionFailed("AnyTLSMultiplexerPool closed")
            }
            if let reused = multiplexers[Self.bucket]?.first(where: { $0.tryReserveStream() }) {
                lastActivity[ObjectIdentifier(reused)] = MonotonicClock.now
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
        let multiplexer: AnyTLSMultiplexer = try lock.withLock { () throws -> AnyTLSMultiplexer in
            if closed {
                connection.cancel()
                logger.debug("[AnyTLSMultiplexerPool] dial succeeded but client closed in flight — discarding")
                throw ProxyError.connectionFailed("AnyTLSMultiplexerPool closed")
            }
            sessionCounter &+= 1
            let seq = sessionCounter
            let multiplexer = AnyTLSMultiplexer(
                inner: connection,
                passwordHash: passwordHash,
                padding: AnyTLSPaddingScheme.default
            )
            multiplexer.seq = seq
            // Claim before publishing so a concurrent acquire can't grab it.
            _ = multiplexer.tryReserveStream()
            multiplexer.onClose = { [weak self, weak multiplexer] in
                guard let self, let multiplexer else { return }
                self.removeMultiplexer(multiplexer, key: Self.bucket)
            }
            multiplexers[Self.bucket, default: []].append(multiplexer)
            lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            return multiplexer
        }
        logger.debug("[AnyTLSMultiplexerPool] new multiplexer seq=\(multiplexer.seq) — running handshake")
        await multiplexer.start()
        return try await dispatchOpenStream(on: multiplexer)
    }

    /// Sets `closed` to reject new acquires, then defers to the base.
    override func closeAll() {
        lock.lock()
        closed = true
        lock.unlock()
        super.closeAll()
    }

    // MARK: - Private

    private func dispatchOpenStream(on multiplexer: AnyTLSMultiplexer) async throws -> AnyTLSStream {
        guard let stream = await multiplexer.openStream() else {
            logger.debug("[AnyTLSMultiplexerPool] openStream failed on multiplexer seq=\(multiplexer.seq)")
            throw ProxyError.connectionFailed("Failed to open AnyTLS stream")
        }
        // Release the reservation and restart the idle clock at stream end, so a freed mux is
        // kept warm for the full idle timeout (not evicted right after a long transfer).
        stream.onEnd = { [weak self, weak multiplexer] in
            guard let multiplexer else { return }
            multiplexer.releaseReservation()
            guard let self else { return }
            self.lock.lock()
            if self.lastActivity[ObjectIdentifier(multiplexer)] != nil {
                self.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
            }
            self.lock.unlock()
        }
        return stream
    }
}
