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

    typealias DialOut = (@escaping (Result<ProxyConnection, Error>) -> Void) -> Void

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
    func acquireStream(completion: @escaping (Result<AnyTLSStream, Error>) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            logger.debug("[AnyTLSMultiplexerPool] acquireStream rejected — client closed")
            completion(.failure(ProxyError.connectionFailed("AnyTLSMultiplexerPool closed")))
            return
        }
        if let reused = multiplexers[Self.bucket]?.first(where: { $0.tryReserveStream() }) {
            lastActivity[ObjectIdentifier(reused)] = MonotonicClock.now
            lock.unlock()
            logger.debug("[AnyTLSMultiplexerPool] acquireStream reusing idle multiplexer seq=\(reused.seq)")
            dispatchOpenStream(on: reused, completion: completion)
            return
        }
        lock.unlock()
        logger.debug("[AnyTLSMultiplexerPool] acquireStream — no idle multiplexer, dialing fresh TLS multiplexer")

        dialOut { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("AnyTLSMultiplexerPool deallocated")))
                return
            }
            switch result {
            case .failure(let error):
                logger.debug("[AnyTLSMultiplexerPool] dial failed: \(error.localizedDescription)")
                completion(.failure(error))
            case .success(let connection):
                self.lock.lock()
                if self.closed {
                    self.lock.unlock()
                    connection.cancel()
                    logger.debug("[AnyTLSMultiplexerPool] dial succeeded but client closed in flight — discarding")
                    completion(.failure(ProxyError.connectionFailed("AnyTLSMultiplexerPool closed")))
                    return
                }
                self.sessionCounter &+= 1
                let seq = self.sessionCounter
                let multiplexer = AnyTLSMultiplexer(
                    inner: connection,
                    passwordHash: self.passwordHash,
                    padding: AnyTLSPaddingScheme.default
                )
                multiplexer.seq = seq
                // Claim before publishing so a concurrent acquire can't grab it.
                _ = multiplexer.tryReserveStream()
                multiplexer.onClose = { [weak self, weak multiplexer] in
                    guard let self, let multiplexer else { return }
                    self.removeMultiplexer(multiplexer, key: Self.bucket)
                }
                self.multiplexers[Self.bucket, default: []].append(multiplexer)
                self.lastActivity[ObjectIdentifier(multiplexer)] = MonotonicClock.now
                self.lock.unlock()
                logger.debug("[AnyTLSMultiplexerPool] new multiplexer seq=\(seq) — running handshake")
                multiplexer.start()
                self.dispatchOpenStream(on: multiplexer, completion: completion)
            }
        }
    }

    /// Sets `closed` to reject new acquires, then defers to the base.
    override func closeAll() {
        lock.lock()
        closed = true
        lock.unlock()
        super.closeAll()
    }

    // MARK: - Private

    private func dispatchOpenStream(on multiplexer: AnyTLSMultiplexer, completion: @escaping (Result<AnyTLSStream, Error>) -> Void) {
        guard let stream = multiplexer.openStream() else {
            logger.debug("[AnyTLSMultiplexerPool] openStream failed on multiplexer seq=\(multiplexer.seq)")
            completion(.failure(ProxyError.connectionFailed("Failed to open AnyTLS stream")))
            return
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
        completion(.success(stream))
    }
}
