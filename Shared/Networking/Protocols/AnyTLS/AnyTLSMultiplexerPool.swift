//
//  AnyTLSMultiplexerPool.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "AnyTLSMultiplexerPool")

/// Per-server AnyTLS multiplexer pool.
nonisolated final class AnyTLSMultiplexerPool {

    /// Creates a fresh TLS-backed `ProxyConnection` for a new multiplexer.
    typealias DialOut = (@escaping (Result<ProxyConnection, Error>) -> Void) -> Void

    private let dialOut: DialOut
    private let passwordHash: Data

    /// Clamped to ≥30s/≥30s/≥0 to match sing-anytls's `NewClient`.
    let idleSessionCheckInterval: TimeInterval
    let idleSessionTimeout: TimeInterval
    let minIdleSession: Int

    private let lock = UnfairLock()
    private var idleMultiplexers: [AnyTLSMultiplexer] = []     // newest seq last (we pop from the end)
    private var activeMultiplexers: [ObjectIdentifier: AnyTLSMultiplexer] = [:]
    private var sessionCounter: UInt64 = 0
    private var closed: Bool = false

    private let timerQueue = DispatchQueue(label: AWCore.Identifier.anyTLSIdleQueue)
    private var idleTimer: DispatchSourceTimer?

    init(
        password: String,
        idleSessionCheckInterval: TimeInterval,
        idleSessionTimeout: TimeInterval,
        minIdleSession: Int,
        dialOut: @escaping DialOut
    ) {
        self.passwordHash = AnyTLSProtocol.passwordHash(password)
        self.idleSessionCheckInterval = max(30, idleSessionCheckInterval)
        self.idleSessionTimeout       = max(30, idleSessionTimeout)
        self.minIdleSession           = max(0, minIdleSession)
        self.dialOut = dialOut
        startIdleTimer()
    }

    deinit {
        idleTimer?.cancel()
    }

    /// Acquires a multiplexer (idle or freshly dialed) and opens a stream on it;
    /// the stream expects a destination address as its first cmdPSH payload.
    func acquireStream(completion: @escaping (Result<AnyTLSStream, Error>) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            logger.debug("[AnyTLSMultiplexerPool] acquireStream rejected — client closed")
            completion(.failure(ProxyError.connectionFailed("AnyTLSMultiplexerPool closed")))
            return
        }
        if let reused = popIdleSessionLocked() {
            activeMultiplexers[ObjectIdentifier(reused)] = reused
            let idleCount = idleMultiplexers.count
            let activeCount = activeMultiplexers.count
            lock.unlock()
            logger.debug("[AnyTLSMultiplexerPool] acquireStream reusing idle multiplexer seq=\(reused.seq) (idle=\(idleCount) active=\(activeCount))")
            dispatchOpenStream(on: reused, completion: completion)
            return
        }
        lock.unlock()
        logger.debug("[AnyTLSMultiplexerPool] acquireStream — pool empty, dialing fresh TLS multiplexer")

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
                multiplexer.onClose = { [weak self, weak multiplexer] in
                    guard let self, let multiplexer else { return }
                    self.evict(multiplexer: multiplexer)
                }
                self.activeMultiplexers[ObjectIdentifier(multiplexer)] = multiplexer
                self.lock.unlock()
                logger.debug("[AnyTLSMultiplexerPool] new multiplexer seq=\(seq) — running handshake")
                multiplexer.start()
                self.dispatchOpenStream(on: multiplexer, completion: completion)
            }
        }
    }

    /// Closes all multiplexers (active and idle) and shuts down the pool.
    func closeAll() {
        lock.lock()
        closed = true
        idleTimer?.cancel()
        idleTimer = nil
        let multiplexers = idleMultiplexers + Array(activeMultiplexers.values)
        idleMultiplexers.removeAll(keepingCapacity: false)
        activeMultiplexers.removeAll(keepingCapacity: false)
        lock.unlock()
        for multiplexer in multiplexers {
            multiplexer.close(error: nil)
        }
    }

    // MARK: - Private

    private func dispatchOpenStream(on multiplexer: AnyTLSMultiplexer, completion: @escaping (Result<AnyTLSStream, Error>) -> Void) {
        guard let stream = multiplexer.openStream() else {
            logger.debug("[AnyTLSMultiplexerPool] openStream failed on multiplexer seq=\(multiplexer.seq)")
            completion(.failure(ProxyError.connectionFailed("Failed to open AnyTLS stream")))
            return
        }
        // Per sing-anytls's `dieHook`: return the multiplexer to the idle pool when the stream closes.
        stream.onEnd = { [weak self, weak multiplexer] in
            guard let self, let multiplexer else { return }
            self.returnToPool(multiplexer: multiplexer)
        }
        completion(.success(stream))
    }

    private func evict(multiplexer: AnyTLSMultiplexer) {
        lock.lock()
        let id = ObjectIdentifier(multiplexer)
        activeMultiplexers.removeValue(forKey: id)
        idleMultiplexers.removeAll { $0 === multiplexer }
        lock.unlock()
    }

    /// Returns the multiplexer to the idle pool after its last stream closes.
    fileprivate func returnToPool(multiplexer: AnyTLSMultiplexer) {
        guard multiplexer.isAlive else {
            logger.debug("[AnyTLSMultiplexerPool] returnToPool seq=\(multiplexer.seq): multiplexer already dead, dropping")
            return
        }
        lock.lock()
        if closed {
            lock.unlock()
            multiplexer.close(error: nil)
            return
        }
        activeMultiplexers.removeValue(forKey: ObjectIdentifier(multiplexer))
        multiplexer.idleSince = CFAbsoluteTimeGetCurrent()
        idleMultiplexers.append(multiplexer)
        let idleCount = idleMultiplexers.count
        let activeCount = activeMultiplexers.count
        lock.unlock()
        logger.debug("[AnyTLSMultiplexerPool] multiplexer seq=\(multiplexer.seq) returned to pool (idle=\(idleCount) active=\(activeCount))")
    }

    private func popIdleSessionLocked() -> AnyTLSMultiplexer? {
        // Pop most-recently-used so the LRU tail naturally ages out via cleanup.
        while let candidate = idleMultiplexers.popLast() {
            if candidate.isAlive { return candidate }
        }
        return nil
    }

    // MARK: - Idle cleanup

    private func startIdleTimer() {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(
            deadline: .now() + idleSessionCheckInterval,
            repeating: idleSessionCheckInterval,
            leeway: .milliseconds(Int(idleSessionCheckInterval * 100))
        )
        timer.setEventHandler { [weak self] in
            self?.runIdleCleanup()
        }
        timer.resume()
        idleTimer = timer
    }

    private func runIdleCleanup() {
        let cutoff = CFAbsoluteTimeGetCurrent() - idleSessionTimeout
        var toClose: [AnyTLSMultiplexer] = []
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        // Walk oldest-first; anything past cutoff is killed unless below the minimum warm count.
        var survivors: [AnyTLSMultiplexer] = []
        var keptCount = 0
        for multiplexer in idleMultiplexers {
            if multiplexer.idleSince > cutoff {
                survivors.append(multiplexer)
                keptCount += 1
                continue
            }
            if keptCount < minIdleSession {
                // Refresh and keep — matches `idleCleanupExpTime`.
                multiplexer.idleSince = CFAbsoluteTimeGetCurrent()
                survivors.append(multiplexer)
                keptCount += 1
                continue
            }
            toClose.append(multiplexer)
        }
        idleMultiplexers = survivors
        lock.unlock()

        for multiplexer in toClose {
            multiplexer.close(error: nil)
        }
    }
}

