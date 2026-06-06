//
//  AnyTLSClient.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLSClient")

/// Per-server AnyTLS session pool.
nonisolated final class AnyTLSClient {

    /// Closure that creates a fresh TLS-backed `ProxyConnection` for a new
    /// session. Provided by `ProxyClient+AnyTLS` so each AnyTLSClient stays
    /// independent of the TLS plumbing — the closure already knows about
    /// the proxy chain (`tunnel`) and the configured TLS knobs.
    typealias DialOut = (@escaping (Result<ProxyConnection, Error>) -> Void) -> Void

    private let dialOut: DialOut
    private let passwordHash: Data

    /// Defaults clamped to ≥30s/≥30s/≥0 to match `session/client.go`'s
    /// `NewClient` (it bumps anything ≤5s up to 30s).
    let idleSessionCheckInterval: TimeInterval
    let idleSessionTimeout: TimeInterval
    let minIdleSession: Int

    private let lock = UnfairLock()
    private var idleSessions: [AnyTLSSession] = []     // newest seq last (we pop from the end)
    private var activeSessions: [ObjectIdentifier: AnyTLSSession] = [:]
    private var sessionCounter: UInt64 = 0
    private var closed: Bool = false

    private let timerQueue = DispatchQueue(label: "AnyTLSClient.idleCleanup")
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

    /// Acquires a session (idle or freshly dialed) and opens a stream on it.
    /// On success the caller gets an `AnyTLSStream` ready to receive its
    /// destination address as the first cmdPSH.
    func createStream(completion: @escaping (Result<AnyTLSStream, Error>) -> Void) {
        lock.lock()
        if closed {
            lock.unlock()
            logger.debug("[AnyTLSClient] createStream rejected — client closed")
            completion(.failure(ProxyError.connectionFailed("AnyTLSClient closed")))
            return
        }
        if let reused = popIdleSessionLocked() {
            activeSessions[ObjectIdentifier(reused)] = reused
            let idleCount = idleSessions.count
            let activeCount = activeSessions.count
            lock.unlock()
            logger.debug("[AnyTLSClient] createStream reusing idle session seq=\(reused.seq) (idle=\(idleCount) active=\(activeCount))")
            dispatchOpenStream(on: reused, completion: completion)
            return
        }
        lock.unlock()
        logger.debug("[AnyTLSClient] createStream — pool empty, dialing fresh TLS session")

        dialOut { [weak self] result in
            guard let self else {
                completion(.failure(ProxyError.connectionFailed("AnyTLSClient deallocated")))
                return
            }
            switch result {
            case .failure(let error):
                logger.debug("[AnyTLSClient] dial failed: \(error.localizedDescription)")
                completion(.failure(error))
            case .success(let connection):
                self.lock.lock()
                if self.closed {
                    self.lock.unlock()
                    connection.cancel()
                    logger.debug("[AnyTLSClient] dial succeeded but client closed in flight — discarding")
                    completion(.failure(ProxyError.connectionFailed("AnyTLSClient closed")))
                    return
                }
                self.sessionCounter &+= 1
                let seq = self.sessionCounter
                let session = AnyTLSSession(
                    inner: connection,
                    passwordHash: self.passwordHash,
                    padding: AnyTLSPaddingScheme.default
                )
                session.seq = seq
                session.onClose = { [weak self, weak session] in
                    guard let self, let session else { return }
                    self.evict(session: session)
                }
                self.activeSessions[ObjectIdentifier(session)] = session
                self.lock.unlock()
                logger.debug("[AnyTLSClient] new session seq=\(seq) — running handshake")
                session.start()
                self.dispatchOpenStream(on: session, completion: completion)
            }
        }
    }

    /// Returns every session (active and idle) to the pool's "closed" state.
    /// Used by `AnyTLSManager.closeAll` and the per-config replace path.
    func closeAll() {
        lock.lock()
        closed = true
        idleTimer?.cancel()
        idleTimer = nil
        let sessions = idleSessions + Array(activeSessions.values)
        idleSessions.removeAll(keepingCapacity: false)
        activeSessions.removeAll(keepingCapacity: false)
        lock.unlock()
        for session in sessions {
            session.close(reason: nil)
        }
    }

    // MARK: - Private

    private func dispatchOpenStream(on session: AnyTLSSession, completion: @escaping (Result<AnyTLSStream, Error>) -> Void) {
        guard let stream = session.openStream() else {
            logger.debug("[AnyTLSClient] openStream failed on session seq=\(session.seq)")
            completion(.failure(ProxyError.connectionFailed("Failed to open AnyTLS stream")))
            return
        }
        // Per sing-anytls's `dieHook` (session/client.go line ~98): when
        // this stream's pipe closes, return its underlying session to the
        // idle pool so the next CreateStream can reuse the warm TLS conn.
        stream.onEnd = { [weak self, weak session] in
            guard let self, let session else { return }
            self.returnToPool(session: session)
        }
        completion(.success(stream))
    }

    /// Called by `AnyTLSSession.onClose`. Evict this session from both pools.
    private func evict(session: AnyTLSSession) {
        lock.lock()
        let id = ObjectIdentifier(session)
        activeSessions.removeValue(forKey: id)
        idleSessions.removeAll { $0 === session }
        lock.unlock()
    }

    /// Returns the session to the idle pool. Called when a stream's lifetime
    /// ends and no other streams remain (tracked by `SessionRecycler`).
    fileprivate func returnToPool(session: AnyTLSSession) {
        guard session.isAlive else {
            logger.debug("[AnyTLSClient] returnToPool seq=\(session.seq): session already dead, dropping")
            return
        }
        lock.lock()
        if closed {
            lock.unlock()
            session.close(reason: nil)
            return
        }
        activeSessions.removeValue(forKey: ObjectIdentifier(session))
        session.idleSince = CFAbsoluteTimeGetCurrent()
        idleSessions.append(session)
        let idleCount = idleSessions.count
        let activeCount = activeSessions.count
        lock.unlock()
        logger.debug("[AnyTLSClient] session seq=\(session.seq) returned to pool (idle=\(idleCount) active=\(activeCount))")
    }

    private func popIdleSessionLocked() -> AnyTLSSession? {
        // Prefer the most recently-used session (last appended) so the LRU
        // tail naturally migrates to the cleanup edge.
        while let candidate = idleSessions.popLast() {
            if candidate.isAlive { return candidate }
        }
        return nil
    }

    // MARK: - Idle cleanup

    private func startIdleTimer() {
        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(
            deadline: .now() + idleSessionCheckInterval,
            repeating: idleSessionCheckInterval
        )
        timer.setEventHandler { [weak self] in
            self?.runIdleCleanup()
        }
        timer.resume()
        idleTimer = timer
    }

    private func runIdleCleanup() {
        let cutoff = CFAbsoluteTimeGetCurrent() - idleSessionTimeout
        var toClose: [AnyTLSSession] = []
        lock.lock()
        if closed {
            lock.unlock()
            return
        }
        // Walk oldest-first (head of array) — anything past cutoff is killed
        // unless we're already below the minimum warm count.
        var survivors: [AnyTLSSession] = []
        var keptCount = 0
        for session in idleSessions {
            if session.idleSince > cutoff {
                survivors.append(session)
                keptCount += 1
                continue
            }
            if keptCount < minIdleSession {
                // Refresh and keep — matches `idleCleanupExpTime`.
                session.idleSince = CFAbsoluteTimeGetCurrent()
                survivors.append(session)
                keptCount += 1
                continue
            }
            toClose.append(session)
        }
        idleSessions = survivors
        lock.unlock()

        for session in toClose {
            session.close(reason: nil)
        }
    }
}

