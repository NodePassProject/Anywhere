//
//  HTTP2SessionPool.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP2Pool")

/// Pools HTTP/2 sessions keyed by `host:port:sni` so many CONNECT tunnels share one
/// TCP/TLS connection; sessions self-evict via `onClose` on GOAWAY or transport close.
nonisolated final class HTTP2SessionPool: SessionPool<HTTP2Session> {

    static let shared = HTTP2SessionPool()

    /// Dedicated (non-pooled) sessions for chained connections, and
    /// post-GOAWAY sessions retained until their in-flight streams drain.
    private var dedicatedSessions: [ObjectIdentifier: HTTP2Session] = [:]

    private override init() {}

    // MARK: - Acquire

    /// Returns a stream on a pooled (or new) session. Chained connections (`tunnel != nil`)
    /// get a dedicated session because their transport path is unique.
    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        tunnel: ProxyConnection?,
        connectHeaders: @escaping () -> [(name: String, value: String)],
        destination: String,
        completion: @escaping (HTTP2Stream) -> Void
    ) {
        if tunnel != nil {
            let session = HTTP2Session(
                host: host, port: port, sni: sni,
                tunnel: tunnel, connectHeaders: connectHeaders
            )
            let sessionID = ObjectIdentifier(session)
            lock.lock()
            dedicatedSessions[sessionID] = session
            lock.unlock()
            session.onClose = { [weak self] in
                guard let self else { return }
                self.lock.lock()
                self.dedicatedSessions.removeValue(forKey: sessionID)
                self.lock.unlock()
                logger.debug("[HTTP2Pool] Evicted dedicated session")
            }
            session.queue.async {
                let stream = session.createStream(destination: destination)
                completion(stream)
            }
            return
        }

        let key = Self.makeKey(host: host, port: port, sni: sni)
        let session: HTTP2Session

        lock.lock()
        // Park GOAWAY sessions in dedicatedSessions to drain, then evict them from the active bucket.
        if let array = sessions[key] {
            for s in array where s.poolIsGoingAway {
                dedicatedSessions[ObjectIdentifier(s)] = s
            }
        }
        sessions[key]?.removeAll { $0.poolIsClosed || $0.poolIsGoingAway }

        if let existing = sessions[key]?.first(where: { $0.tryReserveStream() }) {
            session = existing
        } else {
            let new = HTTP2Session(
                host: host, port: port, sni: sni,
                tunnel: nil, connectHeaders: connectHeaders
            )
            let capturedKey = key
            new.onClose = { [weak self, weak new] in
                guard let self, let new else { return }
                self.removeSession(new, key: capturedKey)
            }
            sessions[key, default: []].append(new)
            session = new
        }
        lock.unlock()

        session.queue.async {
            let stream = session.createStream(destination: destination)
            completion(stream)
        }
    }

    // MARK: - Eviction

    /// Removes the session from both the pool bucket and ``dedicatedSessions``.
    override func removeSession(_ session: HTTP2Session, key: String) {
        super.removeSession(session, key: key)
        lock.lock()
        dedicatedSessions.removeValue(forKey: ObjectIdentifier(session))
        lock.unlock()
        logger.debug("[HTTP2Pool] Evicted session for \(key)")
    }

    override func closeAll() {
        lock.lock()
        let dedicated = Array(dedicatedSessions.values)
        dedicatedSessions.removeAll()
        lock.unlock()

        super.closeAll()

        for session in dedicated {
            session.close()
        }
    }
}
