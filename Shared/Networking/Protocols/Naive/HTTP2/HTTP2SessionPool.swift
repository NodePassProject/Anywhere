//
//  HTTP2SessionPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/18/26.
//

import Foundation

private let logger = AnywhereLogger(category: "HTTP2Pool")

/// Pools ``HTTP2Session`` instances for reuse across CONNECT tunnels.
///
/// Sessions are keyed by `host:port:sni`. When a new stream is requested the
/// pool returns an existing session with available capacity, or creates a new
/// one. This mirrors Chromium's `SpdySessionPool`, which lets many CONNECT
/// tunnels share a single TCP/TLS connection.
///
/// When a session receives GOAWAY or the transport closes, the pool evicts it
/// automatically via the session's `onClose` callback.
nonisolated final class HTTP2SessionPool: SessionPool<HTTP2Session> {

    static let shared = HTTP2SessionPool()

    /// Dedicated (non-pooled) sessions for chained connections, plus
    /// post-GOAWAY sessions that need to stay alive while their existing
    /// streams drain. Retained here so the session isn't deallocated while
    /// streams are still in use.
    private var dedicatedSessions: [ObjectIdentifier: HTTP2Session] = [:]

    private override init() {}

    // MARK: - Acquire

    /// Returns an ``HTTP2Stream`` on a pooled (or new) session.
    ///
    /// For direct connections (`tunnel == nil`), sessions are pooled by server
    /// identity so multiple CONNECT tunnels share a single HTTP/2 connection.
    /// For chained connections (`tunnel != nil`), a dedicated session is
    /// created because the transport path is unique.
    ///
    /// - Parameters:
    ///   - host: Proxy server address (IP or hostname).
    ///   - port: Proxy server port.
    ///   - sni: TLS SNI value.
    ///   - tunnel: Optional outer proxy connection (for proxy chaining).
    ///   - configuration: NaiveProxy configuration (credentials, etc.).
    ///   - destination: The `host:port` target for the CONNECT tunnel.
    ///   - completion: Called with the ready-to-use stream.
    func acquireStream(
        host: String,
        port: UInt16,
        sni: String,
        tunnel: ProxyConnection?,
        configuration: NaiveConfiguration,
        destination: String,
        completion: @escaping (HTTP2Stream) -> Void
    ) {
        // Chained connections cannot be pooled (each outer tunnel is unique).
        if tunnel != nil {
            let session = HTTP2Session(
                host: host, port: port, sni: sni,
                tunnel: tunnel, configuration: configuration
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
                logger.info("[HTTP2Pool] Evicted dedicated session")
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
        // Move post-GOAWAY sessions out of the pool into dedicatedSessions so
        // they stay alive until their existing streams drain, then evict any
        // closed or going-away entries from the active bucket.
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
                tunnel: nil, configuration: configuration
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

    /// Drops the bucket entry plus any draining-after-GOAWAY copy in
    /// ``dedicatedSessions``.
    override func removeSession(_ session: HTTP2Session, key: String) {
        super.removeSession(session, key: key)
        lock.lock()
        dedicatedSessions.removeValue(forKey: ObjectIdentifier(session))
        lock.unlock()
        logger.info("[HTTP2Pool] Evicted session for \(key)")
    }

    /// Closes pooled and dedicated sessions on VPN tunnel teardown.
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
