//
//  HTTP2SessionPool.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/18/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "HTTP2Pool")

/// Pools ``HTTP2Session`` instances for reuse across CONNECT tunnels.
///
/// Sessions are keyed by `host:port:sni`. When a new stream is requested the
/// pool returns an existing session with available capacity, or creates a new
/// one.  This mirrors Chromium's `SpdySessionPool`, which lets many CONNECT
/// tunnels share a single TCP/TLS connection.
///
/// When a session receives GOAWAY or the transport closes, the pool evicts it
/// automatically via the session's `onClose` callback.
class HTTP2SessionPool {

    static let shared = HTTP2SessionPool()

    private let lock = UnfairLock()

    /// Sessions keyed by "host:port:sni".
    private var sessions: [String: [HTTP2Session]] = [:]

    /// Dedicated (non-pooled) sessions for chained connections.
    /// Retained here so the session stays alive while its streams are in use.
    private var dedicatedSessions: [ObjectIdentifier: HTTP2Session] = [:]

    private init() {}

    // MARK: - Acquire

    /// Returns an ``HTTP2Stream`` on a pooled (or new) session.
    ///
    /// For direct connections (`tunnel == nil`), sessions are pooled by server
    /// identity so multiple CONNECT tunnels share a single HTTP/2 connection.
    /// For chained connections (`tunnel != nil`), a dedicated session is created
    /// because the transport path is unique.
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
        // Chained connections cannot be pooled (each outer tunnel is unique)
        guard tunnel == nil else {
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

        let key = "\(host):\(port):\(sni)"
        let session: HTTP2Session

        lock.lock()
        // Evict closed and GOAWAY sessions.
        // GOAWAY sessions move to dedicatedSessions so they stay alive
        // while their existing streams drain.
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

    private func removeSession(_ session: HTTP2Session, key: String) {
        lock.lock()
        sessions[key]?.removeAll { $0 === session }
        if sessions[key]?.isEmpty == true {
            sessions.removeValue(forKey: key)
        }
        // Also clean up if the session was draining after GOAWAY
        dedicatedSessions.removeValue(forKey: ObjectIdentifier(session))
        lock.unlock()
        logger.info("[HTTP2Pool] Evicted session for \(key, privacy: .public)")
    }

    /// Closes all pooled sessions (e.g. on VPN tunnel teardown).
    func closeAll() {
        lock.lock()
        let all = sessions.values.flatMap { $0 }
        let dedicated = Array(dedicatedSessions.values)
        sessions.removeAll()
        dedicatedSessions.removeAll()
        lock.unlock()

        for session in all {
            session.close()
        }
        for session in dedicated {
            session.close()
        }
    }
}
