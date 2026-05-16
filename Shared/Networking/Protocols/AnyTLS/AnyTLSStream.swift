//
//  AnyTLSStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLSStream")

/// One logical stream multiplexed inside an `AnyTLSSession`.
///
/// Outgoing bytes are wrapped in a `cmdPSH(sid, …)` frame and run through the
/// session's padding-aware writer. Incoming bytes arrive from the session's
/// recv loop via ``deliverData(_:)`` / ``deliverClose(error:)`` and are
/// surfaced through the standard ``ProxyConnection`` receive API: if a
/// callback is already waiting it fires immediately; otherwise the bytes
/// queue until ``receiveRaw(completion:)`` is called.
///
/// Mirrors `session.Stream` in sing-anytls 0.0.11.
nonisolated final class AnyTLSStream: ProxyConnection {

    let sid: UInt32
    private weak var session: AnyTLSSession?

    /// Snapshot of the session's TLS version, captured at construction so
    /// `outerTLSVersion` keeps working after the session goes away.
    private let cachedTLSVersion: TLSVersion?

    private let receiveLock = UnfairLock()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var incoming: [Data] = []
    private var receiveError: Error?
    private var eof: Bool = false

    /// Set true once `cancel()` has run so the session does not echo a FIN
    /// back to itself when it tears the stream down.
    private(set) var locallyCancelled: Bool = false

    /// Fires exactly once when the stream transitions to ended (caller
    /// `cancel()`, inbound cmdFIN, or transport failure). `AnyTLSClient`
    /// uses this to return the underlying session to the idle pool.
    var onEnd: (() -> Void)?

    init(sid: UInt32, session: AnyTLSSession, outerTLSVersion: TLSVersion?) {
        self.sid = sid
        self.session = session
        self.cachedTLSVersion = outerTLSVersion
    }

    override var isConnected: Bool {
        receiveLock.withLock { !eof && receiveError == nil } && (session?.isAlive ?? false)
    }

    override var outerTLSVersion: TLSVersion? { cachedTLSVersion }

    // MARK: Send

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard let session else {
            completion(ProxyError.connectionFailed("AnyTLS session deallocated"))
            return
        }
        session.writeData(sid: sid, data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        session?.writeData(sid: sid, data: data, completion: { _ in })
    }

    // MARK: Receive

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        receiveLock.lock()
        if let error = receiveError {
            receiveLock.unlock()
            completion(nil, error)
            return
        }
        if !incoming.isEmpty {
            let chunk = incoming.removeFirst()
            receiveLock.unlock()
            completion(chunk, nil)
            return
        }
        if eof {
            receiveLock.unlock()
            completion(nil, nil)
            return
        }
        // Stash the callback; the session's recv loop will deliver bytes as
        // they arrive, or signal EOF/error on close.
        pendingReceive = completion
        receiveLock.unlock()
    }

    // MARK: Cancel

    override func cancel() {
        receiveLock.lock()
        let already = locallyCancelled
        locallyCancelled = true
        receiveLock.unlock()
        guard !already else { return }
        logger.debug("[AnyTLSStream] cancel sid=\(sid)")
        session?.streamClosed(sid: sid)
        // Local close is also an end — fire the recycle hook so the
        // session goes back to the idle pool.
        fireOnEndOnce()
    }

    // MARK: - Called by AnyTLSSession on the recv loop

    /// Delivers a payload chunk from a cmdPSH frame addressed to this stream.
    func deliverData(_ data: Data) {
        receiveLock.lock()
        if let cb = pendingReceive {
            pendingReceive = nil
            receiveLock.unlock()
            cb(data, nil)
        } else {
            incoming.append(data)
            receiveLock.unlock()
        }
    }

    /// Delivers a clean EOF (`error == nil`) or transport-level failure
    /// (`error != nil`). After this call the stream rejects further reads.
    func deliverClose(error: Error?) {
        receiveLock.lock()
        if eof || receiveError != nil {
            receiveLock.unlock()
            return
        }
        receiveError = error
        eof = true
        let cb = pendingReceive
        pendingReceive = nil
        receiveLock.unlock()
        let kind = error.map { "error=\($0.localizedDescription)" } ?? "EOF"
        logger.debug("[AnyTLSStream] deliverClose sid=\(sid) \(kind) (pendingRead=\(cb != nil))")
        cb?(nil, error)
        fireOnEndOnce()
    }

    private let endLock = UnfairLock()
    private var endFired = false

    private func fireOnEndOnce() {
        endLock.lock()
        if endFired {
            endLock.unlock()
            return
        }
        endFired = true
        let hook = onEnd
        onEnd = nil
        endLock.unlock()
        hook?()
    }
}
