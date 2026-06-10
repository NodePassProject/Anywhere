//
//  AnyTLSStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/16/26.
//

import Foundation

private let logger = AnywhereLogger(category: "AnyTLSStream")

/// One logical stream multiplexed inside an `AnyTLSSession`.
nonisolated final class AnyTLSStream: ProxyConnection {

    let sid: UInt32
    private weak var session: AnyTLSSession?

    /// Captured at construction so `outerTLSVersion` keeps working after the session goes away.
    private let cachedTLSVersion: TLSVersion?

    private let receiveLock = UnfairLock()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var incoming: [Data] = []
    private var receiveError: Error?
    private var eof: Bool = false

    /// Set by `cancel()` so the session does not echo a FIN back to itself.
    private(set) var locallyCancelled: Bool = false

    /// Fires exactly once when the stream ends; used to return the session to the idle pool.
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
        // Stash the callback; the recv loop delivers bytes or EOF/error later.
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
        // Local close is also an end — fire the recycle hook.
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

    /// Delivers a clean EOF (`nil`) or transport failure; further reads are rejected.
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
