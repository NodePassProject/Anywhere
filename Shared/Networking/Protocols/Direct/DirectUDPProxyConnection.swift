//
//  DirectUDPProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Wraps a `RawUDPSocket` as a `ProxyConnection` with pull-based `receive`
/// semantics. The socket's push-based receive loop is armed lazily on the
/// first `receiveRaw` call; incoming datagrams are queued or delivered into
/// a parked completion.
nonisolated final class DirectUDPProxyConnection: ProxyConnection {

    private let socket: RawUDPSocket

    private let recvLock = UnfairLock()
    private var recvBuffer: [Data] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var receiveError: Error?
    private var startedReceiving = false
    private var closed = false

    /// Bounds memory under a burst the consumer hasn't drained yet.
    private static let maxBufferedDatagrams = 1024

    init(socket: RawUDPSocket) {
        self.socket = socket
        super.init()
    }

    override var isConnected: Bool { socket.isReady }
    override var deliversDatagrams: Bool { true }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        socket.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        socket.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        recvLock.lock()

        if !startedReceiving {
            startedReceiving = true
            socket.startReceiving(handler: { [weak self] data in
                self?.deliverIncoming(data)
            }, errorHandler: { [weak self] error in
                self?.deliverError(error)
            })
        }

        if !recvBuffer.isEmpty {
            let next = recvBuffer.removeFirst()
            recvLock.unlock()
            completion(next, nil)
            return
        }

        if let err = receiveError {
            receiveError = nil
            recvLock.unlock()
            completion(nil, err)
            return
        }

        if closed {
            recvLock.unlock()
            completion(nil, nil)
            return
        }

        // Single-pending discipline — overlapping receives are an API
        // violation. The previous overwrite-and-forget behavior silently
        // leaked the earlier completion (a closure capturing the UDPFlow's
        // receive loop, which would then hang forever waiting on a result
        // that never came). Swap the stale completion out under the lock
        // and surface a defined error to it so the caller learns.
        let stale = pendingReceive
        pendingReceive = completion
        recvLock.unlock()
        stale?(nil, ProxyError.protocolError("overlapping receiveRaw on Direct UDP"))
    }

    override func cancel() {
        recvLock.lock()
        closed = true
        let parked = pendingReceive
        pendingReceive = nil
        recvBuffer.removeAll()
        recvLock.unlock()

        socket.cancel()
        parked?(nil, nil)
    }

    // MARK: - Private

    private func deliverIncoming(_ data: Data) {
        recvLock.lock()
        if closed {
            recvLock.unlock()
            return
        }
        if let cb = pendingReceive {
            pendingReceive = nil
            recvLock.unlock()
            cb(data, nil)
            return
        }
        // Drop-oldest when the consumer isn't keeping up — UDP is lossy.
        if recvBuffer.count >= Self.maxBufferedDatagrams {
            recvBuffer.removeFirst()
        }
        recvBuffer.append(data)
        recvLock.unlock()
    }

    private func deliverError(_ error: Error) {
        recvLock.lock()
        if closed {
            recvLock.unlock()
            return
        }
        let cb = pendingReceive
        pendingReceive = nil
        // Stash so a future receiveRaw surfaces it if no one was waiting.
        if cb == nil {
            receiveError = error
        }
        recvLock.unlock()
        cb?(nil, error)
    }
}
