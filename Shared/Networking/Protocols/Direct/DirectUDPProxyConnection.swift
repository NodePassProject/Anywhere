//
//  DirectUDPProxyConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/19/26.
//

import Foundation

/// Adapts a push-based `NWUDPTransport` to a pull-based `ProxyConnection`; the receive loop is armed lazily on the first `receiveRaw`.
nonisolated final class DirectUDPProxyConnection: ProxyConnection {

    private let transport: NWUDPTransport

    private let recvLock = UnfairLock()
    private var recvBuffer: [Data] = []
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var receiveError: Error?
    private var startedReceiving = false
    private var closed = false

    /// Bounds memory under a burst the consumer hasn't drained yet.
    private static let maxBufferedDatagrams = 1024

    init(transport: NWUDPTransport) {
        self.transport = transport
        super.init()
    }

    override var isConnected: Bool { transport.isReady }
    override var deliversDatagrams: Bool { true }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        transport.send(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        transport.send(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        recvLock.lock()

        if !startedReceiving {
            startedReceiving = true
            transport.startReceiving(handler: { [weak self] data in
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

        if let error = receiveError {
            receiveError = nil
            recvLock.unlock()
            completion(nil, error)
            return
        }

        if closed {
            recvLock.unlock()
            completion(nil, nil)
            return
        }

        // Single-pending discipline: fail any stale overlapping receive instead of letting it hang.
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

        transport.cancel()
        parked?(nil, nil)
    }

    // MARK: - Private

    private func deliverIncoming(_ data: Data) {
        recvLock.lock()
        if closed {
            recvLock.unlock()
            return
        }
        if let callback = pendingReceive {
            pendingReceive = nil
            recvLock.unlock()
            callback(data, nil)
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
        let callback = pendingReceive
        pendingReceive = nil
        if callback == nil {
            receiveError = error
        }
        recvLock.unlock()
        callback?(nil, error)
    }
}
