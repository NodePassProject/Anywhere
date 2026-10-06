//
//  QUICConnection+Close.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Synchronization
import Network
import AnywhereQUIC

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

extension QUICConnectionCore {

    // MARK: Close

    func close(error: Error? = nil) { performTeardown(error: error) }

    func performTeardown(error: Error?) {
        let handshakeFailed = self.phase == .handshaking
        let wasEstablished = self.phase == .connected
        guard transition(to: .closed) else { return }
        if handshakeFailed {
            QUICSessionTicketCache.invalidate(serverName: self.serverName, alpn: self.alpn)
        }
        self.retransmitTimer?.cancel()
        self.retransmitTimer = nil
        self.usesBrutalCC = false
        self.engine = nil
        self.transportSealContinuation?.finish()
        self.transportSealContinuation = nil
        self.rootTask?.cancel()
        self.rootTask = nil
        if let transport { publish { transport.cancel() } }
        self.closeCarrier()
        var failedWriters: [CheckedContinuation<Void, Error>] = []
        for queue in self.streamSendQueues.values {
            failedWriters.append(contentsOf: queue.fail())
        }
        self.streamSendQueues.removeAll()
        let datagrams = self.pendingDatagrams
        self.pendingDatagrams.removeAll()
        let closeError: Error
        if let error {
            if wasEstablished, case AnywhereError.quic(.connectionFailed(_)) = error {
                closeError = AnywhereError.quic(.closed(graceful: false))
            } else {
                closeError = error
            }
        } else {
            closeError = AnywhereError.quic(.closed(graceful: false))
        }
        self.finishConnect(closeError)
        for continuation in failedWriters { continuation.resume(throwing: closeError) }
        for d in datagrams { d.latch?.settle(closeError) }
        let closedHandler = self.handlers.withLock { current in
            let closed = current.connectionClosed
            current = QUICConnection.Handlers()
            return closed
        }
        publish { closedHandler?(closeError) }
    }
}
