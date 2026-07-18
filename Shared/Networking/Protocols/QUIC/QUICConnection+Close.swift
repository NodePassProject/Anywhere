//
//  QUICConnection+Close.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import CryptoKit
import Synchronization

extension QUICConnection {

    // MARK: Close

    nonisolated func close(error: Error? = nil) {
        // Defer while a ngtcp2 batch still holds the conn pointer on the stack.
        if bridge.connHeld && isOnQueue {
            bridge.enqueue { self.close(error: error) }
            return
        }
        // Strong-capture `self` so teardown runs even when close() is the last reference;
        // synchronous on `queue` so pool state updates before new streams are handed out.
        let teardown: @Sendable () -> Void = { self.assumeIsolated { $0.performTeardown(error: error) } }
        if isOnQueue {
            teardown()
        } else {
            bridge.enqueue(teardown)
        }
    }

    /// The teardown itself, isolated. Entered from ``close(error:)`` on the queue.
    func performTeardown(error: Error?) {
        guard self.state != .closed else { return }
            // Closed before .connected means TLS didn't complete — invalidate the
            // cached ticket, or a rotated-key ticket causes a permanent HANDSHAKE_TIMEOUT loop.
            if self.state != .connected {
                QUICSessionTicketCache.invalidate(serverName: self.serverName, alpn: self.alpn)
            }
            self.retransmitTimer?.cancel()
            self.retransmitTimer = nil
            // Unregister Brutal before ngtcp2_conn_del frees conn->cc, or late
            // trampolines look up a dangling key.
            if let key = self.brutalCCKey {
                BrutalCongestionControl.unregister(cc: key)
                self.brutalCCKey = nil
                self.brutalCC = nil
            }
            if let connectionOpaquePointer = self.connectionOpaquePointer {
                self.bridge.deleteConn(connectionOpaquePointer)
                self.connectionOpaquePointer = nil
            }
            self.transportReceiveTask?.cancel()
            self.transportReceiveTask = nil
            self.transportSealContinuation?.finish()
            self.transportSealContinuation = nil
            self.transportSealTask?.cancel()
            self.transportSealTask = nil
            self.transport?.cancel()
            self.closeCarrier()
            self.state = .closed
            let writes = self.pendingWrites
            self.pendingWrites.removeAll()
            let datagrams = self.pendingDatagrams
            self.pendingDatagrams.removeAll()
            self.inflightStreamBuffers.removeAll()
            self.streamTxOffset.removeAll()
            let closeError = error ?? QUICError.closed
            // Fire any still-pending connect callback — the carrier's non-EAGAIN
            // recv error path calls close() directly.
            if let callback = self.connectCompletion {
                self.connectCompletion = nil
                callback(closeError)
            }
            for pendingWrite in writes { pendingWrite.completion(closeError) }
            for d in datagrams { d.completion?(closeError) }
            // Detach every handler before announcing the close, so nothing fires after it.
            let closedHandler = self.handlers.withLock { current in
                let closed = current.connectionClosed
                current = Handlers()
                return closed
            }
            closedHandler?(closeError)
    }
}
