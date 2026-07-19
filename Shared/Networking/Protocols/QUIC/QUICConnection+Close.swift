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
        if bridge.connHeld && isOnQueue {
            bridge.enqueue { self.close(error: error) }
            return
        }
        let teardown: @Sendable () -> Void = { self.assumeIsolated { $0.performTeardown(error: error) } }
        if isOnQueue {
            teardown()
        } else {
            bridge.enqueue(teardown)
        }
    }
    
    func performTeardown(error: Error?) {
        guard self.state != .closed else { return }
            self.flushStreamDeliveries()
            if self.state != .connected {
                QUICSessionTicketCache.invalidate(serverName: self.serverName, alpn: self.alpn)
            }
            self.retransmitTimer?.cancel()
            self.retransmitTimer = nil
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
            let closeError = error ?? AnywhereError.quic(.closed(graceful: false))
            self.finishConnect(closeError)
            for pendingWrite in writes { pendingWrite.continuation?.resume(throwing: closeError) }
            for d in datagrams { d.latch?.settle(closeError) }
            let closedHandler = self.handlers.withLock { current in
                let closed = current.connectionClosed
                current = Handlers()
                return closed
            }
            closedHandler?(closeError)
    }
}
