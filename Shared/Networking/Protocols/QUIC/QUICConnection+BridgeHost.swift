//
//  QUICConnection+BridgeHost.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import CryptoKit
import Synchronization

extension QUICConnection {

    // MARK: - ngtcp2 callback handlers

    nonisolated private static func isBenignCloseCode(_ code: UInt64) -> Bool {
        code == 0x00 || code == 0x100
    }

    func buildClientHello(transportParams: Data) -> Data? {
        tlsHandler?.buildClientHello(transportParams: transportParams)
    }

    func processCryptoData(_ data: Data, level: ngtcp2_encryption_level) -> Int32 {
        guard let tls = tlsHandler, let conn = connectionOpaquePointer else {
            return NGTCP2_ERR_CALLBACK_FAILURE
        }
        switch tls.processCryptoData(data, level: level, conn: conn) {
        case .success, .needMoreData: return 0
        case .error(let code): return code
        }
    }

    func deliverStreamData(streamId: Int64, data: Data, fin: Bool) {
        handlers.withLock { $0.streamData }?(streamId, data, fin)
    }

    func deliverDatagram(_ data: Data) {
        handlers.withLock { $0.datagram }?(data)
    }

    func deliverBidiCredit(maxStreams: UInt64) {
        handlers.withLock { $0.bidiCredit }?(maxStreams)
    }

    func handleStreamClose(streamId: Int64, appErrorCode: UInt64, hasAppError: Bool) {
        let error: Error? = (hasAppError && !Self.isBenignCloseCode(appErrorCode))
            ? AnywhereError.quic(.streamClosedWithError(applicationCode: appErrorCode))
            : nil
        terminateStreamSendQueue(streamId: streamId, error: error ?? AnywhereError.quic(.closed(graceful: false)))
        handlers.withLock { $0.streamTermination }?(streamId, error, .closed)
    }

    func handleStreamReset(streamId: Int64, appErrorCode: UInt64) {
        let error: Error? = Self.isBenignCloseCode(appErrorCode)
            ? nil
            : AnywhereError.quic(.streamReset(applicationCode: appErrorCode))
        failStreamSendQueue(streamId: streamId, error: error ?? AnywhereError.quic(.closed(graceful: false)))
        handlers.withLock { $0.streamTermination }?(streamId, error, .reset)
    }

    func handleHandshakeCompleted() {
        guard transition(to: .connected) else { return }
        finishConnect(nil)
    }
}
