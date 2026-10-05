//
//  QUICConnection+BridgeHost.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Synchronization
import AnywhereQUIC

extension QUICConnection {

    // MARK: Engine events

    func drainEngineEvents(_ engine: AnywhereQUIC.QUICConnection) {
        while phase != .closed, let event = engine.nextEvent() {
            switch event {
            case .handshakeCompleted, .handshakeConfirmed, .streamOpened:
                break
            case .streamData(let id, let data, let fin):
                deliverStreamData(streamId: Int64(id.rawValue), data: data, fin: fin)
            case .datagramReceived(let data):
                deliverDatagram(data)
            case .streamWritable:
                scheduleFlush()
            case .streamLimitUpdated(let bidirectional, let maximum):
                if bidirectional { deliverBidiCredit(maxStreams: maximum) }
            case .streamReset(let id, let code, _):
                handleStreamReset(streamId: Int64(id.rawValue), appErrorCode: code)
            case .streamSendingStopped(let id, let code):
                failStreamSendQueue(streamId: Int64(id.rawValue), error: AnywhereError.quic(.streamReset(applicationCode: code)))
            case .streamClosed(let id, let code):
                handleStreamClose(streamId: Int64(id.rawValue), appErrorCode: code ?? 0, hasAppError: code != nil)
            case .pathValidated(let path):
                handlePathValidation(result: .success, pathLocal: path.local)
            case .pathValidationFailed(let path):
                handlePathValidation(result: .failure, pathLocal: path.local)
            case .pathValidationAborted(let path):
                handlePathValidation(result: .aborted, pathLocal: path.local)
            case .connectionClosed(let reason):
                performTeardown(error: connectionError(reason))
            }
        }
        if phase == .handshaking, engine.state == .established, engine.isHandshakeComplete {
            handleHandshakeCompleted()
        }
    }

    func connectionError(_ reason: QUICConnectionCloseReason) -> Error {
        switch reason {
        case .peerTransportError(let code, _, _) where code.rawValue == 0:
            return AnywhereError.quic(.closed(graceful: true))
        case .peerApplicationError(let code, _) where Self.isBenignCloseCode(code):
            return AnywhereError.quic(.closed(graceful: true))
        case .tlsError(let error):
            return error
        case .handshakeTimeout:
            return AnywhereError.quic(.handshakeFailed(detail: "QUIC handshake timed out"))
        default:
            return AnywhereError.quic(.connectionFailed(detail: String(describing: reason)))
        }
    }

    nonisolated private static func isBenignCloseCode(_ code: UInt64) -> Bool {
        code == 0x00 || code == 0x100
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
