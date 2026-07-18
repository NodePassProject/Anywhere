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

    // MARK: - NGTCP2BridgeHost
    //
    // The semantic ngtcp2 events the bridge's C trampolines dispatch here (entered via
    // `assumeIsolated` on this connection's own executor). Pointer/ABI decoding stays in the bridge;
    // these see only Swift-native, `Sendable` arguments.

    /// QUIC application close codes that mean a graceful end (0 QUIC NO_ERROR / 0x100 H3_NO_ERROR).
    nonisolated private static func isBenignCloseCode(_ code: UInt64) -> Bool {
        code == 0x00 || code == 0x100
    }

    /// Builds the ClientHello for the encoded local transport `params` (`client_initial`).
    func buildClientHello(transportParams: Data) -> Data? {
        tlsHandler?.buildClientHello(transportParams: transportParams)
    }

    /// Feeds received CRYPTO `data` to TLS; the stored conn equals the callback's (recv_crypto_data
    /// fires long after `conn_client_new`). Returns ngtcp2's `err_t`.
    func processCryptoData(_ data: Data, level: ngtcp2_encryption_level) -> Int32 {
        guard let tls = tlsHandler, let conn = connectionOpaquePointer else {
            return NGTCP2_ERR_CALLBACK_FAILURE
        }
        switch tls.processCryptoData(data, level: level, conn: conn) {
        case .success, .needMoreData: return 0
        case .error(let code): return code
        }
    }

    /// Hands received STREAM bytes to the owning session's handler (zero-copy view; it must copy).
    func deliverStreamData(streamId: Int64, data: Data, fin: Bool) {
        handlers.withLock { $0.streamData }?(streamId, data, fin)
    }

    /// Hands a received DATAGRAM to the owning session's handler (zero-copy view; it must copy).
    func deliverDatagram(_ data: Data) {
        handlers.withLock { $0.datagram }?(data)
    }

    /// Notifies the owner the peer raised the cumulative local bidi-stream limit.
    func deliverBidiCredit(maxStreams: UInt64) {
        handlers.withLock { $0.bidiCredit }?(maxStreams)
    }

    /// Both directions of a stream terminated. Pending writes always fail (stream gone), but a
    /// benign code is a clean read-side EOF — only `streamTermination` distinguishes the two.
    func handleStreamClose(streamId: Int64, appErrorCode: UInt64, hasAppError: Bool) {
        let error: Error? = (hasAppError && !Self.isBenignCloseCode(appErrorCode))
            ? QUICError.streamClosedWithError(appErrorCode: appErrorCode)
            : nil
        failPendingWrites(streamId: streamId, error: error ?? QUICError.closed)
        releaseStreamSendState(streamId: streamId)
        handlers.withLock { $0.streamTermination }?(streamId, error)
    }

    /// The peer sent RESET_STREAM (before `stream_close`), so pending receives fail fast.
    func handleStreamReset(streamId: Int64, appErrorCode: UInt64) {
        let error: Error? = Self.isBenignCloseCode(appErrorCode)
            ? nil
            : QUICError.streamReset(appErrorCode: appErrorCode)
        failPendingWrites(streamId: streamId, error: error ?? QUICError.closed)
        handlers.withLock { $0.streamTermination }?(streamId, error)
    }

    /// The TLS handshake completed; the connection is up.
    func handleHandshakeCompleted() {
        state = .connected
        connectCompletion?(nil)
        connectCompletion = nil
    }

}
