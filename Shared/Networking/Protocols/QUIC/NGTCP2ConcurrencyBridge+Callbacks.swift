//
//  NGTCP2ConcurrencyBridge+Callbacks.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Security

// MARK: - Host protocol

nonisolated enum NGTCP2PathValidationResult { case success, failure, aborted }

protocol NGTCP2BridgeHost: Actor {

    /// The live `ngtcp2_conn` handle; read by `get_conn`. Isolated.
    var connectionOpaquePointer: OpaquePointer? { get }

    /// Fire-and-forget hop onto the bridge queue — used to defer a callback's effect past the
    /// current ngtcp2 batch (handshake completion, path validation, stream credit).
    nonisolated func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void)

    /// Builds the ClientHello for the encoded local transport `params` (`client_initial`).
    func buildClientHello(transportParams: Data) -> Data?

    /// Feeds received CRYPTO `data` to TLS at `level`; returns ngtcp2's `err_t`.
    func processCryptoData(_ data: Data, level: ngtcp2_encryption_level) -> Int32

    /// Delivers received STREAM bytes — a zero-copy view valid only for this synchronous call.
    func deliverStreamData(streamId: Int64, data: Data, fin: Bool)

    /// Delivers a received DATAGRAM — a zero-copy view valid only for this synchronous call.
    func deliverDatagram(_ data: Data)

    /// The peer raised the cumulative local bidi-stream limit to `maxStreams`.
    func deliverBidiCredit(maxStreams: UInt64)

    /// A contiguous prefix of sent stream data was acked (`ackedOffset` = new acked end).
    func releaseAckedStreamData(streamId: Int64, ackedOffset: UInt64)

    /// Both directions of a stream terminated; `hasAppError` flags an application close code.
    func handleStreamClose(streamId: Int64, appErrorCode: UInt64, hasAppError: Bool)

    /// The peer sent RESET_STREAM with `appErrorCode`.
    func handleStreamReset(streamId: Int64, appErrorCode: UInt64)

    /// The TLS handshake completed.
    func handleHandshakeCompleted()

    /// A migration path finished — or was abandoned during — validation.
    func handlePathValidation(result: NGTCP2PathValidationResult)
}

// MARK: - Host recovery + callback wiring

nonisolated extension NGTCP2ConcurrencyBridge {

    /// Stores an **unretained** back-reference to `host` in `connRef` and installs `get_conn`, which
    /// ngtcp2's crypto layer follows to reach the live `ngtcp2_conn`. The host owns the conn and
    /// outlives it (it drives `ngtcp2_conn_del`), so nothing here is balanced.
    func configureConnRef(_ connRef: inout ngtcp2_crypto_conn_ref, host: any NGTCP2BridgeHost) {
        connRef.user_data = BridgeContext.passUnretained(host as AnyObject)
        connRef.get_conn = { ref in
            guard let ref, let userData = ref.pointee.user_data,
                  let host = NGTCP2ConcurrencyBridge.host(from: userData) else { return nil }
            // ngtcp2 calls get_conn from inside its own calls on the executor; the pointer crosses
            // out of `assumeIsolated` as a plain address (`UInt` is `Sendable`) — same thread.
            let raw = host.assumeIsolated { $0.connectionOpaquePointer.map { UInt(bitPattern: $0) } ?? 0 }
            return OpaquePointer(bitPattern: raw)
        }
    }

    /// Builds the `ngtcp2_callbacks` table: ngtcp2's crypto helpers for the TLS-plumbing slots, and
    /// this file's trampolines for the ones that reach into the host. `recv_datagram` is wired only
    /// when DATAGRAMs are enabled.
    func makeCallbacks(datagramsEnabled: Bool) -> ngtcp2_callbacks {
        var callbacks = ngtcp2_callbacks()
        callbacks.client_initial = ngtcp2ClientInitialCB
        callbacks.recv_crypto_data = ngtcp2RecvCryptoDataCB
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb
        callbacks.recv_stream_data = ngtcp2RecvStreamDataCB
        callbacks.acked_stream_data_offset = ngtcp2AckedCB
        callbacks.stream_close = ngtcp2StreamCloseCB
        callbacks.stream_reset = ngtcp2StreamResetCB
        callbacks.extend_max_local_streams_bidi = ngtcp2BidiCreditCB
        callbacks.rand = ngtcp2RandCB
        callbacks.get_new_connection_id2 = ngtcp2GetNewCIDCB
        callbacks.update_key = ngtcp2_crypto_update_key_cb
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb
        callbacks.handshake_completed = ngtcp2HandshakeCompletedCB
        callbacks.path_validation = ngtcp2PathValidationCB
        if datagramsEnabled {
            callbacks.recv_datagram = ngtcp2RecvDatagramCB
        }
        return callbacks
    }

    /// Recovers the host behind a conn-ref / crypto-callback `user_data` pointer (unretained).
    static func host(from userData: UnsafeMutableRawPointer) -> (any NGTCP2BridgeHost)? {
        BridgeContext.unretained(userData, as: AnyObject.self) as? NGTCP2BridgeHost
    }
}

// MARK: - Trampolines

nonisolated private func hostFromUserData(_ userData: UnsafeMutableRawPointer?) -> (any NGTCP2BridgeHost)? {
    guard let userData else { return nil }
    let ref = userData.assumingMemoryBound(to: ngtcp2_crypto_conn_ref.self)
    guard let p = ref.pointee.user_data else { return nil }
    return NGTCP2ConcurrencyBridge.host(from: p)
}

nonisolated private let ngtcp2StreamCloseFlagAppErrorCodeSet: UInt32 = 0x01

nonisolated private let ngtcp2ClientInitialCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { conn, userData in
    guard let conn else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let dcid = ngtcp2_conn_get_client_initial_dcid(conn) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    let none: UnsafeMutablePointer<UInt8>? = nil
    guard ngtcp2_crypto_derive_and_install_initial_key(
        conn, none, none, none, none, none, none, none, none, none, NGTCP2_PROTO_VER_V1, dcid) == 0 else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    guard let host = hostFromUserData(userData) else { return NGTCP2_ERR_CALLBACK_FAILURE }
    // `conn` is the freshly-minted handle (before the host stores it), so encode/submit ride it here
    // at the C boundary; only the Sendable transport-params / ClientHello `Data` crosses isolation.
    var buffer = [UInt8](repeating: 0, count: 256)
    let length = ngtcp2_conn_encode_local_transport_params(conn, &buffer, buffer.count)
    guard length >= 0 else { return NGTCP2_ERR_CALLBACK_FAILURE }
    let params = Data(buffer.prefix(Int(length)))
    guard let clientHello = host.assumeIsolated({ $0.buildClientHello(transportParams: params) }) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    return clientHello.withUnsafeBytes { raw in
        guard let p = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return NGTCP2_ERR_CALLBACK_FAILURE
        }
        return ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, p, clientHello.count)
    }
}

nonisolated private let ngtcp2RecvCryptoDataCB: @convention(c) (
    OpaquePointer?, ngtcp2_encryption_level, UInt64,
    UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { _, level, _, data, datalen, userData in
    guard let data, datalen > 0 else { return 0 }
    guard let host = hostFromUserData(userData) else { return NGTCP2_ERR_CALLBACK_FAILURE }
    let d = Data(bytes: data, count: datalen)
    return host.assumeIsolated { $0.processCryptoData(d, level: level) }
}

nonisolated private let ngtcp2RecvStreamDataCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, flags, sid, _, data, datalen, userData, _ in
    guard let host = hostFromUserData(userData) else { return 0 }
    let fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0
    if let data, datalen > 0 {
        // Zero-copy view into ngtcp2's buffer; the handler must copy before returning.
        let view = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: data), count: datalen, deallocator: .none)
        host.assumeIsolated { $0.deliverStreamData(streamId: sid, data: view, fin: fin) }
    } else if fin {
        host.assumeIsolated { $0.deliverStreamData(streamId: sid, data: Data(), fin: true) }
    }
    // FC window is extended only when the app consumes data (backpressure).
    return 0
}

nonisolated private let ngtcp2AckedCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, streamId, offset, datalen, userData, _ in
    guard let host = hostFromUserData(userData) else { return 0 }
    host.assumeIsolated { $0.releaseAckedStreamData(streamId: streamId, ackedOffset: offset + datalen) }
    return 0
}

nonisolated private let ngtcp2StreamCloseCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, flags, sid, appErrorCode, userData, _ in
    guard let host = hostFromUserData(userData) else { return 0 }
    let hasAppError = (flags & ngtcp2StreamCloseFlagAppErrorCodeSet) != 0
    host.assumeIsolated { $0.handleStreamClose(streamId: sid, appErrorCode: appErrorCode, hasAppError: hasAppError) }
    return 0
}

nonisolated private let ngtcp2StreamResetCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, sid, _, appErrorCode, userData, _ in
    guard let host = hostFromUserData(userData) else { return 0 }
    host.assumeIsolated { $0.handleStreamReset(streamId: sid, appErrorCode: appErrorCode) }
    return 0
}

nonisolated private let ngtcp2BidiCreditCB: @convention(c) (
    OpaquePointer?, UInt64, UnsafeMutableRawPointer?
) -> Int32 = { _, maxStreams, userData in
    guard let host = hostFromUserData(userData) else { return 0 }
    // Deferred past the current batch so handlers may safely open streams.
    host.enqueue { host.assumeIsolated { $0.deliverBidiCredit(maxStreams: maxStreams) } }
    return 0
}

nonisolated private let ngtcp2RandCB: @convention(c) (
    UnsafeMutablePointer<UInt8>?, Int, UnsafePointer<ngtcp2_rand_ctx>?
) -> Void = { destination, length, _ in
    guard let destination else { return }
    _ = SecRandomCopyBytes(kSecRandomDefault, length, destination)
}

nonisolated private let ngtcp2GetNewCIDCB: @convention(c) (
    OpaquePointer?, UnsafeMutablePointer<ngtcp2_cid>?,
    UnsafeMutablePointer<ngtcp2_stateless_reset_token>?,
    Int, UnsafeMutableRawPointer?
) -> Int32 = { _, cid, token, cidlen, _ in
    guard let cid, let token else { return NGTCP2_ERR_CALLBACK_FAILURE }
    var d = [UInt8](repeating: 0, count: cidlen)
    guard SecRandomCopyBytes(kSecRandomDefault, cidlen, &d) == errSecSuccess else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    cid.pointee.datalen = cidlen
    withUnsafeMutableBytes(of: &cid.pointee.data) { buffer in
        d.withUnsafeBytes { source in
            buffer.copyMemory(from: UnsafeRawBufferPointer(start: source.baseAddress,
                                                           count: min(cidlen, buffer.count)))
        }
    }
    withUnsafeMutableBytes(of: &token.pointee) { buffer in
        _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    return 0
}

nonisolated private let ngtcp2HandshakeCompletedCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, userData in
    guard let host = hostFromUserData(userData) else { return 0 }
    host.enqueue { host.assumeIsolated { $0.handleHandshakeCompleted() } }
    return 0
}

nonisolated private let ngtcp2PathValidationCB: @convention(c) (
    OpaquePointer?, UInt32, UnsafePointer<ngtcp2_path>?, UnsafePointer<ngtcp2_path>?,
    ngtcp2_path_validation_result, UnsafeMutableRawPointer?
) -> Int32 = { _, _, _, _, res, userData in
    guard let host = hostFromUserData(userData) else { return 0 }
    let result: NGTCP2PathValidationResult
    if res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS {
        result = .success
    } else if res == NGTCP2_PATH_VALIDATION_RESULT_FAILURE {
        result = .failure
    } else {
        result = .aborted
    }
    // Deferred off the ngtcp2 batch so promotion/close can re-enter ngtcp2 safely.
    host.enqueue { host.assumeIsolated { $0.handlePathValidation(result: result) } }
    return 0
}

nonisolated private let ngtcp2RecvDatagramCB: @convention(c) (
    OpaquePointer?, UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { _, _, data, datalen, userData in
    guard let data, datalen > 0, let host = hostFromUserData(userData) else { return 0 }
    // Zero-copy view; the handler must not retain it past this synchronous call.
    let view = Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: data), count: datalen, deallocator: .none)
    host.assumeIsolated { $0.deliverDatagram(view) }
    return 0
}
