//
//  NGTCP2ConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/15/26.
//

import Foundation

nonisolated final class NGTCP2ConcurrencyBridge: @unchecked Sendable {

    /// This connection's serial executor. Everything ngtcp2-touching runs on its queue.
    let executor: BridgeExecutor

    init(label: String) {
        self.executor = BridgeExecutor(label: label)
    }

    /// The ngtcp2 serial queue, vended by ``executor``. Timers and the carrier target it.
    var queue: DispatchQueue { executor.queue }

    /// True when the caller already runs on ``queue`` — the on-queue fast paths and the
    /// deferred-teardown guard both branch on it.
    var isOnQueue: Bool { executor.isOnQueue }

    // MARK: - Async hop

    /// Runs `body` on the ngtcp2 queue and resumes the caller with its result — for the
    /// off-queue readers that must observe queue-confined ngtcp2 state.
    func run<T>(_ body: @escaping () -> T) async -> T {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { continuation.resume(returning: body()) }
        }
    }

    // MARK: - Reentrancy

    /// True while a `conn`-holding ngtcp2 batch is on the stack; ``QUICConnection/close(error:)``
    /// defers a queue cycle when set so `ngtcp2_conn_del` can't free `conn` under the batch.
    /// queue-confined.
    private(set) var connHeld = false

    /// Marks `conn` held on the stack, returning the previous state to restore. Pair with
    /// ``exitConnHeld(_:)`` — a `defer` for whole-batch scopes, an explicit call around a
    /// single ngtcp2 call — so nested batches compose:
    ///
    ///     let held = bridge.enterConnHeld(); defer { bridge.exitConnHeld(held) }
    func enterConnHeld() -> Bool {
        let previous = connHeld
        connHeld = true
        return previous
    }

    /// Restores the conn-held state captured by ``enterConnHeld()``.
    func exitConnHeld(_ previous: Bool) {
        connHeld = previous
    }

    // MARK: - Conn-ref context
    //
    // ngtcp2's `ngtcp2_crypto_conn_ref.user_data` (also handed to the crypto callbacks)
    // carries an **unretained** back-reference to the owning ``QUICConnection`` — the
    // connection owns the `ngtcp2_conn` and outlives it, driving `ngtcp2_conn_del` itself.
    // These wrap the pointer round-trip so the connection layer never touches
    // ``BridgeContext`` directly.

    /// The `user_data` pointer to store in `ngtcp2_crypto_conn_ref` (unretained).
    static func connRefContext(_ connection: QUICConnection) -> UnsafeMutableRawPointer {
        BridgeContext.passUnretained(connection)
    }

    /// Recovers the connection behind a conn-ref / crypto-callback `user_data` pointer.
    static func connection(from userData: UnsafeMutableRawPointer) -> QUICConnection {
        BridgeContext.unretained(userData, as: QUICConnection.self)
    }

    // MARK: - Connection operations
    //
    // Thin wrappers over the `ngtcp2_conn_*` / `ngtcp2_swift_conn_*` entry points the
    // connection core drives, so ``QUICConnection``'s own read/write/timer/stream logic
    // names no ngtcp2 symbol. `conn` is the `ngtcp2_conn *`, owned by the connection and
    // valid only on ``queue``; all of these run there. (The one-time `conn_client_new`
    // construction and the TLS/crypto callbacks stay with their layers.)

    /// Opens a client-initiated bidirectional stream; returns its id, or `nil` if blocked.
    func openBidiStream(_ conn: OpaquePointer) -> Int64? {
        var streamId: Int64 = -1
        return ngtcp2_conn_open_bidi_stream(conn, &streamId, nil) == 0 ? streamId : nil
    }

    /// Opens a client-initiated unidirectional stream; returns its id, or `nil` if blocked.
    func openUniStream(_ conn: OpaquePointer) -> Int64? {
        var streamId: Int64 = -1
        return ngtcp2_conn_open_uni_stream(conn, &streamId, nil) == 0 ? streamId : nil
    }

    /// Additional bidirectional streams the local endpoint may still open.
    func streamsBidiLeft(_ conn: OpaquePointer) -> UInt64 {
        ngtcp2_conn_get_streams_bidi_left2(conn)
    }

    /// Extends stream- and connection-level flow control after the app consumes `count` bytes.
    func extendOffsets(_ conn: OpaquePointer, stream: Int64, count: Int) {
        ngtcp2_conn_extend_max_stream_offset(conn, stream, UInt64(count))
        ngtcp2_conn_extend_max_offset(conn, UInt64(count))
    }

    /// Sends RESET_STREAM + STOP_SENDING with the given application error code.
    func shutdownStream(_ conn: OpaquePointer, stream: Int64, appErrorCode: UInt64) {
        ngtcp2_conn_shutdown_stream(conn, 0, stream, appErrorCode)
    }

    /// The peer's decoded transport parameters, or `nil` before the handshake supplies them.
    func remoteTransportParams(_ conn: OpaquePointer) -> UnsafePointer<ngtcp2_transport_params>? {
        ngtcp2_swift_conn_get_remote_transport_params(conn)
    }

    /// The path's current max tx UDP payload size (bytes).
    func pathMaxTxUDPPayload(_ conn: OpaquePointer) -> Int {
        Int(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn))
    }

    /// The connection-close error the peer (or transport) reported, if any.
    func closeError(_ conn: OpaquePointer) -> UnsafePointer<ngtcp2_ccerr>? {
        ngtcp2_conn_get_ccerr(conn)
    }

    /// Frees the `ngtcp2_conn`. The caller must ensure no batch still holds it (see
    /// ``enterConnHeld()``).
    func deleteConn(_ conn: OpaquePointer) {
        ngtcp2_conn_del(conn)
    }

    /// Installs the keep-alive PING interval that detects silently-broken UDP paths.
    func setKeepAliveTimeout(_ conn: OpaquePointer, _ timeout: ngtcp2_duration) {
        ngtcp2_conn_set_keep_alive_timeout(conn, timeout)
    }

    /// Points ngtcp2 at the negotiated TLS cipher-suite handle.
    func setTLSNativeHandle(_ conn: OpaquePointer, _ handle: UnsafeMutableRawPointer?) {
        ngtcp2_conn_set_tls_native_handle(conn, handle)
    }

    // MARK: Timer driving

    /// The next timeout deadline (ngtcp2 timestamp), or `UInt64.max` when none is pending.
    func expiry(_ conn: OpaquePointer) -> ngtcp2_tstamp {
        ngtcp2_conn_get_expiry(conn)
    }

    /// Services expired timers (loss detection, PTO, keep-alive); returns ngtcp2's `err_t`.
    func handleExpiry(_ conn: OpaquePointer, ts: ngtcp2_tstamp) -> Int32 {
        ngtcp2_conn_handle_expiry(conn, ts)
    }

    /// Updates the pacer's next send time; without it the pacer disables and bursts cwnd-wide.
    func updatePacketTxTime(_ conn: OpaquePointer, ts: ngtcp2_tstamp) {
        ngtcp2_conn_update_pkt_tx_time(conn, ts)
    }

    // MARK: Migration

    /// Immediately switches the active path (reactive migration); returns ngtcp2's `err_t`.
    func initiateImmediateMigration(_ conn: OpaquePointer,
                                    path: UnsafeMutablePointer<ngtcp2_path>,
                                    ts: ngtcp2_tstamp) -> Int32 {
        ngtcp2_conn_initiate_immediate_migration(conn, path, ts)
    }

    /// Begins validating a new path before switching (proactive migration); returns `err_t`.
    func initiateMigration(_ conn: OpaquePointer,
                           path: UnsafeMutablePointer<ngtcp2_path>,
                           ts: ngtcp2_tstamp) -> Int32 {
        ngtcp2_conn_initiate_migration(conn, path, ts)
    }

    // MARK: Read / write

    /// Feeds one received datagram into the connection; returns ngtcp2's `err_t`.
    func readPacket(_ conn: OpaquePointer,
                    path: UnsafeMutablePointer<ngtcp2_path>,
                    pktInfo: UnsafeMutablePointer<ngtcp2_pkt_info>,
                    data: UnsafePointer<UInt8>, count: Int, ts: ngtcp2_tstamp) -> Int32 {
        ngtcp2_swift_conn_read_pkt(conn, path, pktInfo, data, count, ts)
    }

    /// Writes the next outgoing packet into `dest`; returns bytes written or a negative `err_t`.
    func writePacket(_ conn: OpaquePointer,
                     path: UnsafeMutablePointer<ngtcp2_path>,
                     pktInfo: UnsafeMutablePointer<ngtcp2_pkt_info>,
                     dest: UnsafeMutablePointer<UInt8>?, destCapacity: Int,
                     ts: ngtcp2_tstamp) -> ngtcp2_ssize {
        ngtcp2_swift_conn_write_pkt(conn, path, pktInfo, dest, destCapacity, ts)
    }

    /// Writes stream data into a packet; `dataLength` receives bytes accepted from `vec`.
    func writeStream(_ conn: OpaquePointer,
                     path: UnsafeMutablePointer<ngtcp2_path>,
                     pktInfo: UnsafeMutablePointer<ngtcp2_pkt_info>,
                     dest: UnsafeMutablePointer<UInt8>?, destCapacity: Int,
                     dataLength: UnsafeMutablePointer<ngtcp2_ssize>, flags: UInt32,
                     stream: Int64, vec: UnsafePointer<ngtcp2_vec>, vecCount: Int,
                     ts: ngtcp2_tstamp) -> ngtcp2_ssize {
        ngtcp2_swift_conn_writev_stream(conn, path, pktInfo, dest, destCapacity,
                                        dataLength, flags, stream, vec, vecCount, ts)
    }

    /// Writes a DATAGRAM frame into a packet; `accepted` receives whether it was queued.
    func writeDatagram(_ conn: OpaquePointer,
                       path: UnsafeMutablePointer<ngtcp2_path>,
                       pktInfo: UnsafeMutablePointer<ngtcp2_pkt_info>,
                       dest: UnsafeMutablePointer<UInt8>?, destCapacity: Int,
                       accepted: UnsafeMutablePointer<Int32>, flags: UInt32,
                       datagramId: UInt64, data: UnsafePointer<UInt8>, dataLength: Int,
                       ts: ngtcp2_tstamp) -> ngtcp2_ssize {
        ngtcp2_swift_conn_write_datagram(conn, path, pktInfo, dest, destCapacity,
                                         accepted, flags, datagramId, data, dataLength, ts)
    }

    // MARK: Diagnostics

    /// The human-readable name for an ngtcp2 error code.
    nonisolated func errorString(_ code: Int32) -> String {
        String(cString: ngtcp2_strerror(code))
    }
}
