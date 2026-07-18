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

    init() {
        self.executor = BridgeExecutor(label: "com.argsment.Anywhere.NGTCP2ConcurrencyBridge")
    }

    /// The ngtcp2 serial queue — bridge-internal; callers enter the domain via ``enqueue``/``run``.
    private var queue: DispatchQueue { executor.queue }

    /// Fire-and-forget hop onto the ngtcp2 queue with a `Sendable`-checked closure — the sanctioned
    /// way for clients to enter the isolation domain instead of reaching for `queue.async` (and the
    /// raw queue's unguarded `.sync`/`.suspend`) directly.
    func enqueue(_ work: @escaping @convention(block) @Sendable () -> Void) {
        queue.async(execute: work)
    }

    /// True when the caller already runs on ``queue`` — the on-queue fast paths and the
    /// deferred-teardown guard both branch on it.
    var isOnQueue: Bool { executor.isOnQueue }

    /// A re-armable one-shot timer firing on ``queue`` for ngtcp2's loss/PTO expiry, so the
    /// connection drives its retransmit deadline without naming a `DispatchSourceTimer`.
    func makeDeadlineTimer(handler: @escaping @Sendable () -> Void) -> BridgeDeadlineTimer {
        executor.makeDeadlineTimer(handler: handler)
    }

    // MARK: - Async hop

    /// Runs `body` on the ngtcp2 queue and resumes the caller with its result — for the
    /// off-queue readers that must observe queue-confined ngtcp2 state.
    func run<T>(_ body: @escaping () -> T) async -> T {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            queue.async { continuation.resume(returning: body()) }
        }
    }

    /// Bridges a single-shot ngtcp2 completion callback into async. The connection stores the
    /// completion `body` receives and a C callback resolves it later on ``queue``, so this is the
    /// irreducible continuation at the ngtcp2 C boundary (connect / stream write / datagram batch);
    /// the completion fires exactly once, so it can't double-resume. `body` hands the completion to
    /// the connection's own callback-form driver.
    func awaitingCompletion(_ body: (@escaping @Sendable (Error?) -> Void) -> Void) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            body { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            }
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

    // MARK: - Construction

    /// Creates the client `ngtcp2_conn` over an initial path built from `localAddr`/`remoteAddr`,
    /// wiring the PMTUD probe array's lifetime across the call. Returns the new conn (or `nil`)
    /// and ngtcp2's `err_t`. The raw path/out-pointer juggling stays here at the C boundary.
    func createClientConn(dcid: inout ngtcp2_cid, scid: inout ngtcp2_cid,
                          localAddr: inout sockaddr_storage, remoteAddr: inout sockaddr_storage,
                          addrLen: Int, version: UInt32,
                          callbacks: inout ngtcp2_callbacks, settings: inout ngtcp2_settings,
                          pmtudProbes: [UInt16]?,
                          params: inout ngtcp2_transport_params,
                          connRef: inout ngtcp2_crypto_conn_ref) -> (conn: OpaquePointer?, rv: Int32) {
        withUnsafeMutablePointer(to: &localAddr) { lp in
            withUnsafeMutablePointer(to: &remoteAddr) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                                       addrlen: ngtcp2_socklen(addrLen)),
                    remote: ngtcp2_addr(addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                                        addrlen: ngtcp2_socklen(addrLen)),
                    user_data: nil
                )
                func build() -> (OpaquePointer?, Int32) {
                    var out: OpaquePointer?
                    let rv = ngtcp2_swift_conn_client_new(
                        &out, &dcid, &scid, &path, version,
                        &callbacks, &settings, &params, nil, &connRef
                    )
                    return (out, rv)
                }
                guard let pmtudProbes else { return build() }
                // ngtcp2 copies the probes at conn-new time; they need only outlive this call.
                return pmtudProbes.withUnsafeBufferPointer { probes in
                    settings.pmtud_probes = probes.baseAddress
                    settings.pmtud_probeslen = probes.count
                    return build()
                }
            }
        }
    }

    /// ngtcp2's default settings, ready for the connection to tune.
    func defaultSettings() -> ngtcp2_settings {
        var settings = ngtcp2_settings()
        ngtcp2_swift_settings_default(&settings)
        return settings
    }

    /// ngtcp2's default transport parameters, ready for the connection to tune.
    func defaultTransportParams() -> ngtcp2_transport_params {
        var params = ngtcp2_transport_params()
        ngtcp2_swift_transport_params_default(&params)
        return params
    }

    // MARK: - Brutal congestion control

    /// Installs the Brutal CC algorithm on `conn`; returns its `ngtcp2_cc *` registry key, or `nil`.
    func installBrutal(_ conn: OpaquePointer) -> OpaquePointer? {
        ngtcp2_swift_install_brutal(conn)
    }

    /// Reverts `conn` to the library's default CC (undoes ``installBrutal(_:)``).
    func uninstallBrutal(_ conn: OpaquePointer) {
        ngtcp2_swift_uninstall_brutal(conn)
    }

    // MARK: - Connection operations
    //
    // Thin wrappers over the `ngtcp2_conn_*` / `ngtcp2_swift_conn_*` entry points the
    // connection core drives, so ``QUICConnection``'s own read/write/timer/stream logic
    // names no ngtcp2 symbol. `conn` is the `ngtcp2_conn *`, owned by the connection and
    // valid only on ``queue``; all of these run there. (The TLS/crypto callbacks stay with
    // their layers.)

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
                                    localAddr: sockaddr_storage, remoteAddr: sockaddr_storage,
                                    addrLen: Int, ts: ngtcp2_tstamp) -> Int32 {
        withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
            ngtcp2_conn_initiate_immediate_migration(conn, pathPtr, ts)
        }
    }

    /// Begins validating a new path before switching (proactive migration); returns `err_t`.
    func initiateMigration(_ conn: OpaquePointer,
                           localAddr: sockaddr_storage, remoteAddr: sockaddr_storage,
                           addrLen: Int, ts: ngtcp2_tstamp) -> Int32 {
        withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
            ngtcp2_conn_initiate_migration(conn, pathPtr, ts)
        }
    }

    // MARK: Path marshaling (library boundary)

    /// Builds an `ngtcp2_path` over pinned copies of `local`/`remote` and runs `body` with it.
    /// ngtcp2 copies the addrs internally, so the copies need only outlive the call. Kept in the
    /// bridge so the raw `sockaddr`/`ngtcp2_path` pointer juggling stays at the C boundary.
    private func withPath<R>(local: sockaddr_storage, remote: sockaddr_storage, addrLen: Int,
                             _ body: (UnsafeMutablePointer<ngtcp2_path>) -> R) -> R {
        var local = local
        var remote = remote
        return withUnsafeMutablePointer(to: &local) { lp in
            withUnsafeMutablePointer(to: &remote) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                                       addrlen: ngtcp2_socklen(addrLen)),
                    remote: ngtcp2_addr(addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                                        addrlen: ngtcp2_socklen(addrLen)),
                    user_data: nil
                )
                return withUnsafeMutablePointer(to: &path) { body($0) }
            }
        }
    }

    /// Runs an ngtcp2 *write* (`body`) with an `ngtcp2_path` over owned capacity buffers, copying
    /// back into `chosenLocal` the local address ngtcp2 reported for the packet — the connection maps
    /// that to a carrier. The buffers are mandatory: every write copies the chosen 4-tuple into
    /// `path`, so NULL would crash.
    private func writeReportingLocal<R>(_ chosenLocal: inout sockaddr_storage,
                                        _ body: (UnsafeMutablePointer<ngtcp2_path>) -> R) -> R {
        var local = sockaddr_storage()
        var remote = sockaddr_storage()
        let cap = ngtcp2_socklen(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &local) { lp in
            withUnsafeMutablePointer(to: &remote) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                                       addrlen: cap),
                    remote: ngtcp2_addr(addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                                        addrlen: cap),
                    user_data: nil
                )
                return withUnsafeMutablePointer(to: &path) { body($0) }
            }
        }
        chosenLocal = local
        return result
    }

    // MARK: Read / write

    /// Feeds one received datagram into the connection over the given fixed path; returns ngtcp2's `err_t`.
    func readPacket(_ conn: OpaquePointer,
                    localAddr: sockaddr_storage, remoteAddr: sockaddr_storage, addrLen: Int,
                    pktInfo: inout ngtcp2_pkt_info,
                    data: UnsafePointer<UInt8>, count: Int, ts: ngtcp2_tstamp) -> Int32 {
        withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
            ngtcp2_swift_conn_read_pkt(conn, pathPtr, &pktInfo, data, count, ts)
        }
    }

    /// Writes the next outgoing packet into `dest`; returns bytes written or a negative `err_t`.
    /// `chosenLocalAddr` receives the local address ngtcp2 attributed the packet to.
    func writePacket(_ conn: OpaquePointer,
                     chosenLocalAddr: inout sockaddr_storage,
                     pktInfo: inout ngtcp2_pkt_info,
                     dest: UnsafeMutablePointer<UInt8>?, destCapacity: Int,
                     ts: ngtcp2_tstamp) -> ngtcp2_ssize {
        writeReportingLocal(&chosenLocalAddr) { pathPtr in
            ngtcp2_swift_conn_write_pkt(conn, pathPtr, &pktInfo, dest, destCapacity, ts)
        }
    }

    /// Writes stream data into a packet from `src`; `dataLength` receives bytes accepted.
    /// `chosenLocalAddr` receives the local address ngtcp2 attributed the packet to.
    func writeStream(_ conn: OpaquePointer,
                     chosenLocalAddr: inout sockaddr_storage,
                     pktInfo: inout ngtcp2_pkt_info,
                     dest: UnsafeMutablePointer<UInt8>?, destCapacity: Int,
                     dataLength: inout ngtcp2_ssize, flags: UInt32, stream: Int64,
                     src: UnsafePointer<UInt8>, srcLen: Int, ts: ngtcp2_tstamp) -> ngtcp2_ssize {
        var vec = ngtcp2_vec(base: UnsafeMutablePointer(mutating: src), len: srcLen)
        return writeReportingLocal(&chosenLocalAddr) { pathPtr in
            ngtcp2_swift_conn_writev_stream(conn, pathPtr, &pktInfo, dest, destCapacity,
                                            &dataLength, flags, stream, &vec, 1, ts)
        }
    }

    /// Writes a DATAGRAM frame into a packet; `accepted` receives whether it was queued.
    /// `chosenLocalAddr` receives the local address ngtcp2 attributed the packet to.
    func writeDatagram(_ conn: OpaquePointer,
                       chosenLocalAddr: inout sockaddr_storage,
                       pktInfo: inout ngtcp2_pkt_info,
                       dest: UnsafeMutablePointer<UInt8>?, destCapacity: Int,
                       accepted: inout Int32, flags: UInt32,
                       datagramId: UInt64, data: UnsafePointer<UInt8>, dataLength: Int,
                       ts: ngtcp2_tstamp) -> ngtcp2_ssize {
        writeReportingLocal(&chosenLocalAddr) { pathPtr in
            ngtcp2_swift_conn_write_datagram(conn, pathPtr, &pktInfo, dest, destCapacity,
                                             &accepted, flags, datagramId, data, dataLength, ts)
        }
    }

    // MARK: Diagnostics

    /// The human-readable name for an ngtcp2 error code.
    nonisolated func errorString(_ code: Int32) -> String {
        String(cString: ngtcp2_strerror(code))
    }
}
