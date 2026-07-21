//
//  QUICConnection+NGTCP2.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation

extension QUICConnection {

    // MARK: - Construction
    
    func createClientConn(
        dcid: inout ngtcp2_cid,
        scid: inout ngtcp2_cid,
        localAddr: inout sockaddr_storage,
        remoteAddr: inout sockaddr_storage,
        addrLen: Int, version: UInt32,
        callbacks: inout ngtcp2_callbacks,
        settings: inout ngtcp2_settings,
        pmtudProbes: [UInt16]?,
        params: inout ngtcp2_transport_params,
        connRef: inout ngtcp2_crypto_conn_ref
    ) -> (conn: OpaquePointer?, rv: Int32) {
        withUnsafeMutablePointer(to: &localAddr) { lp in
            withUnsafeMutablePointer(to: &remoteAddr) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen)
                    ),
                    remote: ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen)
                    ),
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
                return pmtudProbes.withUnsafeBufferPointer { probes in
                    settings.pmtud_probes = probes.baseAddress
                    settings.pmtud_probeslen = probes.count
                    return build()
                }
            }
        }
    }
    
    func defaultSettings() -> ngtcp2_settings {
        var settings = ngtcp2_settings()
        ngtcp2_swift_settings_default(&settings)
        return settings
    }
    
    func defaultTransportParams() -> ngtcp2_transport_params {
        var params = ngtcp2_transport_params()
        ngtcp2_swift_transport_params_default(&params)
        return params
    }

    // MARK: - Brutal congestion control
    
    func installBrutal(_ conn: OpaquePointer) -> OpaquePointer? {
        ngtcp2_swift_install_brutal(conn)
    }
    
    func uninstallBrutal(_ conn: OpaquePointer) {
        ngtcp2_swift_uninstall_brutal(conn)
    }

    // MARK: - Connection operations
    
    func openBidiStream(_ conn: OpaquePointer) -> Int64? {
        var streamId: Int64 = -1
        return ngtcp2_conn_open_bidi_stream(conn, &streamId, nil) == 0 ? streamId : nil
    }
    
    func openUniStream(_ conn: OpaquePointer) -> Int64? {
        var streamId: Int64 = -1
        return ngtcp2_conn_open_uni_stream(conn, &streamId, nil) == 0 ? streamId : nil
    }
    
    func streamsBidiLeft(_ conn: OpaquePointer) -> UInt64 {
        ngtcp2_conn_get_streams_bidi_left2(conn)
    }
    
    func extendOffsets(_ conn: OpaquePointer, stream: Int64, count: Int) {
        ngtcp2_conn_extend_max_stream_offset(conn, stream, UInt64(count))
        ngtcp2_conn_extend_max_offset(conn, UInt64(count))
    }
    
    func shutdownStream(_ conn: OpaquePointer, stream: Int64, appErrorCode: UInt64) {
        ngtcp2_conn_shutdown_stream(conn, 0, stream, appErrorCode)
    }
    
    func remoteTransportParams(_ conn: OpaquePointer) -> UnsafePointer<ngtcp2_transport_params>? {
        ngtcp2_swift_conn_get_remote_transport_params(conn)
    }
    
    func pathMaxTxUDPPayload(_ conn: OpaquePointer) -> Int {
        Int(ngtcp2_conn_get_path_max_tx_udp_payload_size(conn))
    }
    
    func closeError(_ conn: OpaquePointer) -> UnsafePointer<ngtcp2_ccerr>? {
        ngtcp2_conn_get_ccerr(conn)
    }
    
    func deleteConn(_ conn: OpaquePointer) {
        ngtcp2_conn_del(conn)
    }
    
    func setKeepAliveTimeout(_ conn: OpaquePointer, _ timeout: ngtcp2_duration) {
        ngtcp2_conn_set_keep_alive_timeout(conn, timeout)
    }
    
    func setTLSNativeHandle(_ conn: OpaquePointer, _ handle: UnsafeMutableRawPointer?) {
        ngtcp2_conn_set_tls_native_handle(conn, handle)
    }

    // MARK: - Timer driving
    
    func expiry(_ conn: OpaquePointer) -> ngtcp2_tstamp {
        ngtcp2_conn_get_expiry(conn)
    }
    
    func handleExpiry(_ conn: OpaquePointer, ts: ngtcp2_tstamp) -> Int32 {
        ngtcp2_conn_handle_expiry(conn, ts)
    }
    
    func updatePacketTxTime(_ conn: OpaquePointer, ts: ngtcp2_tstamp) {
        ngtcp2_conn_update_pkt_tx_time(conn, ts)
    }

    // MARK: - Migration
    
    func initiateImmediateMigration(
        _ conn: OpaquePointer,
        localAddr: sockaddr_storage,
        remoteAddr: sockaddr_storage,
        addrLen: Int,
        ts: ngtcp2_tstamp
    ) -> Int32 {
        withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
            ngtcp2_conn_initiate_immediate_migration(conn, pathPtr, ts)
        }
    }
    
    func initiateMigration(
        _ conn: OpaquePointer,
        localAddr: sockaddr_storage,
        remoteAddr: sockaddr_storage,
        addrLen: Int,
        ts: ngtcp2_tstamp
    ) -> Int32 {
        withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
            ngtcp2_conn_initiate_migration(conn, pathPtr, ts)
        }
    }

    // MARK: - Path marshaling
    
    private func withPath<R>(
        local: sockaddr_storage,
        remote: sockaddr_storage,
        addrLen: Int,
        _ body: (UnsafeMutablePointer<ngtcp2_path>) -> R
    ) -> R {
        var local = local
        var remote = remote
        return withUnsafeMutablePointer(to: &local) { lp in
            withUnsafeMutablePointer(to: &remote) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen)
                    ),
                    remote: ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen)
                    ),
                    user_data: nil
                )
                return withUnsafeMutablePointer(to: &path) { body($0) }
            }
        }
    }
    
    private func writeReportingLocal<R>(
        _ chosenLocal: inout sockaddr_storage,
        _ body: (UnsafeMutablePointer<ngtcp2_path>) -> R
    ) -> R {
        var local = sockaddr_storage()
        var remote = sockaddr_storage()
        let cap = ngtcp2_socklen(MemoryLayout<sockaddr_storage>.size)
        let result = withUnsafeMutablePointer(to: &local) { lp in
            withUnsafeMutablePointer(to: &remote) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                        addrlen: cap
                    ),
                    remote: ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                        addrlen: cap
                    ),
                    user_data: nil
                )
                return withUnsafeMutablePointer(to: &path) { body($0) }
            }
        }
        chosenLocal = local
        return result
    }

    // MARK: - Read / write
    
    func readPacket(
        _ conn: OpaquePointer,
        localAddr: sockaddr_storage,
        remoteAddr: sockaddr_storage,
        addrLen: Int,
        pktInfo: inout ngtcp2_pkt_info,
        data: UnsafePointer<UInt8>,
        count: Int,
        ts: ngtcp2_tstamp) -> Int32 {
            withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
                ngtcp2_swift_conn_read_pkt(conn, pathPtr, &pktInfo, data, count, ts)
        }
    }
    
    func writePacket(
        _ conn: OpaquePointer,
        chosenLocalAddr: inout sockaddr_storage,
        pktInfo: inout ngtcp2_pkt_info,
        dest: UnsafeMutablePointer<UInt8>?,
        destCapacity: Int,
        ts: ngtcp2_tstamp
    ) -> ngtcp2_ssize {
        writeReportingLocal(&chosenLocalAddr) { pathPtr in
            ngtcp2_swift_conn_write_pkt(conn, pathPtr, &pktInfo, dest, destCapacity, ts)
        }
    }
    
    func writeStream(
        _ conn: OpaquePointer,
        chosenLocalAddr: inout sockaddr_storage,
        pktInfo: inout ngtcp2_pkt_info,
        dest: UnsafeMutablePointer<UInt8>?,
        destCapacity: Int,
        dataLength: inout ngtcp2_ssize,
        flags: UInt32,
        stream: Int64,
        src: UnsafePointer<UInt8>,
        srcLen: Int,
        ts: ngtcp2_tstamp
    ) -> ngtcp2_ssize {
        var vec = ngtcp2_vec(base: UnsafeMutablePointer(mutating: src), len: srcLen)
        return writeReportingLocal(&chosenLocalAddr) { pathPtr in
            ngtcp2_swift_conn_writev_stream(conn, pathPtr, &pktInfo, dest, destCapacity, &dataLength, flags, stream, &vec, 1, ts)
        }
    }
    
    func writeDatagram(
        _ conn: OpaquePointer,
        chosenLocalAddr: inout sockaddr_storage,
        pktInfo: inout ngtcp2_pkt_info,
        dest: UnsafeMutablePointer<UInt8>?,
        destCapacity: Int,
        accepted: inout Int32,
        flags: UInt32,
        datagramId: UInt64,
        data: UnsafePointer<UInt8>,
        dataLength: Int,
        ts: ngtcp2_tstamp
    ) -> ngtcp2_ssize {
        writeReportingLocal(&chosenLocalAddr) { pathPtr in
            ngtcp2_swift_conn_write_datagram(conn, pathPtr, &pktInfo, dest, destCapacity, &accepted, flags, datagramId, data, dataLength, ts)
        }
    }

    // MARK: - Diagnostics
    
    nonisolated func errorString(_ code: Int32) -> String {
        String(cString: ngtcp2_strerror(code))
    }
}
