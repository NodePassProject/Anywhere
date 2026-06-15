//
//  QUICConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Darwin
import Dispatch
import CryptoKit
import Security

private let logger = AnywhereLogger(category: "QUICConnection")

// MARK: - QUICPortHopping

/// Rotate the UDP destination port across `ports` every `interval`. Transport-level technique
/// (Hysteria's "port hopping"): the server DNATs the whole range to one listening port, so the
/// rotation is invisible to QUIC on both ends. See `HysteriaPortHopping` for the wire format.
struct QUICPortHopping {
    /// Inclusive port ranges to draw from; assumed non-empty.
    let ports: [ClosedRange<UInt16>]
    /// Seconds between hops.
    let interval: TimeInterval

    /// Count of distinct ports across all ranges.
    var totalPortCount: Int {
        ports.reduce(0) { $0 + (Int($1.upperBound) - Int($1.lowerBound) + 1) }
    }

    /// A uniformly random port across the union of ranges, or `nil` if empty.
    func randomPort() -> UInt16? {
        let total = totalPortCount
        guard total > 0 else { return nil }
        var index = Int.random(in: 0..<total)
        for range in ports {
            let count = Int(range.upperBound) - Int(range.lowerBound) + 1
            if index < count { return UInt16(Int(range.lowerBound) + index) }
            index -= count
        }
        return ports.first?.lowerBound
    }
}

// MARK: - QUICConnection

nonisolated class QUICConnection {

    enum State {
        case idle, connecting, handshaking, connected, closing, closed
    }

    enum QUICError: Error, LocalizedError {
        case connectionFailed(String)
        case handshakeFailed(String)
        case streamError(String)
        /// Peer sent RESET_STREAM (read side aborted).
        case streamReset(appErrorCode: UInt64)
        /// `stream_close` fired with an application error code set.
        case streamClosedWithError(appErrorCode: UInt64)
        /// Queued DATAGRAM exceeded the path's max frame size and was dropped; re-fragment to `maxBound` for a retry.
        case datagramTooLarge(maxBound: Int)
        case timeout
        case closed

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let m): return "QUIC: \(m)"
            case .handshakeFailed(let m): return "QUIC TLS: \(m)"
            case .streamError(let m): return "QUIC stream: \(m)"
            case .streamReset(let c): return "QUIC stream reset (app code \(c))"
            case .streamClosedWithError(let c): return "QUIC stream closed (app code \(c))"
            case .datagramTooLarge(let b): return "QUIC datagram exceeds path MTU (max \(b) B)"
            case .timeout: return "QUIC timeout"
            case .closed: return "QUIC closed"
            }
        }
    }

    // MARK: Properties

    private let host: String
    private let port: UInt16
    private let serverName: String
    private let alpn: [String]
    private let tuning: QUICTuning

    /// When set, ngtcp2 rides this instead of a kernel socket (QUIC through a proxy chain's UDP relay).
    private let transport: QUICDatagramTransport?

    fileprivate var state: State = .idle
    let queue: DispatchQueue
    private static let queueKey = DispatchSpecificKey<Bool>()

    fileprivate var conn: OpaquePointer?
    private var connRefStorage = ngtcp2_crypto_conn_ref()

    /// True while inside `ngtcp2_swift_conn_read_pkt`; callbacks fired during read
    /// must not trigger a reentrant write — the tail flush in `handleReceivedPacket` covers it.
    private var inReadPkt = false

    /// True while a `conn`-holding ngtcp2 batch is on the stack; `close()` then defers
    /// one queue cycle so `ngtcp2_conn_del` can't free `conn` under the batch.
    /// Saved/restored so nested batches compose.
    private var ngtcp2Busy = false

    /// A coalesced flush is queued; drained by one `writeToUDP` at the end of the queue cycle.
    private var flushScheduled = false

    /// Direct-dial UDP socket. `nil` when QUIC rides a `QUICDatagramTransport`.
    private var quicSocket: QUICSocket?

    /// Port-hopping config; `nil` disables it. Honored only on the direct kernel-socket path —
    /// a chained transport has no port to rotate.
    private let portHopping: QUICPortHopping?
    /// Rotates the socket's destination port every `portHopping.interval`. On `queue`.
    private var hopTimer: DispatchSourceTimer?

    private var localAddr = sockaddr_storage()
    private var remoteAddr = sockaddr_storage()
    private var addrLen: Int = MemoryLayout<sockaddr_in>.size

    fileprivate var tlsHandshaker: QUICTLSHandler?

    private var retransmitTimer: DispatchSourceTimer?

    private var dcid = ngtcp2_cid()
    private var scid = ngtcp2_cid()

    fileprivate var connectCompletion: ((Error?) -> Void)?
    /// Receives a zero-copy view into ngtcp2's buffer, valid only for the synchronous call —
    /// dispatching without copying is a use-after-free.
    var streamDataHandler: ((Int64, Data, Bool) -> Void)?
    /// Fires on stream termination (`error == nil` for a clean close). A stream can
    /// trigger reset then close, so handling must be idempotent.
    var streamTerminationHandler: ((Int64, Error?) -> Void)?
    var datagramHandler: ((Data) -> Void)?
    var connectionClosedHandler: ((Error) -> Void)?

    private var brutalCC: BrutalCongestionControl?
    /// Registry key (`ngtcp2_cc *`) for the `@_cdecl` trampolines.
    private var brutalCCKey: OpaquePointer?

    private let datagramsEnabled: Bool
    static let maxDatagramFrameSize: UInt64 = 65535

    /// Writes blocked by stream flow control; flushed on MAX_STREAM_DATA.
    private var pendingWrites: [PendingWrite] = []

    private struct PendingWrite {
        let streamId: Int64
        var data: Data
        let fin: Bool
        let completion: (Error?) -> Void
    }

    /// Heap copies of stream bytes per stream, ascending end-offset order. ngtcp2's
    /// `writev_stream` is zero-copy and re-reads the pointer on every retransmission,
    /// so bytes must stay valid until acked. Touched only on `queue`.
    private var inflightStreamBuffers: [Int64: [InflightStreamBuffer]] = [:]
    /// Absolute tx offset per stream, labeling retained buffers for the ack callback.
    /// Touched only on `queue`.
    private var streamTxOffset: [Int64: UInt64] = [:]

    /// Stable heap copy of stream bytes handed to ngtcp2.
    private final class InflightStreamBuffer {
        let storage: UnsafeMutableBufferPointer<UInt8>
        /// Absolute stream offset one past this buffer's last accepted byte.
        var endOffset: UInt64 = 0

        init(copying data: Data) {
            let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            _ = data.copyBytes(to: buf)
            storage = buf
        }

        deinit { storage.deallocate() }
    }

    /// Datagrams awaiting send, drained first in `writeToUDP()`. Bounded at
    /// `maxPendingDatagrams` with drop-oldest; each completion fires on every terminal outcome.
    private struct PendingDatagram {
        let data: Data
        let completion: ((Error?) -> Void)?
    }
    private var pendingDatagrams: [PendingDatagram] = []
    private static let maxPendingDatagrams = 1024
    private var didWarnDatagramOverflow = false

    static let maxUDPPayload = 1452

    /// UDP payload ceiling when riding a `QUICDatagramTransport`: the RFC 9000 §14 floor (1200 B)
    /// always fits the inner transport — larger sizes forced inner fragmentation and, with PMTUD
    /// disabled for chained transports, wedged loss recovery at a too-large size forever.
    static let chainedMaxUDPPayload = 1200

    /// Reusable tx buffer; one slot suffices because ngtcp2 is single-threaded on `queue`.
    private var txBuf = [UInt8](repeating: 0, count: QUICConnection.maxUDPPayload)

    /// PMTUD probe sizes, ascending. Must be in (1200, max_tx_udp_payload_size] —
    /// ngtcp2 silently skips larger probes. Copied by ngtcp2 at conn-new time.
    private static let pmtudProbes: [UInt16] = [1350, 1400, 1452]

    // MARK: Init

    var isOnQueue: Bool { DispatchQueue.getSpecific(key: Self.queueKey) == true }

    init(host: String, port: UInt16, serverName: String? = nil, alpn: [String],
         datagramsEnabled: Bool = false, tuning: QUICTuning,
         portHopping: QUICPortHopping? = nil,
         transport: QUICDatagramTransport? = nil) {
        self.host = host
        self.port = port
        self.serverName = serverName ?? host
        self.alpn = alpn
        self.datagramsEnabled = datagramsEnabled
        self.tuning = tuning
        // Port hopping needs a kernel socket whose destination we control; a chained transport
        // has none, so drop it there rather than silently no-op deeper down.
        self.portHopping = transport == nil ? portHopping : nil
        self.transport = transport
        self.queue = DispatchQueue(label: AWCore.Identifier.quicQueue, qos: .userInitiated)
        queue.setSpecific(key: Self.queueKey, value: true)
    }

    // MARK: Connect

    func connect(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.state == .idle else {
                completion(QUICError.connectionFailed("Invalid state"))
                return
            }
            QUICCrypto.registerCallbacks()
            self.state = .connecting
            self.connectCompletion = completion
            self.setupUDP(completion: completion)
        }
    }

    // MARK: Streams

    func openBidiStream() -> Int64? {
        guard state == .connected, let conn else { return nil }
        var streamId: Int64 = -1
        let streamData: UnsafeMutableRawPointer? = nil
        let rv = ngtcp2_conn_open_bidi_stream(conn, &streamId, streamData)
        if rv != 0 {
            return nil
        }
        return streamId
    }

    func openUniStream() -> Int64? {
        guard state == .connected, let conn else { return nil }
        var streamId: Int64 = -1
        let streamData: UnsafeMutableRawPointer? = nil
        let rv = ngtcp2_conn_open_uni_stream(conn, &streamId, streamData)
        if rv != 0 {
            return nil
        }
        return streamId
    }

    /// Extends stream- and connection-level flow control after the app consumes `count` bytes.
    func extendStreamOffset(_ streamId: Int64, count: Int) {
        guard count > 0 else { return }
        if isOnQueue {
            extendStreamOffsetOnQueue(streamId, count: count)
        } else {
            queue.async { [weak self] in
                self?.extendStreamOffsetOnQueue(streamId, count: count)
            }
        }
    }

    private func extendStreamOffsetOnQueue(_ streamId: Int64, count: Int) {
        guard let conn else { return }
        ngtcp2_conn_extend_max_stream_offset(conn, streamId, UInt64(count))
        ngtcp2_conn_extend_max_offset(conn, UInt64(count))
        // Inside read_pkt the post-read scheduleFlush() covers it.
        if inReadPkt { return }
        scheduleFlush()
    }

    /// Coalesces tx flushes so a burst of received packets produces one drain.
    private func scheduleFlush() {
        if flushScheduled { return }
        flushScheduled = true
        queue.async { [weak self] in
            guard let self else { return }
            self.flushScheduled = false
            self.writeToUDP()
            self.flushPendingWrites()
        }
    }

    /// Sends RESET_STREAM + STOP_SENDING, freeing the stream ID slot. The caller supplies the
    /// application error code; each app protocol (HTTP/3, Hysteria, Nowhere) defines its own.
    func shutdownStream(_ streamId: Int64, appErrorCode: UInt64) {
        queue.async { [weak self] in
            guard let self, let conn = self.conn else { return }
            ngtcp2_conn_shutdown_stream(conn, 0, streamId, appErrorCode)
            self.writeToUDP()
        }
    }

    func writeStream(_ streamId: Int64, data: Data, fin: Bool = false,
                     completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            guard let conn = self.conn, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.writeStreamImpl(conn: conn, streamId: streamId,
                                 data: data, fin: fin, completion: completion)
        }
    }

    // MARK: Datagrams

    /// Queues a QUIC DATAGRAM frame; `completion` errs only on fatal conditions (closed, MTU exceeded).
    func writeDatagram(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            guard self.conn != nil, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.enqueueDatagrams([PendingDatagram(data: data, completion: completion)])
            self.writeToUDP()
        }
    }

    /// Queues multiple DATAGRAM frames; `completion` fires once all reach a terminal
    /// state, with the first error or `nil`.
    func writeDatagrams(_ datagrams: [Data], completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            guard self.conn != nil, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            if datagrams.isEmpty {
                completion(nil)
                return
            }
            // All completions fire on `queue`, so the unsynchronised counters are safe.
            var remaining = datagrams.count
            var firstError: Error?
            let onEach: ((Error?) -> Void) = { err in
                if let err, firstError == nil { firstError = err }
                remaining -= 1
                if remaining == 0 { completion(firstError) }
            }
            let pending = datagrams.map {
                PendingDatagram(data: $0, completion: onEach)
            }
            self.enqueueDatagrams(pending)
            self.writeToUDP()
        }
    }

    /// Appends with drop-oldest at `maxPendingDatagrams`; dropped completions fire so callers observe the overflow.
    private func enqueueDatagrams(_ datagrams: [PendingDatagram]) {
        pendingDatagrams.append(contentsOf: datagrams)
        let overflow = pendingDatagrams.count - Self.maxPendingDatagrams
        guard overflow > 0 else { return }
        let dropped = Array(pendingDatagrams.prefix(overflow))
        pendingDatagrams.removeFirst(overflow)
        if !didWarnDatagramOverflow {
            didWarnDatagramOverflow = true
            logger.warning("[QUIC] Datagram send queue overflowed (cap \(Self.maxPendingDatagrams)); dropping oldest")
        }
        let overflowError = QUICError.connectionFailed("Datagram send queue overflowed")
        for d in dropped { d.completion?(overflowError) }
    }

    /// Max datagram payload per UDP packet (0 if unsupported): min(peer `max_datagram_frame_size` − 3
    /// frame header, path MTU − 44 worst-case QUIC packet overhead). The worst case prevents
    /// `write_datagram` returning `nwrite=0, accepted=0` forever and wedging the queue. On `queue`.
    var maxDatagramPayloadSize: Int {
        dispatchPrecondition(condition: .onQueue(queue))
        guard let conn else { return 0 }
        guard let params = ngtcp2_swift_conn_get_remote_transport_params(conn) else { return 0 }
        let maxFrame = Int(params.pointee.max_datagram_frame_size)
        guard maxFrame > 0 else { return 0 }
        let frameLimit = max(0, maxFrame - 3)
        let pathBytes = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn)
        let pathLimit = max(0, Int(pathBytes) - 44)
        return min(frameLimit, pathLimit)
    }

    /// Sends as much stream data as flow control allows, queuing the remainder.
    private func writeStreamImpl(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool,
                                  completion: @escaping (Error?) -> Void) {
        let sent = writeStreamSync(conn: conn, streamId: streamId,
                                    data: data, fin: fin)

        if sent >= data.count {
            completion(nil)
        } else {
            let remaining = Data(data[sent...])
            pendingWrites.append(PendingWrite(
                streamId: streamId, data: remaining,
                fin: fin, completion: completion
            ))
        }
    }

    /// Writes as much stream data as ngtcp2 will accept. Returns bytes accepted.
    private func writeStreamSync(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool) -> Int {
        let ts = currentTimestamp()
        var offset = 0

        guard !data.isEmpty else {
            writeToUDP()
            return 0
        }

        // ngtcp2 retains the pointer until the bytes are acked; copy to a heap
        // buffer released by the ack callback.
        let baseOffset = streamTxOffset[streamId] ?? 0
        let inflight = InflightStreamBuffer(copying: data)
        let stableBase = inflight.storage.baseAddress!

        while offset < data.count {
            var pi = ngtcp2_pkt_info()
            var pdatalen: ngtcp2_ssize = 0

            let remaining = data.count - offset
            let isLast = (offset + remaining >= data.count)
            let flags: UInt32 = {
                var f: UInt32 = 0
                if fin && isLast { f |= UInt32(NGTCP2_WRITE_STREAM_FLAG_FIN) }
                if !isLast { f |= UInt32(NGTCP2_WRITE_STREAM_FLAG_MORE) }
                return f
            }()

            var vec = ngtcp2_vec(base: stableBase.advanced(by: offset),
                                 len: remaining)
            let nwrite: ngtcp2_ssize = txBuf.withUnsafeMutableBufferPointer { dest -> ngtcp2_ssize in
                ngtcp2_swift_conn_writev_stream(
                    conn, nil, &pi, dest.baseAddress, dest.count,
                    &pdatalen, flags,
                    streamId, &vec, 1, ts
                )
            }

            if nwrite == 0 { break }

            if nwrite < 0 {
                let code = Int32(nwrite)
                if code == NGTCP2_ERR_WRITE_MORE {
                    if pdatalen > 0 { offset += Int(pdatalen) }
                    continue
                }
                if code == NGTCP2_ERR_STREAM_DATA_BLOCKED {
                    if pdatalen > 0 { offset += Int(pdatalen) }
                    break
                }
                if code == NGTCP2_ERR_STREAM_NOT_FOUND || code == NGTCP2_ERR_STREAM_SHUT_WR {
                    break
                }
                break
            }

            sendTxBuf(length: Int(nwrite))
            if pdatalen > 0 { offset += Int(pdatalen) }
            if pdatalen == 0 { break }
        }

        // Retain only if bytes were accepted; freed when acked.
        if offset > 0 {
            inflight.endOffset = baseOffset + UInt64(offset)
            inflightStreamBuffers[streamId, default: []].append(inflight)
            streamTxOffset[streamId] = inflight.endOffset
        }

        writeToUDP()
        return offset
    }

    /// Releases retained buffers with `endOffset <= ackedOffset` — they can never be retransmitted. Runs on `queue`.
    fileprivate func releaseAckedStreamData(streamId: Int64, ackedOffset: UInt64) {
        guard var buffers = inflightStreamBuffers[streamId] else { return }
        var drop = 0
        while drop < buffers.count && buffers[drop].endOffset <= ackedOffset {
            drop += 1
        }
        guard drop > 0 else { return }
        buffers.removeFirst(drop)
        inflightStreamBuffers[streamId] = buffers.isEmpty ? nil : buffers
    }

    /// Drops all retained send state for a stream after ngtcp2 frees it.
    fileprivate func releaseStreamSendState(streamId: Int64) {
        inflightStreamBuffers[streamId] = nil
        streamTxOffset[streamId] = nil
    }

    /// Fails queued writes for a terminated stream so their completions don't leak. Runs on `queue`.
    fileprivate func failPendingWrites(streamId: Int64, error: Error) {
        guard !pendingWrites.isEmpty else { return }
        var remaining: [PendingWrite] = []
        remaining.reserveCapacity(pendingWrites.count)
        var failed: [(Error?) -> Void] = []
        for pw in pendingWrites {
            if pw.streamId == streamId {
                failed.append(pw.completion)
            } else {
                remaining.append(pw)
            }
        }
        pendingWrites = remaining
        for cb in failed { cb(error) }
    }

    /// Retries flow-control-blocked writes after packets that may carry MAX_STREAM_DATA.
    private func flushPendingWrites() {
        guard !pendingWrites.isEmpty, let conn else { return }
        // A completion may call close(); ngtcp2Busy defers teardown so `conn`
        // isn't freed mid-loop.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        defer { ngtcp2Busy = prevBusy }
        guard state == .connected else {
            let writes = pendingWrites
            pendingWrites.removeAll()
            for pw in writes { pw.completion(QUICError.closed) }
            return
        }

        var remaining: [PendingWrite] = []
        for pw in pendingWrites {
            let sent = writeStreamSync(conn: conn, streamId: pw.streamId,
                                        data: pw.data, fin: pw.fin)
            if sent >= pw.data.count {
                pw.completion(nil)
            } else {
                remaining.append(PendingWrite(
                    streamId: pw.streamId,
                    data: Data(pw.data[sent...]),
                    fin: pw.fin,
                    completion: pw.completion
                ))
            }
        }
        pendingWrites = remaining
    }

    // MARK: Close

    func close(error: Error? = nil) {
        // Defer while a ngtcp2 batch still holds the conn pointer on the stack.
        if ngtcp2Busy && isOnQueue {
            queue.async { self.close(error: error) }
            return
        }
        // Strong-capture `self` so teardown runs even when close() is the last reference;
        // synchronous on `queue` so pool state updates before new streams are handed out.
        let teardown: () -> Void = {
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
            if let conn = self.conn {
                ngtcp2_conn_del(conn)
                self.conn = nil
            }
            self.transport?.cancel()
            self.closeSocket()
            self.state = .closed
            let writes = self.pendingWrites
            self.pendingWrites.removeAll()
            let dgrams = self.pendingDatagrams
            self.pendingDatagrams.removeAll()
            self.inflightStreamBuffers.removeAll()
            self.streamTxOffset.removeAll()
            let closeError = error ?? QUICError.closed
            // Fire any still-pending connect callback — the socket's non-EAGAIN
            // recv error path calls close() directly.
            if let cb = self.connectCompletion {
                self.connectCompletion = nil
                cb(closeError)
            }
            for pw in writes { pw.completion(closeError) }
            for d in dgrams { d.completion?(closeError) }
            self.connectionClosedHandler?(closeError)
            self.connectionClosedHandler = nil
            self.streamDataHandler = nil
            self.streamTerminationHandler = nil
            self.datagramHandler = nil
        }
        if isOnQueue {
            teardown()
        } else {
            queue.async(execute: teardown)
        }
    }

    // MARK: UDP

    private func setupUDP(completion: @escaping (Error?) -> Void) {
        if let transport {
            setupTunnelTransport(transport: transport, completion: completion)
        } else {
            setupRawSocket(completion: completion)
        }
    }

    private func setupRawSocket(completion: @escaping (Error?) -> Void) {
        do {
            populateRemoteAddr()
            guard remoteAddr.ss_family != 0 else {
                throw QUICError.connectionFailed("DNS lookup failed for \(host)")
            }
            let sock = QUICSocket(queue: queue, receiveBufferSize: Self.maxUDPPayload)
            // ngtcp2's path stays pinned to `remoteAddr` (the canonical host:port); only the
            // socket's real destination rotates. The first dial already uses a hop port so the
            // handshake itself rides the hopped range.
            let initialPeer = initialHopAddr() ?? remoteAddr
            try sock.connect(remoteAddr: initialPeer, localAddr: &localAddr, addrLen: addrLen)
            quicSocket = sock
            try initializeNgtcp2()
            state = .handshaking
            sock.startReceiving(
                onPacket: { [weak self] data in self?.handleReceivedPacket(data) },
                onError: { [weak self] err in
                    self?.close(error: QUICError.connectionFailed("recv errno=\(err)"))
                }
            )
            startHopTimer()
            writeToUDP()    // send client initial
            rescheduleTimer()
        } catch {
            // Nil connectCompletion before firing to prevent double-fire from stray callbacks.
            state = .closed
            closeSocket()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Wires ngtcp2 to a datagram transport (chained QUIC). Placeholder addrs are safe
    /// because `disable_active_migration` is set — ngtcp2 never routes by them.
    private func setupTunnelTransport(
        transport: QUICDatagramTransport,
        completion: @escaping (Error?) -> Void
    ) {
        do {
            configurePlaceholderAddrs()
            try initializeNgtcp2()
            state = .handshaking
            transport.startReceiving { [weak self] data in
                self?.queue.async {
                    self?.handleReceivedPacket(data)
                }
            } errorHandler: { [weak self] error in
                self?.queue.async {
                    guard let self else { return }
                    let err = error ?? QUICError.closed
                    if let cb = self.connectCompletion {
                        self.connectCompletion = nil
                        cb(err)
                    }
                    self.close(error: err)
                }
            }
            writeToUDP()    // send client initial
            rescheduleTimer()
        } catch {
            state = .closed
            transport.cancel()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Stable placeholder addrs for ngtcp2's path identity check; never used for routing.
    private func configurePlaceholderAddrs() {
        addrLen = MemoryLayout<sockaddr_in>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_port = port.bigEndian
                sin.pointee.sin_addr.s_addr = UInt32(0x7f000001).bigEndian  // 127.0.0.1
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_addr.s_addr = INADDR_ANY
            }
        }
    }

    private func closeSocket() {
        hopTimer?.cancel()
        hopTimer = nil
        quicSocket?.close()
        quicSocket = nil
    }

    // MARK: Port hopping

    /// Initial socket destination when port hopping is enabled: `remoteAddr` with a random hop
    /// port. `nil` when hopping is off or no port is available, so the caller dials `remoteAddr`.
    private func initialHopAddr() -> sockaddr_storage? {
        guard let port = portHopping?.randomPort() else { return nil }
        return hopAddr(port: port)
    }

    /// Arms the repeating hop timer. No-op unless hopping is enabled and more than one port is
    /// reachable — a single fixed port has nothing to rotate to.
    private func startHopTimer() {
        guard let portHopping, portHopping.totalPortCount > 1, quicSocket != nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.setEventHandler { [weak self] in self?.performHop() }
        // Loose leeway: hop timing has no latency budget, and slack lets the scheduler coalesce
        // the wakeup with QUIC's own timers.
        timer.schedule(deadline: .now() + portHopping.interval,
                       repeating: portHopping.interval,
                       leeway: .milliseconds(250))
        hopTimer = timer
        timer.resume()
    }

    /// Re-points the socket at a fresh random port. ngtcp2 is untouched — it keeps sending to the
    /// same fixed path, and the kernel redirects those bytes to the new peer.
    private func performHop() {
        guard state != .closed, let portHopping,
              let sock = quicSocket, let port = portHopping.randomPort() else { return }
        sock.reconnect(remoteAddr: hopAddr(port: port), addrLen: addrLen)
        // Flush any pending frames onto the new port so the server's reverse-NAT mapping
        // re-points immediately; an idle connection just falls back to the keep-alive PING.
        writeToUDP()
    }

    /// Copies `remoteAddr`, overriding only the port. Preserves the resolved IP and family.
    private func hopAddr(port: UInt16) -> sockaddr_storage {
        var addr = remoteAddr
        if addr.ss_family == sa_family_t(AF_INET) {
            withUnsafeMutablePointer(to: &addr) { storage in
                storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee.sin_port = port.bigEndian
                }
            }
        } else if addr.ss_family == sa_family_t(AF_INET6) {
            withUnsafeMutablePointer(to: &addr) { storage in
                storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    sin6.pointee.sin6_port = port.bigEndian
                }
            }
        }
        return addr
    }

    private func populateRemoteAddr() {
        var addr4 = in_addr()
        if inet_pton(AF_INET, host, &addr4) == 1 {
            configureIPv4(addr4)
            return
        }

        var addr6 = in6_addr()
        if inet_pton(AF_INET6, host, &addr6) == 1 {
            configureIPv6(addr6)
            return
        }

        // Cache-backed resolver — a direct getaddrinfo() would block the queue.
        var found4: in_addr?
        var found6: in6_addr?
        for ip in DNSResolver.shared.resolveAll(host) {
            if found4 == nil {
                var a4 = in_addr()
                if inet_pton(AF_INET, ip, &a4) == 1 {
                    found4 = a4
                    continue
                }
            }
            if found6 == nil {
                var a6 = in6_addr()
                if inet_pton(AF_INET6, ip, &a6) == 1 {
                    found6 = a6
                }
            }
        }

        if let a4 = found4 {
            configureIPv4(a4)
        } else if let a6 = found6 {
            configureIPv6(a6)
        }
    }

    private func configureIPv4(_ addr: in_addr) {
        addrLen = MemoryLayout<sockaddr_in>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_port = port.bigEndian
                sin.pointee.sin_addr = addr
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                sin.pointee = sockaddr_in()
                sin.pointee.sin_len = UInt8(addrLen)
                sin.pointee.sin_family = sa_family_t(AF_INET)
                sin.pointee.sin_addr.s_addr = INADDR_ANY
            }
        }
    }

    private func configureIPv6(_ addr: in6_addr) {
        addrLen = MemoryLayout<sockaddr_in6>.size
        withUnsafeMutablePointer(to: &remoteAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                sin6.pointee = sockaddr_in6()
                sin6.pointee.sin6_len = UInt8(addrLen)
                sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                sin6.pointee.sin6_port = port.bigEndian
                sin6.pointee.sin6_addr = addr
            }
        }
        withUnsafeMutablePointer(to: &localAddr) { storage in
            storage.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                sin6.pointee = sockaddr_in6()
                sin6.pointee.sin6_len = UInt8(addrLen)
                sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                sin6.pointee.sin6_addr = in6addr_any
            }
        }
    }

    /// Sends `length` bytes from `txBuf`. Drop-on-error; ngtcp2 handles retransmit.
    private func sendTxBuf(length: Int) {
        guard length > 0 else { return }
        if let transport {
            // Copy out before the next ngtcp2 write reuses txBuf.
            let datagram = txBuf.withUnsafeBufferPointer { buf -> Data in
                Data(bytes: buf.baseAddress!, count: length)
            }
            transport.sendDatagram(datagram)
            return
        }
        guard let quicSocket else { return }
        txBuf.withUnsafeBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            quicSocket.send(base, length: length)
        }
    }

    // MARK: ngtcp2 Init

    private func initializeNgtcp2() throws {
        generateConnectionID(&dcid, length: 16)
        generateConnectionID(&scid, length: 16)

        tlsHandshaker = QUICTLSHandler(serverName: serverName, alpn: alpn)

        var callbacks = ngtcp2_callbacks()
        callbacks.client_initial = quicClientInitialCB
        callbacks.recv_crypto_data = quicRecvCryptoDataCB
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb
        callbacks.recv_stream_data = quicRecvStreamDataCB
        callbacks.acked_stream_data_offset = quicAckedCB
        callbacks.stream_close = quicStreamCloseCB
        callbacks.stream_reset = quicStreamResetCB
        callbacks.rand = quicRandCB
        callbacks.get_new_connection_id2 = quicGetNewCIDCB
        callbacks.update_key = ngtcp2_crypto_update_key_cb
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb
        callbacks.handshake_completed = quicHandshakeCompletedCB
        if datagramsEnabled {
            callbacks.recv_datagram = quicRecvDatagramCB
        }

        var settings = ngtcp2_settings()
        ngtcp2_swift_settings_default(&settings)
        settings.initial_ts = currentTimestamp()
        // Chained transports use the RFC 9000 §14 floor; see chainedMaxUDPPayload.
        settings.max_tx_udp_payload_size = (transport != nil) ? Self.chainedMaxUDPPayload : Self.maxUDPPayload
        settings.cc_algo = tuning.ngtcp2CCAlgo
        settings.max_stream_window = tuning.maxStreamWindow
        settings.max_window = tuning.maxWindow
        settings.handshake_timeout = tuning.handshakeTimeout
        var params = ngtcp2_transport_params()
        ngtcp2_swift_transport_params_default(&params)
        params.initial_max_streams_bidi = tuning.initialMaxStreamsBidi
        params.initial_max_streams_uni = tuning.initialMaxStreamsUni
        params.initial_max_data = tuning.initialMaxData
        params.initial_max_stream_data_bidi_local = tuning.initialMaxStreamDataBidiLocal
        params.initial_max_stream_data_bidi_remote = tuning.initialMaxStreamDataBidiRemote
        params.initial_max_stream_data_uni = tuning.initialMaxStreamDataUni
        params.max_idle_timeout = tuning.maxIdleTimeout
        params.disable_active_migration = tuning.disableActiveMigration ? 1 : 0
        if datagramsEnabled {
            params.max_datagram_frame_size = Self.maxDatagramFrameSize
        }

        var path = ngtcp2_path()
        withUnsafeMutablePointer(to: &localAddr) { local in
            withUnsafeMutablePointer(to: &remoteAddr) { remote in
                path.local = ngtcp2_addr(
                    addr: UnsafeMutableRawPointer(local).assumingMemoryBound(to: sockaddr.self),
                    addrlen: ngtcp2_socklen(addrLen))
                path.remote = ngtcp2_addr(
                    addr: UnsafeMutableRawPointer(remote).assumingMemoryBound(to: sockaddr.self),
                    addrlen: ngtcp2_socklen(addrLen))
            }
        }

        connRefStorage.user_data = Unmanaged.passUnretained(self).toOpaque()
        connRefStorage.get_conn = { ref in
            guard let ref, let ud = ref.pointee.user_data else { return nil }
            return Unmanaged<QUICConnection>.fromOpaque(ud).takeUnretainedValue().conn
        }

        // PMTUD only over a real kernel socket: chained probes don't reflect the
        // wire MTU, and a probe failure trips blackhole detection on a routine inner drop.
        let usePMTUD = (transport == nil)
        var connPtr: OpaquePointer?
        let rv = Self.pmtudProbes.withUnsafeBufferPointer { probes -> Int32 in
            if usePMTUD {
                settings.pmtud_probes = probes.baseAddress
                settings.pmtud_probeslen = probes.count
            }
            return ngtcp2_swift_conn_client_new(
                &connPtr, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                &callbacks, &settings, &params, nil, &connRefStorage
            )
        }
        guard rv == 0, let connPtr else {
            throw QUICError.connectionFailed("ngtcp2_conn_client_new: \(rv)")
        }
        self.conn = connPtr

        // Keep-alive PINGs detect silently-broken UDP paths (NAT rebind, idle sweep).
        ngtcp2_conn_set_keep_alive_timeout(connPtr, tuning.keepAliveTimeout)

        ngtcp2_conn_set_tls_native_handle(connPtr,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256)))

        // Install Brutal after conn_client_new and before any packets, so no
        // stale CUBIC decisions leak through.
        if case .brutal(let initialBps) = tuning.cc {
            let brutal = BrutalCongestionControl(initialBps: initialBps)
            if let ccKey = ngtcp2_swift_install_brutal(connPtr) {
                BrutalCongestionControl.register(brutal, for: ccKey)
                self.brutalCC = brutal
                self.brutalCCKey = ccKey
            }
        }
    }

    /// Updates the Brutal target send rate (bytes/sec); no-op if Brutal isn't installed. Safe off-queue.
    func setBrutalBandwidth(_ bps: UInt64) {
        queue.async { [weak self] in
            self?.brutalCC?.setTargetBandwidth(bps)
        }
    }

    /// Reverts to CUBIC (`Hysteria-CC-RX: auto`); safe off-queue. Unregisters BEFORE rewiring
    /// the CC table so a racing trampoline no-ops rather than touching a half-initialized CUBIC struct.
    func uninstallBrutalCC() {
        queue.async { [weak self] in
            guard let self, let conn = self.conn else { return }
            if let key = self.brutalCCKey {
                BrutalCongestionControl.unregister(cc: key)
                self.brutalCCKey = nil
                self.brutalCC = nil
            }
            ngtcp2_swift_uninstall_brutal(conn)
        }
    }

    // MARK: Packet Processing

    fileprivate func handleReceivedPacket(_ data: Data) {
        guard let conn else { return }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        inReadPkt = true
        defer { inReadPkt = false }

        // Guard close() from freeing `conn` while ngtcp2 is still on the stack.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        let rv: Int32 = data.withUnsafeBytes { raw in
            guard let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            var path = ngtcp2_path()
            withUnsafeMutablePointer(to: &localAddr) { local in
                withUnsafeMutablePointer(to: &remoteAddr) { remote in
                    path.local = ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(local).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen))
                    path.remote = ngtcp2_addr(
                        addr: UnsafeMutableRawPointer(remote).assumingMemoryBound(to: sockaddr.self),
                        addrlen: ngtcp2_socklen(addrLen))
                }
            }
            return ngtcp2_swift_conn_read_pkt(conn, &path, &pi, ptr, data.count, ts)
        }
        ngtcp2Busy = prevBusy

        if rv != 0 {
            // Any non-zero read_pkt return is terminal. Close now: a UDP-only workload
            // has no read pressure and would otherwise sit on a dead connection for the keep-alive window.
            let error: Error
            switch rv {
            case NGTCP2_ERR_DRAINING, NGTCP2_ERR_CLOSING:
                error = QUICError.closed
            case NGTCP2_ERR_CALLBACK_FAILURE, NGTCP2_ERR_CRYPTO:
                error = QUICError.handshakeFailed("ngtcp2 error: \(rv)")
            default:
                error = QUICError.connectionFailed("ngtcp2 read_pkt: \(rv)")
            }
            if let cb = connectCompletion {
                connectCompletion = nil
                cb(error)
            }
            close(error: error)
            return
        }
        scheduleFlush()
    }

    fileprivate func writeToUDP() {
        guard let conn else { return }
        // Defer close() until we return; tail completions may re-enter ngtcp2.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        defer { ngtcp2Busy = prevBusy }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        // Fire completions only after all ngtcp2 work: ngtcp2.h forbids other calls
        // between WRITE_MORE and the next write_datagram, and a completion could re-enter.
        var pendingCompletions: [(((Error?) -> Void)?, Error?)] = []

        // Drain datagrams first; WRITE_MORE packs multiple into one UDP packet.
        while !pendingDatagrams.isEmpty {
            var accepted: Int32 = 0
            let head = pendingDatagrams[0]
            let dgram = head.data
            let flags: UInt32 = pendingDatagrams.count > 1
                ? UInt32(NGTCP2_WRITE_DATAGRAM_FLAG_MORE)
                : 0

            let nwrite: ngtcp2_ssize = dgram.withUnsafeBytes { rawBuf in
                guard let srcPtr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return 0
                }
                return txBuf.withUnsafeMutableBufferPointer { dest -> ngtcp2_ssize in
                    ngtcp2_swift_conn_write_datagram(
                        conn, nil, &pi, dest.baseAddress, dest.count,
                        &accepted, flags, 0, srcPtr, dgram.count, ts
                    )
                }
            }

            // WRITE_MORE: datagram committed to the in-progress packet (per ngtcp2.h).
            if nwrite == ngtcp2_ssize(NGTCP2_ERR_WRITE_MORE) {
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, nil))
                continue
            }
            if nwrite < 0 {
                // Fatal error (e.g. exceeds max_datagram_frame_size) — drop.
                logger.warning("[QUIC] Dropping \(dgram.count)-byte datagram: ngtcp2 err \(nwrite)")
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, QUICError.connectionFailed("ngtcp2 write_datagram err \(nwrite)")))
                continue
            }
            if nwrite > 0 {
                sendTxBuf(length: Int(nwrite))
            }
            if accepted != 0 {
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, nil))
                continue
            }
            if nwrite > 0 {
                // Packet flushed but head didn't fit; retry with a fresh packet.
                continue
            }
            // nwrite == 0, accepted == 0: CW full or head too large — use the
            // path-MTU bound to distinguish, dropping rather than wedging the queue.
            let bound = maxDatagramPayloadSize
            if dgram.count > bound {
                logger.warning("[QUIC] Dropping \(dgram.count)-byte datagram: exceeds path-MTU bound (\(bound) B)")
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, QUICError.datagramTooLarge(maxBound: bound)))
                continue
            }
            // Congestion window full; retry on the next writeToUDP.
            break
        }

        while true {
            let nwrite = txBuf.withUnsafeMutableBufferPointer { dest -> ngtcp2_ssize in
                ngtcp2_swift_conn_write_pkt(conn, nil, &pi, dest.baseAddress, dest.count, ts)
            }
            if nwrite <= 0 { break }
            sendTxBuf(length: Int(nwrite))
        }

        // Updates conn->tx.pacing.next_ts; without it the pacer is disabled and sends burst cwnd-wide.
        ngtcp2_conn_update_pkt_tx_time(conn, ts)

        rescheduleTimer()

        // Fire completions after all ngtcp2 work; safe to re-enter ngtcp2 here.
        for (cb, err) in pendingCompletions { cb?(err) }
    }

    // MARK: Timer

    /// Last deadline armed, to avoid recreating a DispatchSourceTimer on every ACK.
    private var lastScheduledExpiry: UInt64 = 0

    private func rescheduleTimer() {
        guard let conn else { return }
        let expiry = ngtcp2_conn_get_expiry(conn)

        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        if retransmitTimer == nil {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.setEventHandler { [weak self] in
                guard let self, let conn = self.conn else { return }
                self.lastScheduledExpiry = 0
                let ts = self.currentTimestamp()
                // handle_expiry may fire CC callbacks; bracket so a close inside is deferred.
                let prevBusy = self.ngtcp2Busy
                self.ngtcp2Busy = true
                let rv = ngtcp2_conn_handle_expiry(conn, ts)
                self.ngtcp2Busy = prevBusy
                if rv != 0 {
                    let error = QUICError.connectionFailed("expiry error: \(rv)")
                    if let cb = self.connectCompletion {
                        self.connectCompletion = nil
                        cb(error)
                    }
                    self.close(error: error)
                    return
                }
                self.writeToUDP()
            }
            retransmitTimer = timer
            timer.resume()
        }

        let deadline: DispatchTime
        if expiry == UInt64.max {
            deadline = .distantFuture
        } else {
            let now = currentTimestamp()
            let delay = expiry > now ? expiry - now : 0
            deadline = .now() + .nanoseconds(Int(min(delay, UInt64(Int.max))))
        }
        // Zero leeway: BBR needs sub-ms pacing accuracy; slack coalesces wakeups
        // into bursts that trip loss detection.
        retransmitTimer?.schedule(deadline: deadline, leeway: .nanoseconds(0))
    }

    // MARK: Utilities

    fileprivate func currentTimestamp() -> ngtcp2_tstamp {
        ngtcp2_tstamp(DispatchTime.now().uptimeNanoseconds)
    }

    private func generateConnectionID(_ cid: inout ngtcp2_cid, length: Int) {
        var data = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &data)
        cid.datalen = length
        withUnsafeMutableBytes(of: &cid.data) { buf in
            data.withUnsafeBytes { src in
                buf.copyMemory(from: UnsafeRawBufferPointer(
                    start: src.baseAddress, count: min(length, buf.count)))
            }
        }
    }
}

// MARK: - ngtcp2 Callbacks

private func qcFromUserData(_ ud: UnsafeMutableRawPointer?) -> QUICConnection? {
    guard let ud else { return nil }
    let ref = ud.assumingMemoryBound(to: ngtcp2_crypto_conn_ref.self)
    guard let p = ref.pointee.user_data else { return nil }
    return Unmanaged<QUICConnection>.fromOpaque(p).takeUnretainedValue()
}

private let quicClientInitialCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { conn, ud in
    guard let conn else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let dcid = ngtcp2_conn_get_client_initial_dcid(conn) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    let n: UnsafeMutablePointer<UInt8>? = nil
    if ngtcp2_crypto_derive_and_install_initial_key(
        conn, n, n, n, n, n, n, n, n, n, NGTCP2_PROTO_VER_V1, dcid) != 0 {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    guard let qc = qcFromUserData(ud), let tls = qc.tlsHandshaker else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    var pb = [UInt8](repeating: 0, count: 256)
    let pLen = ngtcp2_conn_encode_local_transport_params(conn, &pb, pb.count)
    guard pLen >= 0 else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let ch = tls.buildClientHello(transportParams: Data(pb.prefix(Int(pLen)))) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    return ch.withUnsafeBytes { buf -> Int32 in
        guard let p = buf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return NGTCP2_ERR_CALLBACK_FAILURE
        }
        return ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, p, ch.count)
    }
}

private let quicRecvCryptoDataCB: @convention(c) (
    OpaquePointer?, ngtcp2_encryption_level, UInt64,
    UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { conn, level, _, data, datalen, ud in
    guard let conn, let data, datalen > 0 else { return 0 }
    guard let qc = qcFromUserData(ud), let tls = qc.tlsHandshaker else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    let d = Data(bytes: data, count: datalen)
    switch tls.processCryptoData(d, level: level, conn: conn) {
    case .success, .needMoreData: return 0
    case .error(let c): return c
    }
}

private let quicRecvStreamDataCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafePointer<UInt8>?, Int,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { conn, flags, sid, offset, data, datalen, ud, _ in
    guard let conn, let qc = qcFromUserData(ud) else { return 0 }
    let fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0
    if let data, datalen > 0 {
        // Zero-copy view into ngtcp2's buffer; the handler must copy before returning.
        let view = Data(
            bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
            count: datalen,
            deallocator: .none
        )
        qc.streamDataHandler?(sid, view, fin)
    } else if fin {
        qc.streamDataHandler?(sid, Data(), true)
    }
    // FC window is extended only when the app consumes data (backpressure).
    return 0
}

/// Releases retained heap copies once a contiguous prefix of sent data is acked
/// (`offset + datalen` is the new acked end). Runs on `queue`.
private let quicAckedCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, streamId, offset, datalen, ud, _ in
    guard let qc = qcFromUserData(ud) else { return 0 }
    qc.releaseAckedStreamData(streamId: streamId, ackedOffset: offset + datalen)
    return 0
}

/// Mirrors `NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET` from ngtcp2.h —
/// the bare `#define` isn't imported into Swift.
private let ngtcp2StreamCloseFlagAppErrorCodeSet: UInt32 = 0x01

/// Fires after both directions of a stream terminate. `recv_stream_data` doesn't
/// fire for RESET_STREAM, so this is the app's only signal the stream is gone.
private let quicStreamCloseCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, flags, sid, appErrorCode, ud, _ in
    guard let qc = qcFromUserData(ud) else { return 0 }
    let hasError = (flags & ngtcp2StreamCloseFlagAppErrorCodeSet) != 0
    let error: Error? = hasError
        ? QUICConnection.QUICError.streamClosedWithError(appErrorCode: appErrorCode)
        : nil
    qc.failPendingWrites(
        streamId: sid,
        error: error ?? QUICConnection.QUICError.closed
    )
    qc.releaseStreamSendState(streamId: sid)
    qc.streamTerminationHandler?(sid, error)
    return 0
}

/// Fires on peer RESET_STREAM, before `stream_close`, so pending receives fail fast.
private let quicStreamResetCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, sid, _, appErrorCode, ud, _ in
    guard let qc = qcFromUserData(ud) else { return 0 }
    let error = QUICConnection.QUICError.streamReset(appErrorCode: appErrorCode)
    qc.failPendingWrites(streamId: sid, error: error)
    qc.streamTerminationHandler?(sid, error)
    return 0
}

private let quicRandCB: @convention(c) (
    UnsafeMutablePointer<UInt8>?, Int, UnsafePointer<ngtcp2_rand_ctx>?
) -> Void = { dest, len, _ in
    guard let dest else { return }
    _ = SecRandomCopyBytes(kSecRandomDefault, len, dest)
}

private let quicGetNewCIDCB: @convention(c) (
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
    withUnsafeMutableBytes(of: &cid.pointee.data) { buf in
        d.withUnsafeBytes { src in
            buf.copyMemory(from: UnsafeRawBufferPointer(start: src.baseAddress,
                                                         count: min(cidlen, buf.count)))
        }
    }
    withUnsafeMutableBytes(of: &token.pointee) { buf in
        _ = SecRandomCopyBytes(kSecRandomDefault, buf.count, buf.baseAddress!)
    }
    return 0
}

private let quicHandshakeCompletedCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, ud in
    guard let qc = qcFromUserData(ud) else { return 0 }
    qc.queue.async {
        qc.state = .connected
        qc.connectCompletion?(nil)
        qc.connectCompletion = nil
    }
    return 0
}

private let quicRecvDatagramCB: @convention(c) (
    OpaquePointer?, UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { _, _, data, datalen, ud in
    guard let data, datalen > 0, let qc = qcFromUserData(ud) else { return 0 }
    // Zero-copy view; handler must not retain it past this synchronous call.
    let view = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
        count: datalen,
        deallocator: .none
    )
    qc.datagramHandler?(view)
    return 0
}
