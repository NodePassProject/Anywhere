//
//  QUICConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Network
import CryptoKit

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

// MARK: - QUICPacketObfuscator

/// Transforms whole QUIC datagrams at the wire boundary (below ngtcp2, above the direct carrier or chained
/// transport), so the same obfuscation applies on both carriers. Methods are called only on
/// `QUICConnection.queue`, so implementations need no internal locking.
protocol QUICPacketObfuscator: AnyObject {
    /// Transforms one outgoing QUIC datagram into one or more wire datagrams (Gecko may fragment a
    /// handshake packet into several).
    func seal(_ packet: UnsafeRawBufferPointer) -> [Data]

    /// Transforms one received wire datagram into a complete QUIC datagram, or `nil` when it yields
    /// none (a Gecko fragment awaiting reassembly, or a malformed packet).
    func open(_ datagram: Data) -> Data?
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
        /// Peer closed the whole connection with a benign code (transport NO_ERROR, or
        /// application H3_NO_ERROR / `closeErrCodeOK` 0x100).
        case closedOK

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
            case .closedOK: return "QUIC closed (OK)"
            }
        }
    }

    // MARK: Properties

    private let host: String
    private let port: UInt16
    private let serverName: String
    private let alpn: [String]
    private let tuning: QUICTuning

    /// When set, ngtcp2 rides this instead of the direct UDP carrier (QUIC through a proxy chain's UDP relay).
    private let transport: QUICDatagramTransport?

    /// Obfuscates datagrams at the wire boundary (Hysteria Salamander/Gecko); `nil` sends them raw.
    private let obfuscator: QUICPacketObfuscator?

    fileprivate var state: State = .idle
    let queue: DispatchQueue
    private static let queueKey = DispatchSpecificKey<Bool>()

    fileprivate var connectionOpaquePointer: OpaquePointer?
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

    /// Direct-dial UDP carrier (the active path). `nil` when QUIC rides a `QUICDatagramTransport`.
    private var carrier: QUICDatagramCarrier?

    private var localAddr = sockaddr_storage()
    private var remoteAddr = sockaddr_storage()
    private var addrLen: Int = MemoryLayout<sockaddr_in>.size

    // MARK: Migration state (direct carrier only; all touched on `queue`)

    private enum MigrationKind { case reactive, proactive }
    /// Set while a path switch is in flight (awaiting ngtcp2 path validation).
    private var migrationKind: MigrationKind?
    /// Proactive-migration target, live alongside `carrier` until the new path
    /// validates. `nil` for reactive (the dead carrier is retired at once).
    private var migratingCarrier: QUICDatagramCarrier?
    /// Distinct cosmetic local addr of the migration target path, so ngtcp2 sees a
    /// path change and `writeToUDP` can route per path during proactive validation.
    private var migratingLocalAddr = sockaddr_storage()
    /// Monotonic source of distinct cosmetic local addrs across migrations.
    private var migrationCounter: UInt8 = 0
    /// Genuine migration failures (ngtcp2 rejected, or path didn't validate) since the
    /// last success — a signal the server can't migrate. Benign aborts don't count.
    private var migrationFailures = 0
    private static let maxMigrationFailures = 3
    /// True once a proactive migration called `initiate_migration` and ngtcp2 owns a
    /// validation only `path_validation` can resolve. Gates eager aborts mid-probe.
    private var proactiveValidating = false
    /// Fires if a proactive target never becomes ready; bounds the in-flight state.
    private var proactiveDeadline: DispatchWorkItem?
    private static let proactiveReadyTimeout: TimeInterval = 5

    fileprivate var tlsHandler: QUICTLSHandler?

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
    /// Fires after the peer increases the cumulative number of locally initiated
    /// bidirectional streams. Delivery is deferred until ngtcp2 finishes the
    /// current packet-processing batch, so handlers may safely open streams.
    var bidiCreditHandler: ((UInt64) -> Void)?

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
            let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            _ = data.copyBytes(to: buffer)
            storage = buffer
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
    private var txBuffer = [UInt8](repeating: 0, count: QUICConnection.maxUDPPayload)

    /// PMTUD probe sizes, ascending. Must be in (1200, max_tx_udp_payload_size] —
    /// ngtcp2 silently skips larger probes. Copied by ngtcp2 at conn-new time.
    private static let pmtudProbes: [UInt16] = [1350, 1400, 1452]

    // MARK: Init

    var isOnQueue: Bool { DispatchQueue.getSpecific(key: Self.queueKey) == true }

    init(host: String, port: UInt16, serverName: String? = nil, alpn: [String],
         datagramsEnabled: Bool = false, tuning: QUICTuning,
         obfuscator: QUICPacketObfuscator? = nil,
         transport: QUICDatagramTransport? = nil) {
        self.host = host
        self.port = port
        self.serverName = serverName ?? host
        self.alpn = alpn
        self.datagramsEnabled = datagramsEnabled
        self.tuning = tuning
        self.obfuscator = obfuscator
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
        guard state == .connected, let connectionOpaquePointer else { return nil }
        var streamId: Int64 = -1
        let streamData: UnsafeMutableRawPointer? = nil
        let rv = ngtcp2_conn_open_bidi_stream(connectionOpaquePointer, &streamId, streamData)
        if rv != 0 {
            return nil
        }
        return streamId
    }

    /// Number of additional bidirectional streams the local endpoint may open.
    /// Access is serialized on ``queue``.
    var availableBidiStreams: UInt64 {
        dispatchPrecondition(condition: .onQueue(queue))
        guard state == .connected, let connectionOpaquePointer else { return 0 }
        return ngtcp2_conn_get_streams_bidi_left2(connectionOpaquePointer)
    }

    func openUniStream() -> Int64? {
        guard state == .connected, let connectionOpaquePointer else { return nil }
        var streamId: Int64 = -1
        let streamData: UnsafeMutableRawPointer? = nil
        let rv = ngtcp2_conn_open_uni_stream(connectionOpaquePointer, &streamId, streamData)
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
        guard let connectionOpaquePointer else { return }
        ngtcp2_conn_extend_max_stream_offset(connectionOpaquePointer, streamId, UInt64(count))
        ngtcp2_conn_extend_max_offset(connectionOpaquePointer, UInt64(count))
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
            guard let self, let connectionOpaquePointer else { return }
            ngtcp2_conn_shutdown_stream(connectionOpaquePointer, 0, streamId, appErrorCode)
            self.writeToUDP()
        }
    }

    func writeStream(_ streamId: Int64, data: Data, fin: Bool = false,
                     completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            guard let connectionOpaquePointer, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.writeStreamImpl(conn: connectionOpaquePointer, streamId: streamId,
                                 data: data, fin: fin, completion: completion)
        }
    }

    // MARK: Datagrams

    /// Queues a QUIC DATAGRAM frame; `completion` errs only on fatal conditions (closed, MTU exceeded).
    func writeDatagram(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            guard self.connectionOpaquePointer != nil, self.state == .connected else {
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
            guard self.connectionOpaquePointer != nil, self.state == .connected else {
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
            let onEach: ((Error?) -> Void) = { error in
                if let error, firstError == nil { firstError = error }
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
        guard let connectionOpaquePointer else { return 0 }
        guard let parameters = ngtcp2_swift_conn_get_remote_transport_params(connectionOpaquePointer) else { return 0 }
        let maxFrame = Int(parameters.pointee.max_datagram_frame_size)
        guard maxFrame > 0 else { return 0 }
        let frameLimit = max(0, maxFrame - 3)
        let pathBytes = ngtcp2_conn_get_path_max_tx_udp_payload_size(connectionOpaquePointer)
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
            let (nwrite, outCarrier) = writeReportingCarrier { pathPtr in
                txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                    ngtcp2_swift_conn_writev_stream(
                        conn, pathPtr, &pi, destination.baseAddress, destination.count,
                        &pdatalen, flags,
                        streamId, &vec, 1, ts
                    )
                }
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

            sendTxBuf(length: Int(nwrite), to: outCarrier)
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
        for pendingWrite in pendingWrites {
            if pendingWrite.streamId == streamId {
                failed.append(pendingWrite.completion)
            } else {
                remaining.append(pendingWrite)
            }
        }
        pendingWrites = remaining
        for callback in failed { callback(error) }
    }

    /// Retries flow-control-blocked writes after packets that may carry MAX_STREAM_DATA.
    private func flushPendingWrites() {
        guard !pendingWrites.isEmpty, let connectionOpaquePointer else { return }
        // A completion may call close(); ngtcp2Busy defers teardown so `conn`
        // isn't freed mid-loop.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        defer { ngtcp2Busy = prevBusy }
        guard state == .connected else {
            let writes = pendingWrites
            pendingWrites.removeAll()
            for pendingWrite in writes { pendingWrite.completion(QUICError.closed) }
            return
        }

        var remaining: [PendingWrite] = []
        for pendingWrite in pendingWrites {
            let sent = writeStreamSync(conn: connectionOpaquePointer, streamId: pendingWrite.streamId,
                                        data: pendingWrite.data, fin: pendingWrite.fin)
            if sent >= pendingWrite.data.count {
                pendingWrite.completion(nil)
            } else {
                remaining.append(PendingWrite(
                    streamId: pendingWrite.streamId,
                    data: Data(pendingWrite.data[sent...]),
                    fin: pendingWrite.fin,
                    completion: pendingWrite.completion
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
            if let connectionOpaquePointer = self.connectionOpaquePointer {
                ngtcp2_conn_del(connectionOpaquePointer)
                self.connectionOpaquePointer = nil
            }
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
            self.connectionClosedHandler?(closeError)
            self.connectionClosedHandler = nil
            self.streamDataHandler = nil
            self.streamTerminationHandler = nil
            self.datagramHandler = nil
            self.bidiCreditHandler = nil
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
            setupDirectCarrier(completion: completion)
        }
    }

    private func setupDirectCarrier(completion: @escaping (Error?) -> Void) {
        do {
            populateRemoteAddr()
            guard remoteAddr.ss_family != 0 else {
                throw QUICError.connectionFailed("DNS lookup failed for \(host)")
            }
            let carrier = QUICDatagramCarrier(queue: queue)
            try carrier.connect(remoteAddr: remoteAddr, localAddr: &localAddr)
            self.carrier = carrier
            try initializeNgtcp2()
            state = .handshaking
            armActiveCarrier(carrier, localAddr: localAddr)
            writeToUDP()
            rescheduleTimer()
        } catch {
            // Nil connectCompletion before firing to prevent double-fire from stray callbacks.
            state = .closed
            closeCarrier()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Wires ngtcp2 to a datagram transport (chained QUIC). Placeholder addrs are safe:
    /// chained QUIC rides a fixed relay path and never migrates; the transport routes.
    private func setupTunnelTransport(
        transport: QUICDatagramTransport,
        completion: @escaping (Error?) -> Void
    ) {
        do {
            configurePlaceholderAddrs()
            try initializeNgtcp2()
            state = .handshaking
            let placeholderLocal = localAddr
            transport.startReceiving { [weak self] data in
                self?.queue.async {
                    self?.handleReceivedPacket(data, localAddr: placeholderLocal)
                }
            } errorHandler: { [weak self] error in
                self?.queue.async {
                    guard let self else { return }
                    let err = error ?? QUICError.closed
                    if let callback = self.connectCompletion {
                        self.connectCompletion = nil
                        callback(err)
                    }
                    self.close(error: err)
                }
            }
            writeToUDP()
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

    private func closeCarrier() {
        carrier?.close()
        carrier = nil
        // Also retire any in-flight migration target, so closing mid-migration doesn't
        // leak its NWConnection or leave a deferred path_validation/deadline on stale state.
        migratingCarrier?.close()
        clearMigrationState()
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

    // MARK: - Path-aware carrier I/O

    /// Builds an `ngtcp2_path` over pinned copies of `local`/`remote` and runs `body`
    /// with it. ngtcp2 copies the addrs internally, so the copies need only outlive the call.
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

    /// Runs an ngtcp2 *write* (`body`) with an `ngtcp2_path` over owned buffers,
    /// returning the result and the carrier its reported path maps to. The buffers are
    /// mandatory: every write copies the chosen 4-tuple into `path`, so NULL would crash.
    private func writeReportingCarrier<R>(
        _ body: (UnsafeMutablePointer<ngtcp2_path>) -> R
    ) -> (result: R, carrier: QUICDatagramCarrier?) {
        var local = sockaddr_storage()
        var remote = sockaddr_storage()
        let cap = ngtcp2_socklen(MemoryLayout<sockaddr_storage>.size)
        return withUnsafeMutablePointer(to: &local) { lp in
            withUnsafeMutablePointer(to: &remote) { rp in
                var path = ngtcp2_path(
                    local: ngtcp2_addr(addr: UnsafeMutableRawPointer(lp).assumingMemoryBound(to: sockaddr.self),
                                       addrlen: cap),
                    remote: ngtcp2_addr(addr: UnsafeMutableRawPointer(rp).assumingMemoryBound(to: sockaddr.self),
                                        addrlen: cap),
                    user_data: nil
                )
                let result = withUnsafeMutablePointer(to: &path) { body($0) }
                return (result, carrierForOutPath(path))
            }
        }
    }

    /// Arms a carrier's receive loop, tagging inbound packets with `localAddr` so
    /// ngtcp2 attributes them to the right path. Migration triggers are set elsewhere.
    private func armReceive(_ carrier: QUICDatagramCarrier, localAddr: sockaddr_storage,
                            onError: @escaping (Int32) -> Void) {
        carrier.startReceiving(
            onPacket: { [weak self] data in self?.handleReceivedPacket(data, localAddr: localAddr) },
            onError: onError
        )
    }

    /// Arms the active carrier's receive loop (close on hard error) and migration triggers.
    private func armActiveCarrier(_ carrier: QUICDatagramCarrier, localAddr: sockaddr_storage) {
        armReceive(carrier, localAddr: localAddr) { [weak self] errno in
            self?.close(error: QUICError.connectionFailed("recv errno=\(errno)"))
        }
        installMigrationTriggers(on: carrier)
    }

    /// Sets the reactive (path-down) and proactive (better-path) triggers; no-op when migration is off.
    private func installMigrationTriggers(on carrier: QUICDatagramCarrier) {
        guard migrationEnabled else { return }
        carrier.onPathDown = { [weak self] in self?.attemptReactiveMigration() }
        carrier.onBetterPath = { [weak self] in self?.attemptProactiveMigration() }
    }

    // MARK: - Migration

    /// Migration applies only to the direct carrier, and only if we advertised support.
    private var migrationEnabled: Bool {
        transport == nil && !tuning.disableActiveMigration
    }

    /// A distinct cosmetic local addr for the next migration path, matching the remote's
    /// family. Never hits the wire (ngtcp2 uses it only as path identity), but it must
    /// differ from the current local or ngtcp2 won't see a path change.
    private func makeMigrationLocalAddr() -> sockaddr_storage {
        migrationCounter = migrationCounter &+ 1
        let tag = migrationCounter == 0 ? 1 : migrationCounter
        var storage = sockaddr_storage()
        withUnsafeMutablePointer(to: &storage) { sp in
            if Int32(remoteAddr.ss_family) == AF_INET6 {
                sp.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6 in
                    sin6.pointee = sockaddr_in6()
                    sin6.pointee.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                    sin6.pointee.sin6_family = sa_family_t(AF_INET6)
                    var a = in6addr_any
                    withUnsafeMutableBytes(of: &a) { bytes in
                        bytes[0] = 0xfd          // unique-local prefix
                        bytes[15] = tag
                    }
                    sin6.pointee.sin6_addr = a
                }
            } else {
                sp.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    sin.pointee = sockaddr_in()
                    sin.pointee.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                    sin.pointee.sin_family = sa_family_t(AF_INET)
                    sin.pointee.sin_addr.s_addr = UInt32(tag).bigEndian  // 0.0.0.tag
                }
            }
        }
        return storage
    }

    /// The active path died. Move the live session onto a fresh carrier (picking the new
    /// OS-preferred path) via immediate migration, rather than tearing down every stream.
    /// Any failure falls back to `close()` and the pool reconnects. Runs on `queue`.
    private func attemptReactiveMigration() {
        // A proactive migration is moot now the path is dead; abandon it (not a failure).
        if migrationKind == .proactive {
            migratingCarrier?.close()
            clearMigrationState()
        }

        guard migrationEnabled, state == .connected, migrationKind == nil,
              migrationFailures < Self.maxMigrationFailures,
              let conn = connectionOpaquePointer else {
            close(error: QUICError.connectionFailed("network path lost"))
            return
        }

        let newCarrier = QUICDatagramCarrier(queue: queue)
        var placeholder = sockaddr_storage()
        do {
            try newCarrier.connect(remoteAddr: remoteAddr, localAddr: &placeholder)
        } catch {
            close(error: error)
            return
        }

        let newLocal = makeMigrationLocalAddr()
        let ts = currentTimestamp()
        // Bracket the ngtcp2 call so a synchronously-closing callback can't free `conn`.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        let rv = withPath(local: newLocal, remote: remoteAddr, addrLen: addrLen) { pathPtr in
            ngtcp2_conn_initiate_immediate_migration(conn, pathPtr, ts)
        }
        ngtcp2Busy = prevBusy
        guard rv == 0 else {
            logger.warning("[QUIC] Reactive migration rejected (ngtcp2 \(rv)); reconnecting")
            newCarrier.close()
            migrationFailures += 1
            close(error: QUICError.connectionFailed("migration rejected: \(rv)"))
            return
        }

        // Immediate migration switched the active path: one carrier now (no per-path
        // routing), so route all I/O to it, retire the old one, validate in background.
        migrationKind = .reactive
        let oldCarrier = carrier
        carrier = newCarrier
        localAddr = newLocal
        armActiveCarrier(newCarrier, localAddr: newLocal)
        oldCarrier?.close()
        logger.info("[QUIC] Reactive migration initiated; validating new path")
        writeToUDP()
        rescheduleTimer()
    }

    /// A better path appeared while the current one still works. Validate it on a parallel
    /// carrier and switch only once it passes, keeping the working path until then.
    /// Best-effort: any hitch leaves the current path untouched. Runs on `queue`.
    private func attemptProactiveMigration() {
        guard migrationEnabled, state == .connected, migrationKind == nil,
              migrationFailures < Self.maxMigrationFailures,
              connectionOpaquePointer != nil,
              let oldType = carrier?.currentInterfaceType else { return }

        let target = QUICDatagramCarrier(queue: queue)
        var placeholder = sockaddr_storage()
        do {
            try target.connect(remoteAddr: remoteAddr, localAddr: &placeholder)
        } catch {
            target.close()
            return
        }

        let newLocal = makeMigrationLocalAddr()
        migrationKind = .proactive
        migratingCarrier = target
        migratingLocalAddr = newLocal

        // Before validation, a target failure aborts cleanly; once validating, it's left
        // for path_validation to time out so the in-flight probe isn't misrouted.
        armReceive(target, localAddr: newLocal) { [weak self] _ in
            self?.abortProactiveIfNotValidating()
        }
        target.onPathDown = { [weak self] in self?.abortProactiveIfNotValidating() }

        // If the target never reaches `.ready`, give up rather than wedge `migrationKind`.
        let deadline = DispatchWorkItem { [weak self, weak target] in
            guard let self, let target, self.migratingCarrier === target, !self.proactiveValidating else { return }
            logger.warning("[QUIC] Proactive migration target not ready in \(Int(Self.proactiveReadyTimeout))s; staying put")
            self.abortProactiveMigration(countAsFailure: false)
        }
        proactiveDeadline = deadline
        queue.asyncAfter(deadline: .now() + Self.proactiveReadyTimeout, execute: deadline)

        // Once the target is up and confirmed a *different* interface, start validation.
        // NWConnection buffers the probe until ready.
        target.onReady = { [weak self, weak target] in
            guard let self else { return }
            guard let target, self.migratingCarrier === target,
                  let conn = self.connectionOpaquePointer,
                  let newType = target.currentInterfaceType, newType != oldType else {
                self.abortProactiveMigration(countAsFailure: false)
                return
            }
            let ts = self.currentTimestamp()
            let prevBusy = self.ngtcp2Busy
            self.ngtcp2Busy = true
            let rv = self.withPath(local: newLocal, remote: self.remoteAddr, addrLen: self.addrLen) { pathPtr in
                ngtcp2_conn_initiate_migration(conn, pathPtr, ts)
            }
            self.ngtcp2Busy = prevBusy
            guard rv == 0 else {
                logger.warning("[QUIC] Proactive migration rejected (ngtcp2 \(rv)); staying put")
                self.abortProactiveMigration(countAsFailure: true)
                return
            }
            // Committed: ngtcp2 owns the validation now. Cancel the readiness deadline;
            // path_validation success/failure drives the rest.
            self.proactiveValidating = true
            self.proactiveDeadline?.cancel()
            self.proactiveDeadline = nil
            logger.info("[QUIC] Proactive migration: validating better path")
            self.writeToUDP()
            self.rescheduleTimer()
        }
    }

    /// Drops a proactive-migration target and stays on the current path. `countAsFailure`
    /// is true only when migration genuinely failed (ngtcp2 rejected, or validation
    /// failed); benign aborts pass false. Runs on `queue`.
    private func abortProactiveMigration(countAsFailure: Bool) {
        guard migrationKind == .proactive else { return }
        migratingCarrier?.close()
        clearMigrationState()
        if countAsFailure { migrationFailures += 1 }
    }

    /// Aborts a proactive migration only while still safe — before `initiate_migration`
    /// hands ngtcp2 an active validation. Used by the target's error hooks.
    private func abortProactiveIfNotValidating() {
        guard migrationKind == .proactive, !proactiveValidating else { return }
        abortProactiveMigration(countAsFailure: false)
    }

    /// Clears migration tracking and the readiness deadline; leaves `migrationFailures`. Runs on `queue`.
    private func clearMigrationState() {
        proactiveDeadline?.cancel()
        proactiveDeadline = nil
        proactiveValidating = false
        migratingCarrier = nil
        migrationKind = nil
    }

    /// Result ngtcp2 reports for a migration path; `aborted` means it abandoned the validation, not that the path failed.
    fileprivate enum PathValidationResult { case success, failure, aborted }

    /// ngtcp2 finished (or abandoned) validating a migration path. The trampoline defers
    /// it off the ngtcp2 batch, so `close()` and re-entrant ngtcp2 calls are safe here.
    fileprivate func handlePathValidation(result: PathValidationResult) {
        // ABORTED ≠ failure: ngtcp2 abandons a validation (superseded by a newer
        // migration, or its CID retired) — not a dead path. A reactive switch during
        // proactive validation aborts the proactive pv; that stale ABORTED must not undo
        // it. Retire the target only if a proactive migration is still live.
        if result == .aborted {
            if migrationKind == .proactive { abortProactiveMigration(countAsFailure: false) }
            return
        }
        guard let kind = migrationKind else { return }
        if result == .success {
            if kind == .proactive, let target = migratingCarrier {
                let old = carrier
                carrier = target
                localAddr = migratingLocalAddr
                migratingCarrier = nil       // cleared first so routing settles on `carrier`
                armActiveCarrier(target, localAddr: localAddr)
                old?.close()
            }
            clearMigrationState()
            migrationFailures = 0
            logger.info("[QUIC] Migration validated; new path active")
        } else {
            logger.warning("[QUIC] Migration path validation failed")
            if kind == .proactive {
                abortProactiveMigration(countAsFailure: true)
            } else {
                clearMigrationState()
                close(error: QUICError.connectionFailed("migration path validation failed"))
            }
        }
    }

    /// The carrier for a just-written packet, per the path ngtcp2 reported. Two carriers
    /// exist only during a proactive migration; otherwise this is always `carrier`.
    private func carrierForOutPath(_ path: ngtcp2_path) -> QUICDatagramCarrier? {
        if migratingCarrier != nil, pathLocalMatchesMigrating(path.local) {
            return migratingCarrier
        }
        return carrier
    }

    private func pathLocalMatchesMigrating(_ addr: ngtcp2_addr) -> Bool {
        guard let a = addr.addr, addr.addrlen > 0 else { return false }
        var mig = migratingLocalAddr
        return withUnsafeBytes(of: &mig) { migBytes in
            guard let base = migBytes.baseAddress else { return false }
            return memcmp(a, base, min(Int(addr.addrlen), migBytes.count)) == 0
        }
    }

    /// Sends `length` bytes from `txBuffer` to the given `carrier`. Drop-on-error; ngtcp2 retransmits.
    private func sendTxBuf(length: Int, to carrier: QUICDatagramCarrier?) {
        guard length > 0 else { return }
        if let obfuscator {
            let datagrams = txBuffer.withUnsafeBytes { raw in
                obfuscator.seal(UnsafeRawBufferPointer(rebasing: raw[0..<length]))
            }
            for datagram in datagrams { sendDatagram(datagram, to: carrier) }
            return
        }
        if let transport {
            // Copy out before the next ngtcp2 write reuses txBuffer.
            let datagram = txBuffer.withUnsafeBufferPointer { buffer -> Data in
                Data(bytes: buffer.baseAddress!, count: length)
            }
            transport.sendDatagram(datagram)
            return
        }
        guard let carrier else { return }
        txBuffer.withUnsafeBufferPointer { buffer in
            guard let base = buffer.baseAddress else { return }
            carrier.send(base, length: length)
        }
    }

    /// Routes one wire datagram to the chained transport or the given direct carrier.
    private func sendDatagram(_ datagram: Data, to carrier: QUICDatagramCarrier?) {
        if let transport {
            transport.sendDatagram(datagram)
            return
        }
        guard let carrier else { return }
        datagram.withUnsafeBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            carrier.send(base, length: datagram.count)
        }
    }

    // MARK: ngtcp2 Init

    private func initializeNgtcp2() throws {
        generateConnectionID(&dcid, length: 16)
        generateConnectionID(&scid, length: 16)

        tlsHandler = QUICTLSHandler(serverName: serverName, alpn: alpn)

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
        callbacks.extend_max_local_streams_bidi = quicBidiCreditCB
        callbacks.rand = quicRandCB
        callbacks.get_new_connection_id2 = quicGetNewCIDCB
        callbacks.update_key = ngtcp2_crypto_update_key_cb
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb
        callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb
        callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb
        callbacks.handshake_completed = quicHandshakeCompletedCB
        callbacks.path_validation = quicPathValidationCB
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
        var parameters = ngtcp2_transport_params()
        ngtcp2_swift_transport_params_default(&parameters)
        parameters.initial_max_streams_bidi = tuning.initialMaxStreamsBidi
        parameters.initial_max_streams_uni = tuning.initialMaxStreamsUni
        parameters.initial_max_data = tuning.initialMaxData
        parameters.initial_max_stream_data_bidi_local = tuning.initialMaxStreamDataBidiLocal
        parameters.initial_max_stream_data_bidi_remote = tuning.initialMaxStreamDataBidiRemote
        parameters.initial_max_stream_data_uni = tuning.initialMaxStreamDataUni
        parameters.max_idle_timeout = tuning.maxIdleTimeout
        // Advertise migration support only when we can migrate (direct carrier); chained
        // QUIC honestly declares it won't. ngtcp2 gates *our* migration on the server's
        // flag, not this one — this is just the correct outbound declaration.
        parameters.disable_active_migration = migrationEnabled ? 0 : 1
        if datagramsEnabled {
            parameters.max_datagram_frame_size = Self.maxDatagramFrameSize
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
            guard let ref, let userData = ref.pointee.user_data else { return nil }
            return Unmanaged<QUICConnection>.fromOpaque(userData).takeUnretainedValue().connectionOpaquePointer
        }

        // PMTUD only over the direct carrier: chained probes don't reflect the
        // wire MTU, and a probe failure trips blackhole detection on a routine inner drop.
        let usePMTUD = (transport == nil)
        var connectionOpaquePointer: OpaquePointer?
        let rv = Self.pmtudProbes.withUnsafeBufferPointer { probes -> Int32 in
            if usePMTUD {
                settings.pmtud_probes = probes.baseAddress
                settings.pmtud_probeslen = probes.count
            }
            return ngtcp2_swift_conn_client_new(
                &connectionOpaquePointer, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                &callbacks, &settings, &parameters, nil, &connRefStorage
            )
        }
        guard rv == 0, let connectionOpaquePointer else {
            throw QUICError.connectionFailed("ngtcp2_conn_client_new: \(rv)")
        }
        self.connectionOpaquePointer = connectionOpaquePointer

        // Keep-alive PINGs detect silently-broken UDP paths (NAT rebind, idle sweep).
        ngtcp2_conn_set_keep_alive_timeout(connectionOpaquePointer, tuning.keepAliveTimeout)

        ngtcp2_conn_set_tls_native_handle(connectionOpaquePointer,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256)))

        // Install Brutal after conn_client_new and before any packets, so no
        // stale CUBIC decisions leak through.
        if case .brutal(let initialBps) = tuning.cc {
            let brutal = BrutalCongestionControl(initialBps: initialBps)
            if let ccKey = ngtcp2_swift_install_brutal(connectionOpaquePointer) {
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
            guard let self, let connectionOpaquePointer = self.connectionOpaquePointer else { return }
            if let key = self.brutalCCKey {
                BrutalCongestionControl.unregister(cc: key)
                self.brutalCCKey = nil
                self.brutalCC = nil
            }
            ngtcp2_swift_uninstall_brutal(connectionOpaquePointer)
        }
    }

    // MARK: Packet Processing

    /// A peer CONNECTION_CLOSE is benign (graceful) when it carries transport NO_ERROR (0)
    /// or an application code of 0 / 0x100 (HTTP/3 H3_NO_ERROR).
    private func isBenignConnectionClose(_ ccerr: ngtcp2_ccerr) -> Bool {
        if ccerr.type == NGTCP2_CCERR_TYPE_TRANSPORT {
            return ccerr.error_code == 0
        }
        if ccerr.type == NGTCP2_CCERR_TYPE_APPLICATION {
            return ccerr.error_code == 0 || ccerr.error_code == 0x100
        }
        return false
    }

    fileprivate func handleReceivedPacket(_ data: Data, localAddr: sockaddr_storage) {
        guard let connectionOpaquePointer else { return }

        // Deobfuscate first; a `nil` result is an incomplete fragment or malformed packet — nothing
        // to feed ngtcp2 yet.
        let packet: Data
        if let obfuscator {
            guard let opened = obfuscator.open(data) else { return }
            packet = opened
        } else {
            packet = data
        }

        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        inReadPkt = true
        defer { inReadPkt = false }

        // Guard close() from freeing `conn` while ngtcp2 is still on the stack.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        let rv: Int32 = packet.withUnsafeBytes { raw -> Int32 in
            guard let pointer = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return withPath(local: localAddr, remote: remoteAddr, addrLen: addrLen) { pathPtr in
                ngtcp2_swift_conn_read_pkt(connectionOpaquePointer, pathPtr, &pi, pointer, packet.count, ts)
            }
        }
        ngtcp2Busy = prevBusy

        if rv != 0 {
            // Any non-zero read_pkt return is terminal. Close now: a UDP-only workload
            // has no read pressure and would otherwise sit on a dead connection for the keep-alive window.
            let error: Error
            switch rv {
            case NGTCP2_ERR_DRAINING:
                // Peer sent CONNECTION_CLOSE. A benign code (NO_ERROR / H3_NO_ERROR 0x100)
                // is a graceful end-of-connection.
                if let ccerr = ngtcp2_conn_get_ccerr(connectionOpaquePointer), isBenignConnectionClose(ccerr.pointee) {
                    error = QUICError.closedOK
                } else {
                    error = QUICError.closed
                }
            case NGTCP2_ERR_CLOSING:
                error = QUICError.closed
            case NGTCP2_ERR_CALLBACK_FAILURE, NGTCP2_ERR_CRYPTO:
                error = QUICError.handshakeFailed("ngtcp2 error: \(rv)")
            default:
                error = QUICError.connectionFailed("ngtcp2 read_pkt: \(rv)")
            }
            if let callback = connectCompletion {
                connectCompletion = nil
                callback(error)
            }
            close(error: error)
            return
        }
        scheduleFlush()
    }

    fileprivate func writeToUDP() {
        guard let connectionOpaquePointer else { return }
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
            let datagram = head.data
            let flags: UInt32 = pendingDatagrams.count > 1
                ? UInt32(NGTCP2_WRITE_DATAGRAM_FLAG_MORE)
                : 0

            let (nwrite, outCarrier) = writeReportingCarrier { pathPtr in
                datagram.withUnsafeBytes { rawBuf -> ngtcp2_ssize in
                    guard let srcPtr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return 0
                    }
                    return txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                        ngtcp2_swift_conn_write_datagram(
                            connectionOpaquePointer, pathPtr, &pi, destination.baseAddress, destination.count,
                            &accepted, flags, 0, srcPtr, datagram.count, ts
                        )
                    }
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
                logger.warning("[QUIC] Dropping \(datagram.count)-byte datagram: ngtcp2 err \(nwrite)")
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, QUICError.connectionFailed("ngtcp2 write_datagram err \(nwrite)")))
                continue
            }
            if nwrite > 0 {
                sendTxBuf(length: Int(nwrite), to: outCarrier)
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
            if datagram.count > bound {
                logger.warning("[QUIC] Dropping \(datagram.count)-byte datagram: exceeds path-MTU bound (\(bound) B)")
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, QUICError.datagramTooLarge(maxBound: bound)))
                continue
            }
            // Congestion window full; retry on the next writeToUDP.
            break
        }

        while true {
            let (nwrite, outCarrier) = writeReportingCarrier { pathPtr in
                txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                    ngtcp2_swift_conn_write_pkt(connectionOpaquePointer, pathPtr, &pi, destination.baseAddress, destination.count, ts)
                }
            }
            if nwrite <= 0 { break }
            sendTxBuf(length: Int(nwrite), to: outCarrier)
        }

        // Updates conn->tx.pacing.next_ts; without it the pacer is disabled and sends burst cwnd-wide.
        ngtcp2_conn_update_pkt_tx_time(connectionOpaquePointer, ts)

        rescheduleTimer()

        // Fire completions after all ngtcp2 work; safe to re-enter ngtcp2 here.
        for (callback, error) in pendingCompletions { callback?(error) }
    }

    // MARK: Timer

    /// Last deadline armed, to avoid recreating a DispatchSourceTimer on every ACK.
    private var lastScheduledExpiry: UInt64 = 0

    private func rescheduleTimer() {
        guard let connectionOpaquePointer else { return }
        let expiry = ngtcp2_conn_get_expiry(connectionOpaquePointer)

        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        if retransmitTimer == nil {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.setEventHandler { [weak self] in
                guard let self, let connectionOpaquePointer = self.connectionOpaquePointer else { return }
                self.lastScheduledExpiry = 0
                let ts = self.currentTimestamp()
                // handle_expiry may fire CC callbacks; bracket so a close inside is deferred.
                let prevBusy = self.ngtcp2Busy
                self.ngtcp2Busy = true
                let rv = ngtcp2_conn_handle_expiry(connectionOpaquePointer, ts)
                self.ngtcp2Busy = prevBusy
                if rv != 0 {
                    let error = QUICError.connectionFailed("expiry error: \(rv)")
                    if let callback = self.connectCompletion {
                        self.connectCompletion = nil
                        callback(error)
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
        withUnsafeMutableBytes(of: &cid.data) { buffer in
            data.withUnsafeBytes { source in
                buffer.copyMemory(from: UnsafeRawBufferPointer(
                    start: source.baseAddress, count: min(length, buffer.count)))
            }
        }
    }
}

// MARK: - ngtcp2 Callbacks

private func qcFromUserData(_ userData: UnsafeMutableRawPointer?) -> QUICConnection? {
    guard let userData else { return nil }
    let ref = userData.assumingMemoryBound(to: ngtcp2_crypto_conn_ref.self)
    guard let p = ref.pointee.user_data else { return nil }
    return Unmanaged<QUICConnection>.fromOpaque(p).takeUnretainedValue()
}

private let quicClientInitialCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { conn, userData in
    guard let conn else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let dcid = ngtcp2_conn_get_client_initial_dcid(conn) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    let n: UnsafeMutablePointer<UInt8>? = nil
    if ngtcp2_crypto_derive_and_install_initial_key(
        conn, n, n, n, n, n, n, n, n, n, NGTCP2_PROTO_VER_V1, dcid) != 0 {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    guard let connection = qcFromUserData(userData), let tls = connection.tlsHandler else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    var paramsBuffer = [UInt8](repeating: 0, count: 256)
    let paramsLength = ngtcp2_conn_encode_local_transport_params(conn, &paramsBuffer, paramsBuffer.count)
    guard paramsLength >= 0 else { return NGTCP2_ERR_CALLBACK_FAILURE }
    guard let clientHello = tls.buildClientHello(transportParams: Data(paramsBuffer.prefix(Int(paramsLength)))) else {
        return NGTCP2_ERR_CALLBACK_FAILURE
    }
    return clientHello.withUnsafeBytes { buffer -> Int32 in
        guard let p = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return NGTCP2_ERR_CALLBACK_FAILURE
        }
        return ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL, p, clientHello.count)
    }
}

private let quicRecvCryptoDataCB: @convention(c) (
    OpaquePointer?, ngtcp2_encryption_level, UInt64,
    UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { conn, level, _, data, datalen, userData in
    guard let conn, let data, datalen > 0 else { return 0 }
    guard let connection = qcFromUserData(userData), let tls = connection.tlsHandler else {
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
) -> Int32 = { conn, flags, sid, offset, data, datalen, userData, _ in
    guard let conn, let connection = qcFromUserData(userData) else { return 0 }
    let fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0
    if let data, datalen > 0 {
        // Zero-copy view into ngtcp2's buffer; the handler must copy before returning.
        let view = Data(
            bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
            count: datalen,
            deallocator: .none
        )
        connection.streamDataHandler?(sid, view, fin)
    } else if fin {
        connection.streamDataHandler?(sid, Data(), true)
    }
    // FC window is extended only when the app consumes data (backpressure).
    return 0
}

/// Releases retained heap copies once a contiguous prefix of sent data is acked
/// (`offset + datalen` is the new acked end). Runs on `queue`.
private let quicAckedCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, streamId, offset, datalen, userData, _ in
    guard let connection = qcFromUserData(userData) else { return 0 }
    connection.releaseAckedStreamData(streamId: streamId, ackedOffset: offset + datalen)
    return 0
}

/// Mirrors `NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET` from ngtcp2.h —
/// the bare `#define` isn't imported into Swift.
private let ngtcp2StreamCloseFlagAppErrorCodeSet: UInt32 = 0x01

/// QUIC application close codes that signal a graceful end-of-stream rather than a
/// failure: 0 (QUIC "no error") and 0x100 (HTTP/3 H3_NO_ERROR).
private func isBenignQUICCloseCode(_ code: UInt64) -> Bool {
    code == 0x00 || code == 0x100
}

/// Fires after both directions of a stream terminate. `recv_stream_data` doesn't
/// fire for RESET_STREAM, so this is the app's only signal the stream is gone.
private let quicStreamCloseCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, flags, sid, appErrorCode, userData, _ in
    guard let connection = qcFromUserData(userData) else { return 0 }
    let hasError = (flags & ngtcp2StreamCloseFlagAppErrorCodeSet) != 0
    let error: Error? = (hasError && !isBenignQUICCloseCode(appErrorCode))
        ? QUICConnection.QUICError.streamClosedWithError(appErrorCode: appErrorCode)
        : nil
    // Pending writes always fail (the stream is gone), but a benign code is a clean
    // read-side EOF, so only `streamTerminationHandler` distinguishes the two.
    connection.failPendingWrites(
        streamId: sid,
        error: error ?? QUICConnection.QUICError.closed
    )
    connection.releaseStreamSendState(streamId: sid)
    connection.streamTerminationHandler?(sid, error)
    return 0
}

/// Fires on peer RESET_STREAM, before `stream_close`, so pending receives fail fast.
private let quicStreamResetCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, sid, _, appErrorCode, userData, _ in
    guard let connection = qcFromUserData(userData) else { return 0 }
    let error: Error? = isBenignQUICCloseCode(appErrorCode)
        ? nil
        : QUICConnection.QUICError.streamReset(appErrorCode: appErrorCode)
    connection.failPendingWrites(streamId: sid, error: error ?? QUICConnection.QUICError.closed)
    connection.streamTerminationHandler?(sid, error)
    return 0
}

private let quicBidiCreditCB: @convention(c) (
    OpaquePointer?, UInt64, UnsafeMutableRawPointer?
) -> Int32 = { _, maxStreams, userData in
    guard let connection = qcFromUserData(userData) else { return 0 }
    connection.queue.async { [weak connection] in
        connection?.bidiCreditHandler?(maxStreams)
    }
    return 0
}

private let quicRandCB: @convention(c) (
    UnsafeMutablePointer<UInt8>?, Int, UnsafePointer<ngtcp2_rand_ctx>?
) -> Void = { destination, length, _ in
    guard let destination else { return }
    _ = SecRandomCopyBytes(kSecRandomDefault, length, destination)
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

private let quicHandshakeCompletedCB: @convention(c) (
    OpaquePointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, userData in
    guard let connection = qcFromUserData(userData) else { return 0 }
    connection.queue.async {
        connection.state = .connected
        connection.connectCompletion?(nil)
        connection.connectCompletion = nil
    }
    return 0
}

/// Fires when a migration path finishes — or is abandoned during — validation. Defers
/// off the ngtcp2 batch (like the handshake callback) so promotion/close can re-enter
/// ngtcp2 safely. ABORTED is mapped distinctly (see `handlePathValidation`).
private let quicPathValidationCB: @convention(c) (
    OpaquePointer?, UInt32, UnsafePointer<ngtcp2_path>?, UnsafePointer<ngtcp2_path>?,
    ngtcp2_path_validation_result, UnsafeMutableRawPointer?
) -> Int32 = { _, _, _, _, res, userData in
    guard let connection = qcFromUserData(userData) else { return 0 }
    let result: QUICConnection.PathValidationResult
    if res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS {
        result = .success
    } else if res == NGTCP2_PATH_VALIDATION_RESULT_FAILURE {
        result = .failure
    } else {
        result = .aborted
    }
    connection.queue.async { connection.handlePathValidation(result: result) }
    return 0
}

private let quicRecvDatagramCB: @convention(c) (
    OpaquePointer?, UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutableRawPointer?
) -> Int32 = { _, _, data, datalen, userData in
    guard let data, datalen > 0, let connection = qcFromUserData(userData) else { return 0 }
    // Zero-copy view; handler must not retain it past this synchronous call.
    let view = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
        count: datalen,
        deallocator: .none
    )
    connection.datagramHandler?(view)
    return 0
}
