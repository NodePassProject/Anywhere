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

private let logger = AnywhereLogger(category: "QUIC")

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
        /// `stream_close` fired with an application error code set — either
        /// the peer sent a terminating frame with a non-zero code or the
        /// local endpoint shut the stream down with one.
        case streamClosedWithError(appErrorCode: UInt64)
        /// A queued DATAGRAM exceeded the path's current maximum frame
        /// size and was dropped. `maxBound` is the size the upper layer
        /// should re-fragment to for a retry.
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

    /// Optional datagram transport; when set, ngtcp2 rides it instead of a
    /// kernel socket. Used to route QUIC through a proxy chain's UDP relay.
    private let transport: QUICDatagramTransport?

    fileprivate var state: State = .idle
    let queue: DispatchQueue
    private static let queueKey = DispatchSpecificKey<Bool>()

    fileprivate var conn: OpaquePointer?
    private var connRefStorage = ngtcp2_crypto_conn_ref()

    /// True while `handleReceivedPacket` is inside `ngtcp2_swift_conn_read_pkt`.
    /// Callbacks fired by ngtcp2 during read (e.g. recv_stream_data → app →
    /// `extendStreamOffset`) must not trigger a reentrant write — the
    /// tail-flush at the end of `handleReceivedPacket` covers it.
    private var inReadPkt = false

    /// True while a `conn`-holding ngtcp2 batch is executing on `queue`
    /// (`read_pkt`, `writeToUDP`, `flushPendingWrites`, `handle_expiry`). Each
    /// of these keeps a local `conn` pointer live across app callbacks /
    /// completions it fires synchronously. A `close()` requested from inside
    /// one — e.g. a `pendingWrites` completion in `flushPendingWrites`, or a
    /// per-datagram completion fired by `writeToUDP` — must NOT run
    /// `ngtcp2_conn_del` now: the batch above us still holds that `conn` and
    /// dereferences it again, so freeing it strands the pointer and the next
    /// ngtcp2 call faults inside `ngtcp2_cpymem` (memcpy on freed conn state).
    /// When set, `close()` defers its teardown one queue cycle, by which point
    /// the batch has unwound. Saved/restored rather than plain-set so nested
    /// batches (flushPendingWrites → writeStreamSync → writeToUDP) compose.
    private var ngtcp2Busy = false

    /// Set when an operation (e.g. `extendStreamOffset`) has queued a
    /// MAX_STREAM_DATA/MAX_DATA update that needs to go out but we don't
    /// want to flush synchronously on the hot path.  Drained at the end
    /// of the current queue cycle via a single coalesced `writeToUDP`.
    private var flushScheduled = false

    /// Guarantees the terminal teardown in `close()` runs exactly once, on
    /// `queue`, retaining `self` until it completes — so the ngtcp2 conn, UDP
    /// socket, and dispatch sources are always freed even when `close()` is
    /// dispatched from off-queue on the connection's last reference.
    private let closeLatch = CloseOnce()

    /// Connected UDP socket for the direct-dial path. `nil` when QUIC rides a
    /// `QUICDatagramTransport` (chained), and before/after the socket is open.
    private var quicSocket: QUICSocket?

    private var localAddr = sockaddr_storage()
    private var remoteAddr = sockaddr_storage()
    /// Actual sockaddr size (either `sockaddr_in` or `sockaddr_in6`).
    private var addrLen: Int = MemoryLayout<sockaddr_in>.size

    fileprivate var tlsHandshaker: QUICTLSHandler?

    private var retransmitTimer: DispatchSourceTimer?

    private var dcid = ngtcp2_cid()
    private var scid = ngtcp2_cid()

    fileprivate var connectCompletion: ((Error?) -> Void)?
    /// Stream data delivery. The `Data` is a zero-copy view into ngtcp2's
    /// receive buffer and is only valid for the duration of this synchronous
    /// call — the handler MUST consume or copy it before returning. Dispatching
    /// the view to another queue without copying is a use-after-free.
    var streamDataHandler: ((Int64, Data, Bool) -> Void)?
    /// Called when a stream is terminated at the QUIC level.
    /// - `error == nil`: clean close (both sides FIN'd with no app error code).
    /// - `error != nil`: RESET_STREAM from the peer, or `stream_close` fired
    ///   with an app error code set. The carried error wraps the app code so
    ///   callers can distinguish abort vs. orderly close.
    ///
    /// Fires synchronously on `queue` from inside ngtcp2's read_pkt callback,
    /// for both the `stream_reset` and `stream_close` ngtcp2 hooks. Handlers
    /// are called once per underlying event, so the Hysteria layer may see
    /// reset followed by close on the same stream — idempotent handling is
    /// required on the receiver side.
    var streamTerminationHandler: ((Int64, Error?) -> Void)?
    /// Called when a QUIC DATAGRAM frame is received.
    var datagramHandler: ((Data) -> Void)?
    /// Called when the QUIC connection is closed (draining, error, etc.).
    /// Allows the session to react immediately rather than discovering it on the next operation.
    var connectionClosedHandler: ((Error) -> Void)?

    /// When `.brutal` is selected, the Swift-side CC state. Kept alive here
    /// because its lifetime must match the QUIC connection.
    private var brutalCC: BrutalCongestionControl?
    /// `ngtcp2_cc *` returned by `ngtcp2_swift_install_brutal`. Used as the
    /// registry key so the `@_cdecl` trampolines can dispatch to `brutalCC`.
    private var brutalCCKey: OpaquePointer?

    /// When true, advertises DATAGRAM frame support in transport params.
    private let datagramsEnabled: Bool
    /// Maximum DATAGRAM frame size advertised to the peer (what we can receive).
    static let maxDatagramFrameSize: UInt64 = 65535

    /// Pending writes that were blocked by stream flow control.
    /// Flushed when incoming packets extend the window (MAX_STREAM_DATA).
    private var pendingWrites: [PendingWrite] = []

    private struct PendingWrite {
        let streamId: Int64
        var data: Data
        let fin: Bool
        let completion: (Error?) -> Void
    }

    /// Stream bytes ngtcp2 still references for retransmission, per stream, in
    /// ascending end-offset order. ngtcp2's `writev_stream` is zero-copy: it
    /// retains the *pointer* we pass (only the `ngtcp2_vec` descriptors are
    /// copied — see ngtcp2_conn.c `conn_write_pkt`) in its retransmission queue
    /// and re-reads the bytes on every retransmission until they're acked.
    /// ngtcp2.h: "The caller must keep the portion of data covered by
    /// |*pdatalen| bytes in tact until acked_stream_data_offset indicates that
    /// they are acknowledged by a remote endpoint or the stream is closed." A
    /// pointer from `Data.withUnsafeBytes` dies with its closure, so each
    /// accepted write is copied into a heap buffer held here until
    /// `acked_stream_data_offset` (`releaseAckedStreamData`) frees it, the
    /// stream closes, or the connection tears down. Touched only on `queue`.
    private var inflightStreamBuffers: [Int64: [InflightStreamBuffer]] = [:]
    /// Absolute tx offset per stream — a mirror of ngtcp2's `strm->tx.offset`
    /// (every accepted byte goes through `writeStreamSync`), used to label each
    /// retained buffer so the ack callback can match it against the acked
    /// offset. Touched only on `queue`.
    private var streamTxOffset: [Int64: UInt64] = [:]

    /// Stable heap copy of stream bytes handed to ngtcp2, owning its allocation
    /// for as long as ngtcp2 may retransmit it. See `inflightStreamBuffers`.
    private final class InflightStreamBuffer {
        let storage: UnsafeMutableBufferPointer<UInt8>
        /// Absolute stream offset one past this buffer's last accepted byte.
        var endOffset: UInt64 = 0

        /// Copies `data` (which must be non-empty) into a fresh allocation.
        init(copying data: Data) {
            let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            _ = data.copyBytes(to: buf)
            storage = buf
        }

        deinit { storage.deallocate() }
    }

    /// Pending datagrams waiting to be sent. Drained in `writeToUDP()` where
    /// they get first priority for congestion window space.
    ///
    /// Bounded at `maxPendingDatagrams` with drop-oldest semantics when the
    /// congestion window can't keep up — preserves UDP's lossy contract
    /// rather than letting memory grow without bound under a backed-up path.
    /// Matches the receive side's `HysteriaUDPConnection.maxQueuedPackets`.
    ///
    /// Each entry carries an optional per-datagram completion. The
    /// completion fires on the final outcome (sent, dropped due to MTU,
    /// dropped due to queue overflow, dropped on close) so the upper layer
    /// can react to a `datagramTooLarge` outcome by re-fragmenting at the
    /// reported bound — without it, PMTU changes between fragmentation and
    /// send would silently lose data with no signal to the caller.
    private struct PendingDatagram {
        let data: Data
        let completion: ((Error?) -> Void)?
    }
    private var pendingDatagrams: [PendingDatagram] = []
    private static let maxPendingDatagrams = 1024
    private var didWarnDatagramOverflow = false

    static let maxUDPPayload = 1452

    /// Per-packet UDP payload ceiling when QUIC rides a
    /// `QUICDatagramTransport` instead of a kernel socket. Sized to the
    /// RFC 9000 §14 initial PMTU floor (1200 B) so every outer packet
    /// fits in any conformant inner UDP transport — the inner can deliver
    /// 1200 B as one DATAGRAM (its own MTU is at least the same floor,
    /// typically 1408 B after QUIC overhead). At the previous 1452 B the
    /// outer routinely needed the inner to fragment, costing one extra
    /// inner-Hysteria header per packet (~16 B per fragment, plus a
    /// second inner-QUIC packet's worth of header per outer packet); and
    /// when the inner's path collapsed below the outer's static size,
    /// loss recovery looped at the same too-large size forever (PMTUD is
    /// disabled for chained transports so the outer can't naturally
    /// shrink). 1200 is the smallest size that can never be too large.
    static let chainedMaxUDPPayload = 1200

    /// Reusable tx buffer. ngtcp2 is single-threaded on `queue` so a single
    /// slot is sufficient; bursts are amortised at the dispatch-source level
    /// (the receive side drains the kernel queue to EAGAIN on every wake-up),
    /// not via a per-syscall batch. The matching rx buffer lives in
    /// ``QUICSocket``.
    private var txBuf = [UInt8](repeating: 0, count: QUICConnection.maxUDPPayload)

    /// Payload sizes PMTUD probes. Must be in (1200, max_tx_udp_payload_size]
    /// — ngtcp2 silently skips probes above `hard_max_udp_payload_size =
    /// min(remote_max_udp_payload_size, settings.max_tx_udp_payload_size)`.
    /// Ascending so each success advances to the next size.
    /// Values copied internally by ngtcp2 at conn-new time.
    private static let pmtudProbes: [UInt16] = [1350, 1400, 1452]

    // MARK: Init

    /// Returns true if the caller is already executing on this connection's queue.
    var isOnQueue: Bool { DispatchQueue.getSpecific(key: Self.queueKey) == true }

    init(host: String, port: UInt16, serverName: String? = nil, alpn: [String] = ["h3"],
         datagramsEnabled: Bool = false, tuning: QUICTuning,
         transport: QUICDatagramTransport? = nil) {
        self.host = host
        self.port = port
        self.serverName = serverName ?? host
        self.alpn = alpn
        self.datagramsEnabled = datagramsEnabled
        self.tuning = tuning
        self.transport = transport
        self.queue = DispatchQueue(label: "com.argsment.Anywhere.quic")
        queue.setSpecific(key: Self.queueKey, value: true)
    }

#if DEBUG
    /// Leak tripwire: by the time a connection is freed, `close()` (or a
    /// setup-failure path) must have released the socket, ngtcp2 conn, and
    /// dispatch sources. A live handle here means it was dropped without
    /// closing — the exact leak this and `CloseOnce` exist to surface. Reads
    /// are race-free: deinit implies no other reference, so nothing else can
    /// touch this state. DEBUG-only; never aborts a shipping build.
    deinit {
        assert(quicSocket == nil && conn == nil && retransmitTimer == nil,
               "QUICConnection leaked: freed without close() (socketOpen=\(quicSocket?.isOpen ?? false), connSet=\(conn != nil))")
    }
#endif

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

    /// Extends both the stream-level and connection-level flow control windows.
    /// Called when the application has consumed `count` bytes from a stream,
    /// allowing the server to send more data.
    func extendStreamOffset(_ streamId: Int64, count: Int) {
        guard count > 0 else { return }
        // All ngtcp2_conn_* calls and `flushScheduled`/`inReadPkt` mutation
        // must happen on the QUIC queue.  Off-queue callers bounce through
        // an async; the same async coalesces with any pending flush.
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
        // Coalesce MAX_STREAM_DATA/MAX_DATA flushes: on bulk receive the
        // reader drains one ~1300-byte chunk at a time, each triggering an
        // ack.  Flushing a full writeToUDP cycle per ack burnt CPU on the
        // hot path.  ngtcp2 queues the frame internally; schedule one
        // coalesced flush per queue cycle and let the next organic write
        // (or this async bounce) carry it out.
        //
        // Inside read_pkt: skip entirely — handleReceivedPacket's tail-flush
        // already drains pending updates.  Outside read_pkt: schedule once
        // via queue.async so a run of acks merges into one writeToUDP.
        if inReadPkt { return }
        if flushScheduled { return }
        flushScheduled = true
        queue.async { [weak self] in
            guard let self else { return }
            self.flushScheduled = false
            self.writeToUDP()
        }
    }

    /// Shuts down a stream (sends RESET_STREAM + STOP_SENDING).
    /// This frees the stream ID slot so the server grants new ones via MAX_STREAMS.
    /// - Parameter appErrorCode: Application-layer error code (e.g. an HTTP/3
    ///   error code per RFC 9114 §8.1). Defaults to `H3_NO_ERROR` (0x100).
    func shutdownStream(_ streamId: Int64, appErrorCode: UInt64 = 0x0100) {
        queue.async { [weak self] in
            guard let self, let conn = self.conn else { return }
            ngtcp2_conn_shutdown_stream(conn, 0, streamId, appErrorCode)
            self.writeToUDP()
        }
    }

    func writeStream(_ streamId: Int64, data: Data, fin: Bool = false,
                     completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // See `writeDatagram` — split the guards so the user's
            // completion fires once even when `self` is gone.
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

    /// Queues a QUIC DATAGRAM frame for sending.
    ///
    /// The datagram is sent on the next `writeToUDP()` cycle, where it gets
    /// first priority for congestion window space (coalesced with ACKs and
    /// control frames).  QUIC datagrams are unreliable — if the congestion
    /// window is still exhausted after retries, the datagram is silently
    /// dropped (same as UDP packet loss).
    ///
    /// Only returns an error for fatal issues (connection closed, payload
    /// exceeds the remote's max_datagram_frame_size).
    func writeDatagram(_ data: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // Two-stage guard so the user's completion always fires once,
            // even when the connection has gone away. A single combined
            // `guard let self, …` would silently abandon the completion
            // (and any batch tracker it carries) on the `self == nil` arm.
            guard let self else { completion(QUICError.closed); return }
            guard self.conn != nil, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            self.enqueueDatagrams([PendingDatagram(data: data, completion: completion)])
            self.writeToUDP()
        }
    }

    /// Queues multiple QUIC DATAGRAM frames for sending atomically.
    ///
    /// All datagrams are appended to the pending queue before a single
    /// `writeToUDP()` cycle, preventing interleaving with datagrams from
    /// other concurrent callers. `completion` fires once, after every
    /// datagram in the batch has reached a terminal state — with the first
    /// error observed across the batch, or `nil` if all were accepted.
    /// This lets a caller that fragmented one upper-layer packet into N
    /// datagrams react to the aggregate outcome (e.g. retry the whole
    /// payload at a smaller MTU on `datagramTooLarge`).
    func writeDatagrams(_ datagrams: [Data], completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            // See `writeDatagram` for why the guards are split — the batch
            // tracker holds the caller's completion, and dropping it on
            // self == nil would strand the caller (and any further
            // datagrams it intended to send).
            guard let self else { completion(QUICError.closed); return }
            guard self.conn != nil, self.state == .connected else {
                completion(QUICError.closed)
                return
            }
            if datagrams.isEmpty {
                completion(nil)
                return
            }
            // Shared per-batch tracker. `onEach` runs on `queue` (all
            // datagram completions are fired from `writeToUDP` or `close`,
            // both on queue), so the unsynchronised counter/error capture
            // is safe.
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

    /// Appends datagrams to `pendingDatagrams`, enforcing the
    /// `maxPendingDatagrams` cap by dropping oldest entries when a sender
    /// outruns the congestion window. Dropped entries have their per-datagram
    /// completion fired with `QUICError.closed`-style overflow signal —
    /// without that, a backed-up path would silently strand the caller's
    /// completion and the upper layer could never observe the drop.
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

    /// Maximum datagram payload size we can both encode and ship in one UDP
    /// packet to the remote endpoint. Returns 0 when datagrams aren't
    /// supported, the connection isn't ready, or the path MTU has collapsed
    /// below the QUIC packet-header floor.
    ///
    /// Two ceilings apply and we take the lower:
    /// - **Remote frame ceiling**: the peer's `max_datagram_frame_size`, minus
    ///   the DATAGRAM frame's own overhead (1 byte type + length varint). For
    ///   payloads up to 16383 bytes the varint is 2 bytes, so 3 bytes total.
    ///   A frame larger than this gets rejected by ngtcp2 with
    ///   `NGTCP2_ERR_INVALID_ARGUMENT`.
    /// - **Path-MTU ceiling**: the maximum UDP payload ngtcp2 will currently
    ///   emit on this path, minus the QUIC packet headers wrapping the frame
    ///   (short-header byte, dest-CID, packet number, AEAD tag, DATAGRAM frame
    ///   header). The worst case is: 1 (flags) + 20 (max DCID per ngtcp2) +
    ///   4 (largest packet-number encoding) + 16 (AES-GCM tag) + 3 (DATAGRAM
    ///   frame header with 2-byte length varint) = 44 bytes. Must be the
    ///   worst case, not the typical case: an under-estimate leaves
    ///   `write_datagram` returning `nwrite=0, accepted=0` indefinitely, and
    ///   the `writeToUDP` loop's `dgram.count > bound` check treats that
    ///   payload as CW-blocked rather than too-large — wedging the head of
    ///   the queue against the same condition every retry until something
    ///   else changes the path MTU. 44 ensures that any payload we hand to
    ///   ngtcp2 will actually fit on the wire, or trip the `> bound` branch
    ///   so the upper layer can re-fragment.
    ///
    /// Must be called on `queue` — reads ngtcp2 state that is only mutated
    /// there (transport params, current path MTU). Off-queue calls would
    /// race with the read loop's `read_pkt` cycle and any of ngtcp2's path
    /// validation / PMTUD updates.
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

    /// Writes stream data, queuing any remainder that can't be sent due to
    /// flow control. Queued data is flushed when incoming packets extend the
    /// window (MAX_STREAM_DATA).
    private func writeStreamImpl(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool,
                                  completion: @escaping (Error?) -> Void) {
        let sent = writeStreamSync(conn: conn, streamId: streamId,
                                    data: data, fin: fin)

        if sent >= data.count {
            completion(nil)
        } else {
            // Stream flow control blocked — queue remainder for later
            let remaining = Data(data[sent...])
            pendingWrites.append(PendingWrite(
                streamId: streamId, data: remaining,
                fin: fin, completion: completion
            ))
        }
    }

    /// Writes as much stream data as possible synchronously. Returns the
    /// number of bytes accepted by ngtcp2. Each ngtcp2 packet is flushed
    /// to the socket immediately via `send(2)`; the tail `writeToUDP`
    /// call drains any remaining control/datagram packets and updates the
    /// pacing deadline.
    private func writeStreamSync(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool) -> Int {
        let ts = currentTimestamp()
        var offset = 0

        // Empty payload: nothing to retain or feed through the data loop
        // (preserves prior behavior — a bare FIN was never emitted here).
        guard !data.isEmpty else {
            writeToUDP()
            return 0
        }

        // ngtcp2 keeps the pointer we hand it — not a copy — until the bytes
        // are acked (see `inflightStreamBuffers`). Copy into a buffer that
        // outlives this call and feed ngtcp2 pointers into it; once we know how
        // much was accepted, register it for release by the ack callback.
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

        // Retain the buffer iff ngtcp2 accepted (and may thus retransmit) some
        // bytes; `acked_stream_data_offset` frees it once they're acked. When
        // nothing was accepted, `inflight` is released here, freeing storage.
        if offset > 0 {
            inflight.endOffset = baseOffset + UInt64(offset)
            inflightStreamBuffers[streamId, default: []].append(inflight)
            streamTxOffset[streamId] = inflight.endOffset
        }

        writeToUDP()
        return offset
    }

    /// Frees the heap copies of stream bytes ngtcp2 has now acknowledged.
    /// ngtcp2 reports the contiguous acked prefix (`offset + datalen`); any
    /// buffer ending at or before it can never be retransmitted, so its storage
    /// is safe to release. Buffers past the prefix stay — ngtcp2 may still
    /// resend them. Runs on `queue` (invoked synchronously from read_pkt's
    /// ack handling).
    fileprivate func releaseAckedStreamData(streamId: Int64, ackedOffset: UInt64) {
        guard var buffers = inflightStreamBuffers[streamId] else { return }
        // Appended in ascending end-offset order, so the acked ones are a prefix.
        var drop = 0
        while drop < buffers.count && buffers[drop].endOffset <= ackedOffset {
            drop += 1
        }
        guard drop > 0 else { return }
        buffers.removeFirst(drop)  // releases each buffer → deinit frees storage
        inflightStreamBuffers[streamId] = buffers.isEmpty ? nil : buffers
    }

    /// Drops all retained send state for a stream. Called from `stream_close`,
    /// after which ngtcp2 has freed the stream and no longer references our
    /// buffers, and on connection teardown.
    fileprivate func releaseStreamSendState(streamId: Int64) {
        inflightStreamBuffers[streamId] = nil
        streamTxOffset[streamId] = nil
    }

    /// Fails any queued pendingWrites that target a terminated stream. Called
    /// from the `stream_close` / `stream_reset` callbacks — after the stream
    /// is gone, those writes can never drain (ngtcp2 will return
    /// `STREAM_NOT_FOUND` / `STREAM_SHUT_WR` on every retry), so their
    /// completions would leak. Runs inline on `queue`.
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

    /// Retries pending writes that were blocked by stream flow control.
    /// Called after processing incoming packets which may contain MAX_STREAM_DATA.
    private func flushPendingWrites() {
        guard !pendingWrites.isEmpty, let conn else { return }
        // Each `pw.completion(nil)` in the loop below runs app code synchronously
        // and may request a close. Keep `conn` alive for the whole loop: without
        // this guard a completion that tore the connection down would free the
        // `conn` captured above, and the next iteration's `writeStreamSync` would
        // fault in ngtcp2's `ngtcp2_cpymem`. `close()` defers while this is set.
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
        // If a close is requested while a `conn`-holding ngtcp2 batch is on the
        // stack (a callback during read_pkt, or a completion fired by
        // writeToUDP / flushPendingWrites), the batch above us still holds and
        // will reuse the `conn` pointer. Running `ngtcp2_conn_del` synchronously
        // here would dangle it — the next ngtcp2 call faults in `ngtcp2_cpymem`.
        // Defer the teardown one queue cycle (strong `self`, like `CloseOnce`,
        // so the last-reference case can't skip it); by then the batch has
        // returned and no local `conn` is live. Off-queue closes already defer
        // through `CloseOnce`, so this only covers the on-queue reentrant case.
        if ngtcp2Busy && isOnQueue {
            queue.async { self.close(error: error) }
            return
        }
        // `CloseOnce` runs this once on `queue`, strong-capturing `self` so the
        // ngtcp2 conn / UDP socket / dispatch sources are always freed — even
        // when `close()` is the connection's last reference (e.g. dispatched
        // off-queue by `HysteriaSession`/`closeAll`). When already on `queue`
        // (e.g. handleReceivedPacket detecting DRAINING) it runs synchronously
        // so pool-visible state updates before new streams can be handed out.
        closeLatch.fire(on: queue, runningOnQueue: isOnQueue) {
            guard self.state != .closed else { return }
            // Any close that happens before we reached `.connected` means the
            // TLS handshake didn't complete — invalidate any cached session
            // ticket for this (SNI, ALPN) so the next attempt does a full
            // handshake instead of replaying a ticket whose keys the server
            // may have rotated. Without this, one bad ticket produces a
            // permanent HANDSHAKE_TIMEOUT loop across every future session.
            if self.state != .connected {
                QUICSessionTicketCache.invalidate(serverName: self.serverName, alpn: self.alpn)
            }
            self.retransmitTimer?.cancel()
            self.retransmitTimer = nil
            // Drop the Brutal CC registration before `ngtcp2_conn_del` frees
            // `conn->cc` — trampolines fired after this point would otherwise
            // look up a dangling key.
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
            // Fail any pending writes; fail pending datagrams' completions.
            let writes = self.pendingWrites
            self.pendingWrites.removeAll()
            let dgrams = self.pendingDatagrams
            self.pendingDatagrams.removeAll()
            // `conn` is gone, so the retained stream send buffers can no longer
            // be retransmitted — free their heap copies (deinit deallocates).
            self.inflightStreamBuffers.removeAll()
            self.streamTxOffset.removeAll()
            let closeError = error ?? QUICError.closed
            // Surface the close to a still-pending connect callback. Most
            // close paths (DRAINING in handleReceivedPacket, handshake
            // crypto failure, timer expiry, transport errorHandler) clear
            // and fire `connectCompletion` themselves before reaching
            // here, but the socket's recv error handler (``QUICSocket``'s
            // `onError`) on a non-EAGAIN errno calls `close(error:)`
            // directly — without this the connect callback would leak and
            // any caller that hadn't installed `connectionClosedHandler`
            // first would hang on a dropped socket during the handshake
            // window.
            if let cb = self.connectCompletion {
                self.connectCompletion = nil
                cb(closeError)
            }
            for pw in writes { pw.completion(closeError) }
            for d in dgrams { d.completion?(closeError) }
            self.connectionClosedHandler?(closeError)
            self.connectionClosedHandler = nil
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
        // Non-blocking SOCK_DGRAM driven by a DispatchSource for reads.
        do {
            populateRemoteAddr()
            guard remoteAddr.ss_family != 0 else {
                throw QUICError.connectionFailed("DNS lookup failed for \(host)")
            }
            let sock = QUICSocket(queue: queue, receiveBufferSize: Self.maxUDPPayload)
            try sock.connect(remoteAddr: remoteAddr, localAddr: &localAddr, addrLen: addrLen)
            quicSocket = sock
            try initializeNgtcp2()
            state = .handshaking
            // Reads fire on `queue` and drive ngtcp2 inline; a zero-copy view
            // goes straight to handleReceivedPacket. A terminal recv error
            // closes the connection directly (see the connectCompletion note
            // in close()).
            sock.startReceiving(
                onPacket: { [weak self] data in self?.handleReceivedPacket(data) },
                onError: { [weak self] err in
                    self?.close(error: QUICError.connectionFailed("recv errno=\(err)"))
                }
            )
            writeToUDP()    // send client initial
            rescheduleTimer()
        } catch {
            // Clear `connectCompletion` before firing so any later async
            // path (e.g. a stray expiry/recv that slipped past closeSocket)
            // can't double-fire it.
            state = .closed
            closeSocket()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Wires ngtcp2 to a ``QUICDatagramTransport`` (used for chained QUIC
    /// dials). Placeholder addrs are safe because callers set
    /// `disable_active_migration`, so ngtcp2 never inspects them.
    private func setupTunnelTransport(
        transport: QUICDatagramTransport,
        completion: @escaping (Error?) -> Void
    ) {
        do {
            configurePlaceholderAddrs()
            try initializeNgtcp2()
            state = .handshaking
            // Hop to our queue: ngtcp2 must only be touched from `queue`.
            // Even if the inner relay already has buffered datagrams,
            // `handleReceivedPacket` runs via `queue.async` and can't
            // preempt the rest of this synchronous setup block — so the
            // arm-before-`writeToUDP` order matches the raw-socket path
            // and is race-free.
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
            // See `setupRawSocket` for why we nil this before firing.
            state = .closed
            transport.cancel()
            connectCompletion = nil
            completion(error)
        }
    }

    /// Synthesises stable placeholder addrs for `ngtcp2_path`. Values are
    /// unused for routing (the transport delivers packets) but must be
    /// consistent so ngtcp2's path identity check passes.
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
        quicSocket?.close()
        quicSocket = nil
    }

    private func populateRemoteAddr() {
        // Try IPv4 first
        var addr4 = in_addr()
        if inet_pton(AF_INET, host, &addr4) == 1 {
            configureIPv4(addr4)
            return
        }

        // Try IPv6
        var addr6 = in6_addr()
        if inet_pton(AF_INET6, host, &addr6) == 1 {
            configureIPv6(addr6)
            return
        }

        // Cache-backed resolution. A direct getaddrinfo() would block the QUIC
        // queue on a cold system resolver (notably post-wake); DNSResolver
        // returns stale IPs immediately on TTL expiry and refreshes in the
        // background, so only a cold cache miss can block here.
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

    /// Sends one datagram of `length` bytes from `txBuf`. EAGAIN / transport
    /// errors drop the packet; ngtcp2's loss recovery handles the retransmit.
    private func sendTxBuf(length: Int) {
        guard length > 0 else { return }
        if let transport {
            // Detach from `txBuf` — the next ngtcp2 write reuses it.
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
        // Clamp the outer's per-packet UDP payload when riding a chained
        // transport: PMTUD is disabled (see below), so this value never
        // shrinks at runtime — and a static 1452 was larger than typical
        // inner Hysteria DATAGRAM payloads (~1408 B), so every outer
        // packet forced an inner fragmentation cycle. 1200 B is the
        // RFC 9000 §14 PMTU floor and fits in one inner DATAGRAM end-to-end.
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

        // PMTU discovery only makes sense over a real kernel socket. When
        // we're riding a `QUICDatagramTransport` (chained QUIC over a UDP
        // relay), the "path" is virtualized: probes are carried inside the
        // inner protocol, which has its own framing/MTU rules. Successful
        // probes don't prove anything about the wire — they only confirm
        // the inner can carry that size today — and a probe failure trips
        // ngtcp2's blackhole detection on what is, on the wire, a routine
        // inner drop. So skip probes whenever the QUIC layer sits over a
        // non-direct transport rather than a kernel socket.
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

        // Emit a PING after a configurable idle period so a silently-broken
        // UDP path (carrier NAT rebind, server-side idle sweep) surfaces as a
        // loss / idle-close within one retransmission cycle rather than
        // waiting for the next app write to hit CONNECTION_CLOSE. The exact
        // period is per-protocol (see `QUICTuning.keepAliveTimeout`): Naive
        // uses 15 s, Hysteria 10 s.
        ngtcp2_conn_set_keep_alive_timeout(connPtr, tuning.keepAliveTimeout)

        ngtcp2_conn_set_tls_native_handle(connPtr,
            UnsafeMutableRawPointer(bitPattern: UInt(NGTCP2_APPLE_CS_AES_128_GCM_SHA256)))

        // Install Brutal CC on top of the CUBIC state ngtcp2 just set up.
        // Done *after* `ngtcp2_conn_client_new` so the CC struct is valid,
        // and before any packets have been read/sent so no stale CUBIC
        // decisions leak through.
        if case .brutal(let initialBps) = tuning.cc {
            let brutal = BrutalCongestionControl(initialBps: initialBps)
            if let ccKey = ngtcp2_swift_install_brutal(connPtr) {
                BrutalCongestionControl.register(brutal, for: ccKey)
                self.brutalCC = brutal
                self.brutalCCKey = ccKey
            }
        }
    }

    /// Updates the Brutal target send rate (bytes/sec). No-op if this
    /// connection isn't running Brutal. Safe to call off-queue.
    func setBrutalBandwidth(_ bps: UInt64) {
        queue.async { [weak self] in
            self?.brutalCC?.setTargetBandwidth(bps)
        }
    }

    /// Uninstalls Brutal and reverts to ngtcp2's CUBIC. Used when the
    /// Hysteria server responds with `Hysteria-CC-RX: auto`, which means
    /// "drop Brutal and let your own pacer adapt". No-op if Brutal isn't
    /// installed. Safe to call off-queue.
    ///
    /// The Brutal registry entry is dropped BEFORE the CC table is rewired
    /// so any in-flight trampoline that loses the race finds no entry and
    /// no-ops (rather than touching a half-initialized CUBIC struct). After
    /// the CC swap, ngtcp2 only calls the new CUBIC callbacks, so the
    /// Brutal trampolines become unreachable.
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

        // Bracket the read_pkt window: a callback that requests close() must not
        // free `conn` while ngtcp2 is still on the stack below this call.
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
            // Every non-zero return from `read_pkt` is terminal. ngtcp2
            // either entered DRAINING/CLOSING explicitly, or one of its
            // callbacks (recv_crypto_data, recv_stream_data, …) bubbled up
            // a fatal code — PROTO, TRANSPORT_PARAM, NOMEM, VERSION_NEGO,
            // CALLBACK_FAILURE, CRYPTO, etc. None of these are recoverable
            // from the application's side; the previous behavior of falling
            // through to writeToUDP() worked only because a follow-up read
            // eventually surfaced CLOSING — but a UDP-only workload has no
            // organic read pressure and can sit on a torn-down connection
            // for the full keep-alive window (~10 s) before noticing.
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
        writeToUDP()
        // Incoming packets may contain MAX_STREAM_DATA, extending the send
        // window.  Retry any writes that were blocked by flow control.
        flushPendingWrites()
    }

    fileprivate func writeToUDP() {
        guard let conn else { return }
        // Hold off a reentrant teardown: the per-datagram completions fired at
        // the tail of this function, and any caller that keeps using `conn`
        // after we return (e.g. `flushPendingWrites`' loop), need `conn` to stay
        // valid. `close()` defers while this is set; restored on the way out.
        let prevBusy = ngtcp2Busy
        ngtcp2Busy = true
        defer { ngtcp2Busy = prevBusy }
        let ts = currentTimestamp()
        var pi = ngtcp2_pkt_info()

        // Per-datagram completions are collected and fired after all ngtcp2
        // work is done: ngtcp2.h forbids calling other ngtcp2 API functions
        // between a WRITE_MORE return and the next write_datagram, and a
        // synchronous completion could re-enter ngtcp2 (e.g. via a caller
        // that opens a stream from its send completion).
        var pendingCompletions: [(((Error?) -> Void)?, Error?)] = []

        // Drain pending datagrams first for fair CW access. WRITE_MORE packs
        // multiple datagrams into one UDP packet.
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

            // WRITE_MORE: ngtcp2 committed this datagram to an in-progress
            // packet (paccepted is always nonzero on WRITE_MORE per ngtcp2.h).
            if nwrite == ngtcp2_ssize(NGTCP2_ERR_WRITE_MORE) {
                let popped = pendingDatagrams.removeFirst()
                pendingCompletions.append((popped.completion, nil))
                continue
            }
            if nwrite < 0 {
                // Fatal (exceeds remote's max_datagram_frame_size,
                // datagrams unsupported, …) — drop this datagram.
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
                // Packet emitted (with prior WRITE_MORE'd content) but the
                // current head didn't fit. Retry on the next iteration with
                // a fresh packet.
                continue
            }
            // nwrite == 0 && accepted == 0: CW full, doesn't fit, or
            // amplification limit. Distinguish via path-MTU bound — when
            // bound is 0 (MTU collapsed or peer doesn't support datagrams)
            // nothing further can be sent, so we drop rather than wedge.
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

        // Drain remaining control/stream packets.
        while true {
            let nwrite = txBuf.withUnsafeMutableBufferPointer { dest -> ngtcp2_ssize in
                ngtcp2_swift_conn_write_pkt(conn, nil, &pi, dest.baseAddress, dest.count, ts)
            }
            if nwrite <= 0 { break }
            sendTxBuf(length: Int(nwrite))
        }

        // Must be called after writev_stream / write_datagram / write_pkt
        // cycles to update conn->tx.pacing.next_ts; without it the pacer
        // stays disabled and transmits become cwnd-only bursts.
        ngtcp2_conn_update_pkt_tx_time(conn, ts)

        // Any ngtcp2 op may shift the next deadline.
        rescheduleTimer()

        // Fire per-datagram completions now that no ngtcp2 sequence is
        // in flight; safe for a completion to re-enter ngtcp2.
        for (cb, err) in pendingCompletions { cb?(err) }
    }

    // MARK: Timer

    /// Schedules a one-shot timer at the exact deadline ngtcp2 needs
    /// (retransmission, loss detection, etc.) — an event-driven alarm
    /// rather than a periodic tick.
    private var lastScheduledExpiry: UInt64 = 0

    private func rescheduleTimer() {
        guard let conn else { return }
        let expiry = ngtcp2_conn_get_expiry(conn)

        // Short-circuit when the deadline hasn't moved.  Under bulk transfer
        // ngtcp2's expiry shifts on nearly every ACK — creating a fresh
        // DispatchSourceTimer each time was a measurable CPU sink.
        if expiry == lastScheduledExpiry && retransmitTimer != nil { return }
        lastScheduledExpiry = expiry

        if retransmitTimer == nil {
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.setEventHandler { [weak self] in
                guard let self, let conn = self.conn else { return }
                self.lastScheduledExpiry = 0
                let ts = self.currentTimestamp()
                // Loss detection inside handle_expiry can fire CC callbacks;
                // bracket it so a close requested under it is deferred, not run
                // on top of the live `conn`.
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
                // writeToUDP() calls rescheduleTimer() at the end
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
        // BBR relies on sub-millisecond inter-packet pacing accuracy; a loose
        // leeway lets the dispatch scheduler coalesce wakeups, converting
        // smooth pacing into bursts that trip loss detection. Use zero
        // leeway so the alarm fires at the exact deadline.
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
        // Wrap ngtcp2's buffer without copying. streamDataHandler runs
        // synchronously on this thread and appends into its own storage
        // before returning, so the pointer stays valid. Saves one
        // full memcpy (≈ datalen bytes) per received packet — meaningful
        // under bulk transfer where this fires thousands of times/s.
        let view = Data(
            bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
            count: datalen,
            deallocator: .none
        )
        qc.streamDataHandler?(sid, view, fin)
    } else if fin {
        qc.streamDataHandler?(sid, Data(), true)
    }
    // Flow control window is NOT extended here.  It is extended later by
    // extendStreamOffset() when the application actually consumes the data.
    // This provides backpressure to the server so it doesn't outrun lwIP's
    // pbuf pool.
    return 0
}

/// Fires when a contiguous prefix of a stream's sent data is acknowledged.
/// ngtcp2's `writev_stream` is zero-copy and keeps our buffer pointers until
/// this confirms the bytes are acked, so this is where the retained heap copies
/// are released (without it, the data loop's buffers leak — and before they
/// were retained at all, ngtcp2 retransmitted from freed memory). `offset` is
/// the previous acked offset and `datalen` the newly-acked length, so
/// `offset + datalen` is the new contiguous acked end. Runs on `queue`.
private let quicAckedCB: @convention(c) (
    OpaquePointer?, Int64, UInt64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, streamId, offset, datalen, ud, _ in
    guard let qc = qcFromUserData(ud) else { return 0 }
    qc.releaseAckedStreamData(streamId: streamId, ackedOffset: offset + datalen)
    return 0
}

/// Bit in `flags` that indicates `appErrorCode` was exchanged (RESET_STREAM
/// or STOP_SENDING). Mirrors `NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET`
/// from ngtcp2.h — redeclared here because the bare `#define` isn't imported
/// into Swift.
private let ngtcp2StreamCloseFlagAppErrorCodeSet: UInt32 = 0x01

/// Fires after BOTH directions of a bidirectional stream are terminated
/// (peer FIN + our FIN, or any reset/shutdown path). Without this the
/// application layer would never learn that the stream is gone —
/// `recv_stream_data` doesn't fire for RESET_STREAM, so pending receives
/// would hang forever and orphan entries would accumulate in per-stream
/// maps until the QUIC connection itself closed.
private let quicStreamCloseCB: @convention(c) (
    OpaquePointer?, UInt32, Int64, UInt64,
    UnsafeMutableRawPointer?, UnsafeMutableRawPointer?
) -> Int32 = { _, flags, sid, appErrorCode, ud, _ in
    guard let qc = qcFromUserData(ud) else { return 0 }
    let hasError = (flags & ngtcp2StreamCloseFlagAppErrorCodeSet) != 0
    let error: Error? = hasError
        ? QUICConnection.QUICError.streamClosedWithError(appErrorCode: appErrorCode)
        : nil
    // Drain any queued writes for this stream — their completions would
    // otherwise leak once ngtcp2 frees the per-stream state.
    qc.failPendingWrites(
        streamId: sid,
        error: error ?? QUICConnection.QUICError.closed
    )
    // ngtcp2 has freed the stream and no longer references our retained send
    // buffers, so release them now rather than waiting for connection close.
    qc.releaseStreamSendState(streamId: sid)
    qc.streamTerminationHandler?(sid, error)
    return 0
}

/// Fires when the peer sends RESET_STREAM, signalling that the peer will
/// not send any more data on this stream and discarded anything past
/// `finalSize`. Our read side is effectively aborted. `stream_close` will
/// still fire later once the write direction closes too, but surfacing the
/// reset immediately lets pending receives fail fast instead of hanging
/// until the write side is torn down.
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
    // Wrap ngtcp2's receive buffer without copying — mirrors the stream-data
    // path. `datagramHandler` (HysteriaSession.handleDatagram →
    // HysteriaProtocol.decodeUDPMessage) detaches the bytes it actually keeps
    // via `subdata(in:)` before returning, so the no-copy view only needs to
    // be valid for this synchronous call. Saves ~1.2 KB allocation per
    // datagram — meaningful under bulk UDP through Hysteria where this
    // fires thousands of times/s.
    let view = Data(
        bytesNoCopy: UnsafeMutableRawPointer(mutating: data),
        count: datalen,
        deallocator: .none
    )
    qc.datagramHandler?(view)
    return 0
}
