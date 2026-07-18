//
//  QUICConnection+Streams.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Network
import CryptoKit
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

extension QUICConnection {

    // MARK: Streams

    nonisolated func openBidiStream() -> Int64? {
        assumeIsolated { me in
            guard me.state == .connected, let conn = me.connectionOpaquePointer else { return nil }
            return me.bridge.openBidiStream(conn)
        }
    }

    /// Number of additional bidirectional streams the local endpoint may open.
    /// Access is serialized on ``queue`` (asserted by `assumeIsolated`).
    nonisolated var availableBidiStreams: UInt64 {
        assumeIsolated { me in
            guard me.state == .connected, let conn = me.connectionOpaquePointer else { return 0 }
            return me.bridge.streamsBidiLeft(conn)
        }
    }

    nonisolated func openUniStream() -> Int64? {
        assumeIsolated { me in
            guard me.state == .connected, let conn = me.connectionOpaquePointer else { return nil }
            return me.bridge.openUniStream(conn)
        }
    }

    /// Extends stream- and connection-level flow control after the app consumes `count` bytes.
    nonisolated func extendStreamOffset(_ streamId: Int64, count: Int) {
        guard count > 0 else { return }
        if isOnQueue {
            assumeIsolated { $0.extendStreamOffsetOnQueue(streamId, count: count) }
        } else {
            bridge.enqueue { [weak self] in
                self?.assumeIsolated { $0.extendStreamOffsetOnQueue(streamId, count: count) }
            }
        }
    }

    func extendStreamOffsetOnQueue(_ streamId: Int64, count: Int) {
        guard let connectionOpaquePointer else { return }
        bridge.extendOffsets(connectionOpaquePointer, stream: streamId, count: count)
        // Inside read_pkt the post-read scheduleFlush() covers it.
        if inReadPkt { return }
        scheduleFlush()
    }

    /// Coalesces tx flushes so a burst of received packets produces one drain.
    func scheduleFlush() {
        if flushScheduled { return }
        flushScheduled = true
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { me in
                me.flushScheduled = false
                me.writeToUDP()
                me.flushPendingWrites()
            }
        }
    }

    /// Sends RESET_STREAM + STOP_SENDING, freeing the stream ID slot. The caller supplies the
    /// application error code; each app protocol (HTTP/3, Hysteria, Nowhere) defines its own.
    nonisolated func shutdownStream(_ streamId: Int64, appErrorCode: UInt64) {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { me in
                guard let conn = me.connectionOpaquePointer else { return }
                me.bridge.shutdownStream(conn, stream: streamId, appErrorCode: appErrorCode)
                me.writeToUDP()
            }
        }
    }

    nonisolated func writeStream(_ streamId: Int64, data: Data, fin: Bool = false,
                                         completion: @escaping @Sendable (Error?) -> Void) {
        bridge.enqueue { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            self.assumeIsolated { me in
                guard let conn = me.connectionOpaquePointer, me.state == .connected else {
                    completion(QUICError.closed)
                    return
                }
                me.writeStreamImpl(conn: conn, streamId: streamId,
                                   data: data, fin: fin, completion: completion)
            }
        }
    }

    /// Async stream write — the single-shot ngtcp2 write completion is bridged in
    /// ``NGTCP2ConcurrencyBridge``.
    nonisolated func writeStream(_ streamId: Int64, data: Data, fin: Bool = false) async throws {
        try await bridge.awaitingCompletion { writeStream(streamId, data: data, fin: fin, completion: $0) }
    }

    /// Fire-and-forget stream write for callers already on ``queue`` (asserted by
    /// `assumeIsolated`): enqueues the frame synchronously in the current queue turn and
    /// drops the result. For connection-setup writes (HTTP/3 control/QPACK streams) whose
    /// failure surfaces through `connectionClosedHandler` anyway — no completion, no self-hop.
    nonisolated func writeStreamOnQueue(_ streamId: Int64, data: Data, fin: Bool = false) {
        assumeIsolated { me in
            guard let conn = me.connectionOpaquePointer, me.state == .connected else { return }
            me.writeStreamImpl(conn: conn, streamId: streamId, data: data, fin: fin, completion: { _ in })
        }
    }

    // MARK: Datagrams

    /// Async DATAGRAM batch write — the ngtcp2-boundary completion (fired once after every frame
    /// reaches a terminal state) is bridged in ``NGTCP2ConcurrencyBridge``.
    nonisolated func writeDatagrams(_ datagrams: [Data]) async throws {
        try await bridge.awaitingCompletion { writeDatagrams(datagrams, completion: $0) }
    }

    /// Queues multiple DATAGRAM frames; `completion` fires once all reach a terminal
    /// state, with the first error or `nil`.
    nonisolated func writeDatagrams(_ datagrams: [Data], completion: @escaping @Sendable (Error?) -> Void) {
        bridge.enqueue { [weak self] in
            // Split guards so the completion fires even when `self` is gone.
            guard let self else { completion(QUICError.closed); return }
            self.assumeIsolated { me in
                guard me.connectionOpaquePointer != nil, me.state == .connected else {
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
                me.enqueueDatagrams(pending)
                me.writeToUDP()
            }
        }
    }

    /// Async atomic DATAGRAM batch write — the ngtcp2-boundary completion is bridged in
    /// ``NGTCP2ConcurrencyBridge``.
    nonisolated func writeDatagramsAtomically(_ datagrams: [Data]) async throws {
        try await bridge.awaitingCompletion { writeDatagramsAtomically(datagrams, completion: $0) }
    }

    /// Queues one logical packet's DATAGRAM fragments as an indivisible batch.
    /// Capacity pressure rejects the new batch and never evicts existing frames.
    nonisolated func writeDatagramsAtomically(
        _ datagrams: [Data],
        completion: @escaping @Sendable (Error?) -> Void
    ) {
        bridge.enqueue { [weak self] in
            guard let self else { completion(QUICError.closed); return }
            self.assumeIsolated { me in
                guard me.connectionOpaquePointer != nil, me.state == .connected else {
                    completion(QUICError.closed)
                    return
                }
                if datagrams.isEmpty {
                    completion(nil)
                    return
                }
                guard Self.canEnqueueDatagramBatch(
                    pendingCount: me.pendingDatagrams.count,
                    batchCount: datagrams.count
                ) else {
                    completion(QUICError.datagramQueueFull)
                    return
                }

                var remaining = datagrams.count
                var firstError: Error?
                let onEach: ((Error?) -> Void) = { error in
                    if let error, firstError == nil { firstError = error }
                    remaining -= 1
                    if remaining == 0 { completion(firstError) }
                }
                me.pendingDatagrams.append(contentsOf: datagrams.map {
                    PendingDatagram(data: $0, completion: onEach)
                })
                me.writeToUDP()
            }
        }
    }

    static func canEnqueueDatagramBatch(pendingCount: Int, batchCount: Int) -> Bool {
        guard pendingCount >= 0, batchCount >= 0,
              pendingCount <= maxPendingDatagrams else { return false }
        return batchCount <= maxPendingDatagrams - pendingCount
    }

    /// Appends with drop-oldest at `maxPendingDatagrams`; dropped completions fire so callers observe the overflow.
    func enqueueDatagrams(_ datagrams: [PendingDatagram]) {
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

    /// Async reader for ``maxDatagramPayloadSize`` — the property asserts on-``queue``, so the
    /// async datagram-send path (which runs off-queue) hops on to read it here.
    nonisolated func currentMaxDatagramPayloadSize() async -> Int {
        await bridge.run { [weak self] in self?.maxDatagramPayloadSize ?? 0 }
    }

    /// Max datagram payload per UDP packet (0 if unsupported): min(peer `max_datagram_frame_size` − 3
    /// frame header, path MTU − 44 worst-case QUIC packet overhead). The worst case prevents
    /// `write_datagram` returning `nwrite=0, accepted=0` forever and wedging the queue. On `queue`.
    nonisolated var maxDatagramPayloadSize: Int {
        assumeIsolated { me in
            guard let conn = me.connectionOpaquePointer else { return 0 }
            guard let parameters = me.bridge.remoteTransportParams(conn) else { return 0 }
            let maxFrame = Int(parameters.pointee.max_datagram_frame_size)
            guard maxFrame > 0 else { return 0 }
            let frameLimit = max(0, maxFrame - 3)
            let pathBytes = me.bridge.pathMaxTxUDPPayload(conn)
            let pathLimit = max(0, pathBytes - 44)
            return min(frameLimit, pathLimit)
        }
    }

    /// Sends as much stream data as flow control allows, queuing the remainder.
    func writeStreamImpl(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool,
                                  completion: @escaping @Sendable (Error?) -> Void) {
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
    func writeStreamSync(conn: OpaquePointer, streamId: Int64,
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

            var chosenLocal = sockaddr_storage()
            // The source pointer is taken as a scoped-access closure parameter so it stays
            // region-local (like `destination`) — the stable heap address is unchanged, and the
            // retained `inflight` keeps the bytes valid for ngtcp2's later retransmits.
            let nwrite = inflight.withStableBase { base in
                txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                    bridge.writeStream(
                        conn, chosenLocalAddr: &chosenLocal, pktInfo: &pi,
                        dest: destination.baseAddress, destCapacity: destination.count,
                        dataLength: &pdatalen, flags: flags, stream: streamId,
                        src: base.advanced(by: offset), srcLen: remaining, ts: ts
                    )
                }
            }
            let outCarrier = carrierForOutPath(local: chosenLocal)

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
    func releaseAckedStreamData(streamId: Int64, ackedOffset: UInt64) {
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
    func releaseStreamSendState(streamId: Int64) {
        inflightStreamBuffers[streamId] = nil
        streamTxOffset[streamId] = nil
    }

    /// Fails queued writes for a terminated stream so their completions don't leak. Runs on `queue`.
    func failPendingWrites(streamId: Int64, error: Error) {
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
    func flushPendingWrites() {
        guard !pendingWrites.isEmpty, let connectionOpaquePointer else { return }
        // A completion may call close(); the conn-held guard defers teardown so `conn`
        // isn't freed mid-loop.
        let prevBusy = bridge.enterConnHeld()
        defer { bridge.exitConnHeld(prevBusy) }
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

}
