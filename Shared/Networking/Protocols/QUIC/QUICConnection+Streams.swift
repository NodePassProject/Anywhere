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
    
    nonisolated func shutdownStream(_ streamId: Int64, appErrorCode: UInt64) {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { me in
                guard let conn = me.connectionOpaquePointer else { return }
                me.bridge.shutdownStream(conn, stream: streamId, appErrorCode: appErrorCode)
                me.writeToUDP()
            }
        }
    }
    
    nonisolated func writeStream(_ streamId: Int64, data: Data, fin: Bool = false) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard let conn = me.connectionOpaquePointer, me.state == .connected else {
                continuation.resume(throwing: QUICError.closed)
                return
            }
            me.writeStreamImpl(conn: conn, streamId: streamId,
                               data: data, fin: fin, continuation: continuation)
        }
    }
    
    nonisolated func writeStreamOnQueue(_ streamId: Int64, data: Data, fin: Bool = false) {
        assumeIsolated { me in
            guard let conn = me.connectionOpaquePointer, me.state == .connected else { return }
            me.writeStreamImpl(conn: conn, streamId: streamId, data: data, fin: fin, continuation: nil)
        }
    }

    // MARK: Datagrams
    
    nonisolated func writeDatagrams(_ datagrams: [Data]) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.connectionOpaquePointer != nil, me.state == .connected else {
                continuation.resume(throwing: QUICError.closed)
                return
            }
            if datagrams.isEmpty { continuation.resume(); return }
            let latch = DatagramBatchLatch(count: datagrams.count, continuation: continuation)
            me.enqueueDatagrams(datagrams.map { PendingDatagram(data: $0, latch: latch) })
            me.writeToUDP()
        }
    }
    
    nonisolated func writeDatagramsAtomically(_ datagrams: [Data]) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.connectionOpaquePointer != nil, me.state == .connected else {
                continuation.resume(throwing: QUICError.closed)
                return
            }
            if datagrams.isEmpty { continuation.resume(); return }
            guard Self.canEnqueueDatagramBatch(
                pendingCount: me.pendingDatagrams.count,
                batchCount: datagrams.count
            ) else {
                continuation.resume(throwing: QUICError.datagramQueueFull)
                return
            }
            let latch = DatagramBatchLatch(count: datagrams.count, continuation: continuation)
            me.pendingDatagrams.append(contentsOf: datagrams.map { PendingDatagram(data: $0, latch: latch) })
            me.writeToUDP()
        }
    }

    static func canEnqueueDatagramBatch(pendingCount: Int, batchCount: Int) -> Bool {
        guard pendingCount >= 0, batchCount >= 0,
              pendingCount <= maxPendingDatagrams else { return false }
        return batchCount <= maxPendingDatagrams - pendingCount
    }
    
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
        for d in dropped { d.latch?.settle(overflowError) }
    }
    
    nonisolated func currentMaxDatagramPayloadSize() async -> Int {
        await bridge.run { [weak self] in self?.maxDatagramPayloadSize ?? 0 }
    }
    
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
    
    func writeStreamImpl(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool,
                                  continuation: CheckedContinuation<Void, Error>?) {
        let sent = writeStreamSync(conn: conn, streamId: streamId,
                                    data: data, fin: fin)

        if sent >= data.count {
            continuation?.resume()
        } else {
            let remaining = Data(data[sent...])
            pendingWrites.append(PendingWrite(
                streamId: streamId, data: remaining,
                fin: fin, continuation: continuation
            ))
        }
    }
    
    func writeStreamSync(conn: OpaquePointer, streamId: Int64,
                                  data: Data, fin: Bool) -> Int {
        let ts = currentTimestamp()
        var offset = 0

        guard !data.isEmpty else {
            writeToUDP()
            return 0
        }
        
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
        
        if offset > 0 {
            inflight.endOffset = baseOffset + UInt64(offset)
            inflightStreamBuffers[streamId, default: []].append(inflight)
            streamTxOffset[streamId] = inflight.endOffset
        }

        writeToUDP()
        return offset
    }
    
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
    
    func releaseStreamSendState(streamId: Int64) {
        inflightStreamBuffers[streamId] = nil
        streamTxOffset[streamId] = nil
    }
    
    func failPendingWrites(streamId: Int64, error: Error) {
        guard !pendingWrites.isEmpty else { return }
        var remaining: [PendingWrite] = []
        remaining.reserveCapacity(pendingWrites.count)
        var failed: [CheckedContinuation<Void, Error>?] = []
        for pendingWrite in pendingWrites {
            if pendingWrite.streamId == streamId {
                failed.append(pendingWrite.continuation)
            } else {
                remaining.append(pendingWrite)
            }
        }
        pendingWrites = remaining
        for continuation in failed { continuation?.resume(throwing: error) }
    }
    
    func flushPendingWrites() {
        guard !pendingWrites.isEmpty, let connectionOpaquePointer else { return }
        
        let prevBusy = bridge.enterConnHeld()
        defer { bridge.exitConnHeld(prevBusy) }
        guard state == .connected else {
            let writes = pendingWrites
            pendingWrites.removeAll()
            for pendingWrite in writes { pendingWrite.continuation?.resume(throwing: QUICError.closed) }
            return
        }

        var remaining: [PendingWrite] = []
        for pendingWrite in pendingWrites {
            let sent = writeStreamSync(conn: connectionOpaquePointer, streamId: pendingWrite.streamId,
                                        data: pendingWrite.data, fin: pendingWrite.fin)
            if sent >= pendingWrite.data.count {
                pendingWrite.continuation?.resume()
            } else {
                remaining.append(PendingWrite(
                    streamId: pendingWrite.streamId,
                    data: Data(pendingWrite.data[sent...]),
                    fin: pendingWrite.fin,
                    continuation: pendingWrite.continuation
                ))
            }
        }
        pendingWrites = remaining
    }
}
