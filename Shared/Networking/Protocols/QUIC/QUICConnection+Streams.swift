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
            return me.openBidiStream(conn)
        }
    }
    
    nonisolated var availableBidiStreams: UInt64 {
        assumeIsolated { me in
            guard me.state == .connected, let conn = me.connectionOpaquePointer else { return 0 }
            return me.streamsBidiLeft(conn)
        }
    }

    nonisolated func openUniStream() -> Int64? {
        assumeIsolated { me in
            guard me.state == .connected, let conn = me.connectionOpaquePointer else { return nil }
            return me.openUniStream(conn)
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
        extendOffsets(connectionOpaquePointer, stream: streamId, count: count)
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
            }
        }
    }
    
    nonisolated func shutdownStream(_ streamId: Int64, appErrorCode: UInt64) {
        bridge.enqueue { [weak self] in
            self?.assumeIsolated { me in
                guard let conn = me.connectionOpaquePointer else { return }
                me.shutdownStream(conn, stream: streamId, appErrorCode: appErrorCode)
                me.writeToUDP()
            }
        }
    }
    
    nonisolated func writeStream(_ streamId: Int64, data: Data, fin: Bool = false) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.connectionOpaquePointer != nil, me.state == .connected else {
                continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
                return
            }
            me.appendStreamWrite(streamId, data: data, fin: fin, continuation: continuation)
        }
    }

    nonisolated func writeStreamOnQueue(_ streamId: Int64, data: Data, fin: Bool = false) {
        assumeIsolated { me in
            guard me.connectionOpaquePointer != nil, me.state == .connected else { return }
            me.appendStreamWrite(streamId, data: data, fin: fin, continuation: nil)
        }
    }

    // MARK: Datagrams
    
    nonisolated func writeDatagrams(_ datagrams: [Data]) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.connectionOpaquePointer != nil, me.state == .connected else {
                continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
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
                continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
                return
            }
            if datagrams.isEmpty { continuation.resume(); return }
            guard Self.canEnqueueDatagramBatch(
                pendingCount: me.pendingDatagrams.count,
                batchCount: datagrams.count
            ) else {
                continuation.resume(throwing: AnywhereError.quic(.datagramQueueFull))
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
        let overflowError = AnywhereError.quic(.connectionFailed(detail: "Datagram send queue overflowed"))
        for d in dropped { d.latch?.settle(overflowError) }
    }
    
    nonisolated func currentMaxDatagramPayloadSize() async -> Int {
        await bridge.run { [weak self] in self?.maxDatagramPayloadSize ?? 0 }
    }
    
    nonisolated var maxDatagramPayloadSize: Int {
        assumeIsolated { me in
            guard let conn = me.connectionOpaquePointer else { return 0 }
            guard let parameters = me.remoteTransportParams(conn) else { return 0 }
            let maxFrame = Int(parameters.pointee.max_datagram_frame_size)
            guard maxFrame > 0 else { return 0 }
            let frameLimit = max(0, maxFrame - 3)
            let pathBytes = me.pathMaxTxUDPPayload(conn)
            let pathLimit = max(0, pathBytes - 44)
            return min(frameLimit, pathLimit)
        }
    }
    
    func appendStreamWrite(
        _ streamId: Int64,
        data: Data,
        fin: Bool,
        continuation: CheckedContinuation<Void, Error>?
    ) {
        if data.isEmpty && !fin {
            continuation?.resume()
            return
        }
        let queue: StreamSendQueue
        if let existing = streamSendQueues[streamId] {
            queue = existing
        } else {
            queue = StreamSendQueue()
            streamSendQueues[streamId] = queue
        }
        guard !queue.finQueued else {
            continuation?.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
            return
        }
        queue.append(
            StreamSendChunk(
                copying: data,
                at: queue.endOffset,
                fin: fin,
                continuation: continuation
            )
        )
        writeToUDP()
    }
    
    func pumpStreamQueues(_ conn: OpaquePointer, ts: ngtcp2_tstamp) {
        guard !streamSendQueues.isEmpty else { return }

        var ids = streamSendQueues.filter { $0.value.hasUnsent }.keys.sorted()
        guard !ids.isEmpty else { return }
        if let pivot = ids.firstIndex(where: { $0 > streamPumpCursor }), pivot > 0 {
            ids = Array(ids[pivot...]) + Array(ids[..<pivot])
        }

        outer: for id in ids {
            guard let queue = streamSendQueues[id] else { continue }
            while queue.hasUnsent {
                guard let chunk = queue.currentChunk() else { break }
                let offsetInChunk = Int(queue.sentOffset - chunk.startOffset)
                let regionLength = Int(chunk.endOffset - queue.sentOffset)

                var pi = ngtcp2_pkt_info()
                var pdatalen: ngtcp2_ssize = 0
                var chosenLocal = sockaddr_storage()
                var flags = UInt32(NGTCP2_WRITE_STREAM_FLAG_MORE)
                if chunk.fin { flags |= UInt32(NGTCP2_WRITE_STREAM_FLAG_FIN) }
                
                let nwrite = chunk.withStableBase { base in
                    txBuffer.withUnsafeMutableBufferPointer { destination -> ngtcp2_ssize in
                        writeStream(
                            conn,
                            chosenLocalAddr: &chosenLocal,
                            pktInfo: &pi,
                            dest: destination.baseAddress,
                            destCapacity: destination.count,
                            dataLength: &pdatalen,
                            flags: flags,
                            stream: id,
                            src: base.advanced(by: offsetInChunk),
                            srcLen: regionLength,
                            ts: ts
                        )
                    }
                }
                
                if nwrite == 0 {
                    break outer
                }

                if nwrite < 0, Int32(nwrite) != NGTCP2_ERR_WRITE_MORE {
                    let code = Int32(nwrite)
                    if code == NGTCP2_ERR_STREAM_DATA_BLOCKED {
                        if pdatalen > 0 {
                            for continuation in queue.advance(
                                accepted: Int(pdatalen),
                                regionLength: regionLength,
                                finFlagged: chunk.fin
                            ) {
                                continuation.resume()
                            }
                        }
                        streamPumpCursor = id
                        continue outer
                    }
                    if code == NGTCP2_ERR_STREAM_NOT_FOUND || code == NGTCP2_ERR_STREAM_SHUT_WR {
                        failStreamSendQueue(
                            streamId: id,
                            error: AnywhereError.quic(.closed(graceful: false))
                        )
                        continue outer
                    }
                    streamPumpCursor = id
                    continue outer
                }

                if nwrite > 0 {
                    sendTxBuf(length: Int(nwrite), to: carrierForOutPath(local: chosenLocal))
                }

                let accepted = pdatalen > 0 ? Int(pdatalen) : 0
                if accepted > 0 || regionLength == 0 {
                    for continuation in queue.advance(
                        accepted: accepted,
                        regionLength: regionLength,
                        finFlagged: chunk.fin
                    ) {
                        continuation.resume()
                    }
                    continue
                }

                streamPumpCursor = id
                continue outer
            }
            streamPumpCursor = id
        }
    }

    func releaseAckedStreamData(streamId: Int64, ackedOffset: UInt64) {
        streamSendQueues[streamId]?.trimAcked(upTo: ackedOffset)
    }

    func releaseStreamSendState(streamId: Int64) {
        streamSendQueues[streamId] = nil
    }

    func failStreamSendQueue(streamId: Int64, error: Error) {
        guard let queue = streamSendQueues[streamId] else { return }
        for continuation in queue.fail() {
            continuation.resume(throwing: error)
        }
    }
}
