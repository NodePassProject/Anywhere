//
//  QUICConnection+Streams.swift
//  Anywhere
//
//  Created by NodePassProject on 7/18/26.
//

import Foundation
import Synchronization
import Network
import AnywhereQUIC

nonisolated private let logger = AnywhereLogger(category: "QUICConnection")

extension QUICConnection {

    // MARK: Streams

    nonisolated func openBidiStream() -> Int64? {
        assumeIsolated { me in
            guard me.phase == .connected, let engine = me.engine else { return nil }
            return try? Int64(engine.openStream(bidirectional: true).rawValue)
        }
    }

    nonisolated var availableBidiStreams: UInt64 {
        assumeIsolated { me in
            guard me.phase == .connected, let engine = me.engine else { return 0 }
            return engine.availableBidirectionalStreams
        }
    }

    nonisolated func openUniStream() -> Int64? {
        assumeIsolated { me in
            guard me.phase == .connected, let engine = me.engine else { return nil }
            return try? Int64(engine.openStream(bidirectional: false).rawValue)
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
        guard let engine, streamId >= 0 else { return }
        engine.extendReceiveWindow(for: QUICStreamID(rawValue: UInt64(streamId)), by: count)
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
                guard let engine = me.engine else { return }
                guard streamId >= 0 else { return }
                engine.shutdownStream(QUICStreamID(rawValue: UInt64(streamId)), errorCode: appErrorCode)
                me.failStreamSendQueue(streamId: streamId, error: AnywhereError.quic(.closed(graceful: false)))
                me.writeToUDP()
            }
        }
    }

    nonisolated func writeStream(_ streamId: Int64, data: Data, fin: Bool = false) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.engine != nil, me.phase == .connected else {
                continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
                return
            }
            me.appendStreamWrite(streamId, data: data, fin: fin, continuation: continuation)
        }
    }

    nonisolated func writeStreamOnQueue(_ streamId: Int64, data: Data, fin: Bool = false) {
        assumeIsolated { me in
            guard me.engine != nil, me.phase == .connected else { return }
            me.appendStreamWrite(streamId, data: data, fin: fin, continuation: nil)
        }
    }

    // MARK: Datagrams

    nonisolated func writeDatagrams(_ datagrams: [Data]) async throws {
        try await bridge.runParkedThrowing(host: self) { me, continuation in
            guard me.engine != nil, me.phase == .connected else {
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
            guard me.engine != nil, me.phase == .connected else {
                continuation.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
                return
            }
            if datagrams.isEmpty { continuation.resume(); return }
            guard Self.canEnqueueDatagramBatch(
                pendingCount: me.pendingDatagrams.count + (me.engine?.pendingDatagramCount ?? 0),
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
        let overflow = pendingDatagrams.count + (engine?.pendingDatagramCount ?? 0) - Self.maxPendingDatagrams
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
            me.engine?.maxDatagramPayloadSize ?? 0
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
        guard streamId >= 0, !queue.finQueued, !queue.isFailed else {
            continuation?.resume(throwing: AnywhereError.quic(.closed(graceful: false)))
            return
        }
        queue.append(
            StreamSendChunk(
                data: data,
                fin: fin,
                continuation: continuation
            )
        )
        writeToUDP()
    }

    func pumpStreamQueues(_ engine: AnywhereQUIC.QUICConnection) {
        var ids = streamSendQueues.filter { !$0.value.chunks.isEmpty }.keys.sorted()
        if let pivot = ids.firstIndex(where: { $0 > streamPumpCursor }), pivot > 0 {
            ids = Array(ids[pivot...]) + Array(ids[..<pivot])
        }
        for id in ids {
            guard let queue = streamSendQueues[id], !queue.isFailed else { continue }
            while let chunk = queue.chunks.first {
                do {
                    let remaining = chunk.data.dropFirst(chunk.offset)
                    let accepted = try engine.send(remaining, on: QUICStreamID(rawValue: UInt64(id)), fin: chunk.fin)
                    chunk.offset += accepted
                    guard chunk.offset == chunk.data.count else { break }
                    queue.chunks.removeFirst()
                    let continuation = chunk.continuation
                    chunk.continuation = nil
                    continuation?.resume()
                } catch {
                    let failure: Error
                    switch error {
                    case .invalidState, .streamNotFound, .streamSendClosed:
                        failure = AnywhereError.quic(.closed(graceful: false))
                    default:
                        failure = AnywhereError.quic(.streamFailed(detail: String(describing: error)))
                    }
                    terminateStreamSendQueue(streamId: id, error: failure)
                    break
                }
            }
            streamPumpCursor = id
        }
    }

    func terminateStreamSendQueue(streamId: Int64, error: Error) {
        failStreamSendQueue(streamId: streamId, error: error)
        streamSendQueues[streamId] = nil
    }

    func failStreamSendQueue(streamId: Int64, error: Error) {
        guard let queue = streamSendQueues[streamId] else { return }
        for continuation in queue.fail() {
            continuation.resume(throwing: error)
        }
    }
}
