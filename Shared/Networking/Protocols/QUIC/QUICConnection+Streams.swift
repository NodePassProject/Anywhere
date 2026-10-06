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

extension QUICConnectionCore {

    func openStream(bidirectional: Bool) -> Int64? {
        guard phase == .connected, let engine else { return nil }
        return try? Int64(engine.openStream(bidirectional: bidirectional).rawValue)
    }

    func extendStreamOffset(_ streamId: Int64, count: Int) {
        guard let engine, streamId >= 0 else { return }
        engine.extendReceiveWindow(for: QUICStreamID(rawValue: UInt64(streamId)), by: count)
        scheduleFlush()
    }

    func scheduleFlush() {
        guard !flushScheduled, phase != .closed else { return }
        flushScheduled = true
        publish { [weak owner] in
            owner?.update { core in
                core.flushScheduled = false
                core.writeToUDP()
            }
        }
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
        scheduleFlush()
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
