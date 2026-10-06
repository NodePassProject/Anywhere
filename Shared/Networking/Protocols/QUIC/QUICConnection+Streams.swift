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
        if engine.extendReceiveWindow(for: QUICStreamID(rawValue: UInt64(streamId)), by: count) {
            scheduleFlush()
        }
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
    
    func enqueueDatagramsInEngine(_ datagrams: [Data]) -> Bool {
        guard pendingDatagrams.isEmpty, let engine else { return false }
        do {
            try engine.sendDatagrams(datagrams)
        } catch {
            return false
        }
        return true
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

    func writeStreamImmediately(_ streamId: Int64, data: Data, fin: Bool) -> Result<Void, Error>? {
        guard phase == .connected, let engine else {
            return .failure(AnywhereError.quic(.closed(graceful: false)))
        }
        if data.isEmpty && !fin { return .success(()) }
        let queue = streamSendQueues[streamId]
        guard streamId >= 0, queue?.finQueued != true, queue?.isFailed != true else {
            return .failure(AnywhereError.quic(.closed(graceful: false)))
        }
        let id = QUICStreamID(rawValue: UInt64(streamId))
        guard !data.isEmpty, queue?.chunks.isEmpty ?? true, engine.sendCapacity(on: id) >= data.count else {
            return nil
        }
        do {
            try engine.send(data, on: id, fin: fin)
        } catch {
            return .failure(Self.streamWriteError(error))
        }
        if fin {
            if let queue {
                queue.finQueued = true
            } else {
                let queue = StreamSendQueue()
                queue.finQueued = true
                streamSendQueues[streamId] = queue
            }
        }
        scheduleFlush()
        return .success(())
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
        if queue.chunks.count == 1, let engine {
            pumpStreamQueue(streamId, queue, engine)
        }
        if !queue.chunks.isEmpty { blockedStreams.insert(streamId) }
        scheduleFlush()
    }

    func pumpStreamQueues(_ engine: AnywhereQUIC.QUICConnection) {
        for id in blockedStreams {
            guard let queue = streamSendQueues[id] else {
                blockedStreams.remove(id)
                continue
            }
            pumpStreamQueue(id, queue, engine)
        }
    }

    private func pumpStreamQueue(_ id: Int64, _ queue: StreamSendQueue, _ engine: AnywhereQUIC.QUICConnection) {
        defer { if queue.chunks.isEmpty { blockedStreams.remove(id) } }
        guard !queue.isFailed else { return }
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
                terminateStreamSendQueue(streamId: id, error: Self.streamWriteError(error))
                break
            }
        }
    }

    nonisolated static func streamWriteError(_ error: QUICError) -> Error {
        switch error {
        case .invalidState, .streamNotFound, .streamSendClosed:
            return AnywhereError.quic(.closed(graceful: false))
        default:
            return AnywhereError.quic(.streamFailed(detail: String(describing: error)))
        }
    }

    func terminateStreamSendQueue(streamId: Int64, error: Error) {
        failStreamSendQueue(streamId: streamId, error: error)
        streamSendQueues[streamId] = nil
    }

    func failStreamSendQueue(streamId: Int64, error: Error) {
        blockedStreams.remove(streamId)
        guard let queue = streamSendQueues[streamId] else { return }
        for continuation in queue.fail() {
            continuation.resume(throwing: error)
        }
    }
}
