//
//  MITMLegWriter.swift
//  Anywhere
//
//  Created by NodePassProject on 10/20/26.
//

import Foundation

actor MITMLegWriter {
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        sessionContext.executor.asUnownedSerialExecutor()
    }

    static let maxQueuedReplies = 8192

    private static let maxBatchBytes = 256 * 1024

    private static let maxUnsentBytes: UInt64 = 128 * 1024

    private enum Mark {
        case reply
        case resume(CheckedContinuation<Void, Error>)
        case call(@Sendable (Error?) -> Void)
    }

    private enum Phase {
        case open
        case closing
        case closed
    }

    private let leg: any MITMByteLeg
    private let sessionContext: SessionExecutionContext
    private let onFailure: (@Sendable (Error) -> Void)?

    private var phase: Phase = .open
    private var failure: Error?
    private var queue = MITMByteQueue()
    private var queuedBytes: UInt64 = 0
    private var sentBytes: UInt64 = 0
    private var isSending = false
    private var marks: [(through: UInt64, mark: Mark)] = []
    private var markHead = 0
    private var queuedReplies = 0
    private var wake: CheckedContinuation<Void, Never>?
    private var loop: Task<Void, Never>?
    private var closeDeadline: BridgeDeadlineTimer?
    private var closeCompletion: (@Sendable () -> Void)?

    init(leg: any MITMByteLeg, sessionContext: SessionExecutionContext, onFailure: (@Sendable (Error) -> Void)?) {
        self.leg = leg
        self.sessionContext = sessionContext
        self.onFailure = onFailure
    }

    func write(_ data: Data, isReply: Bool = false) -> Bool {
        guard phase == .open, !data.isEmpty else { return true }
        if isReply {
            guard queuedReplies < Self.maxQueuedReplies else { return false }
            queuedReplies += 1
        }
        enqueue(data, mark: isReply ? .reply : nil)
        return true
    }

    func write(_ data: Data, then completion: @escaping @Sendable (Error?) -> Void) {
        guard phase == .open else {
            completion(AnywhereError.transport(.terminated))
            return
        }
        guard !data.isEmpty else {
            if queuedBytes == sentBytes {
                completion(nil)
            } else {
                marks.append((through: queuedBytes, mark: .call(completion)))
            }
            return
        }
        enqueue(data, mark: .call(completion))
    }

    func writeWithBackpressure(_ data: Data) async throws {
        guard phase == .open else { throw failure ?? AnywhereError.transport(.terminated) }
        guard !data.isEmpty else { return }
        enqueue(data, mark: nil)
        guard queuedBytes - sentBytes > Self.maxUnsentBytes else { return }
        let through = max(queuedBytes - Self.maxUnsentBytes, marks.last?.through ?? 0)
        try await withCheckedThrowingContinuation { marks.append((through: through, mark: .resume($0))) }
    }

    func drain() async throws {
        guard phase == .open else { throw failure ?? AnywhereError.transport(.terminated) }
        guard queuedBytes > sentBytes else { return }
        let through = queuedBytes
        try await withCheckedThrowingContinuation { marks.append((through: through, mark: .resume($0))) }
    }

    func close(gracePeriod: Duration, then completion: @escaping @Sendable () -> Void) {
        guard phase == .open else {
            completion()
            return
        }
        phase = .closing
        closeCompletion = completion
        guard isSending || !queue.isEmpty else {
            finishClose()
            return
        }
        let deadline = BridgeDeadlineTimer(queue: sessionContext.executor.queue) { [weak self] in
            self?.assumeIsolated { $0.abort() }
        }
        deadline.schedule(afterNanoseconds: UInt64(max(gracePeriod.nanosecondsClamped, 0)))
        closeDeadline = deadline
        wakeLoop()
    }

    func abort() {
        guard phase != .closed else { return }
        loop?.cancel()
        loop = nil
        queue = MITMByteQueue()
        settle(through: .max, error: AnywhereError.transport(.terminated))
        finishClose()
    }

    private func enqueue(_ data: Data, mark: Mark?) {
        queue.append(data)
        queuedBytes += UInt64(data.count)
        if let mark { marks.append((through: queuedBytes, mark: mark)) }
        if loop == nil { loop = Task { await self.run() } }
        wakeLoop()
    }

    private func run() async {
        while let batch = await nextBatch() {
            isSending = true
            do {
                try await leg.send(contentsOf: batch)
            } catch {
                isSending = false
                fail(error)
                return
            }
            isSending = false
            sentBytes += UInt64(batch.reduce(0) { $0 + $1.count })
            settle(through: sentBytes, error: nil)
        }
    }

    private func nextBatch() async -> [Data]? {
        while true {
            switch phase {
            case .closed:
                return nil
            case .closing where queue.isEmpty:
                finishClose()
                return nil
            case .open, .closing:
                if !queue.isEmpty { return queue.popChunks(Self.maxBatchBytes) }
                await withCheckedContinuation { wake = $0 }
            }
        }
    }

    private func fail(_ error: Error) {
        guard phase != .closed else { return }
        failure = error
        queue = MITMByteQueue()
        settle(through: .max, error: error)
        finishClose()
        onFailure?(error)
    }

    private func finishClose() {
        phase = .closed
        closeDeadline?.cancel()
        closeDeadline = nil
        wakeLoop()
        let completion = closeCompletion
        closeCompletion = nil
        completion?()
    }

    private func wakeLoop() {
        guard let wake else { return }
        self.wake = nil
        wake.resume()
    }

    private func settle(through offset: UInt64, error: Error?) {
        while markHead < marks.count, marks[markHead].through <= offset {
            let mark = marks[markHead].mark
            markHead += 1
            switch mark {
            case .reply:
                queuedReplies -= 1
            case .resume(let continuation):
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            case .call(let completion):
                completion(error)
            }
        }
        if markHead == marks.count {
            marks.removeAll(keepingCapacity: true)
            markHead = 0
        } else if markHead >= 64, markHead * 2 >= marks.count {
            marks.removeFirst(markHead)
            markHead = 0
        }
    }
}
