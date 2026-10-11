//
//  TickScheduler.swift
//  Anywhere
//
//  Created by NodePassProject on 10/11/26.
//

import Foundation
import Synchronization

nonisolated protocol DeadlineSource: AnyObject, Sendable {
    func nextDeadline() -> Deadline?
    func fire(now: MonotonicClock.Instant)
}

nonisolated final class DeadlineToken: Sendable {
    fileprivate let sequence: UInt64
    private let scheduler: TickScheduler
    private let cancelled = OneShotLatch()

    fileprivate init(sequence: UInt64, scheduler: TickScheduler) {
        self.sequence = sequence
        self.scheduler = scheduler
    }

    var isCancelled: Bool { cancelled.isClaimed }

    func cancel() {
        guard cancelled.claim() else { return }
        scheduler.noteCancelled(self)
    }
}

nonisolated final class DeadlineRegistration: Sendable {
    fileprivate let id: UInt64
    private let scheduler: TickScheduler
    private let cancelled = OneShotLatch()

    fileprivate init(id: UInt64, scheduler: TickScheduler) {
        self.id = id
        self.scheduler = scheduler
    }

    func poke() {
        guard !cancelled.isClaimed else { return }
        scheduler.poke(id: id)
    }

    func cancel() {
        guard cancelled.claim() else { return }
        scheduler.unregister(id: id)
    }

    deinit {
        cancel()
    }
}

nonisolated final class TickScheduler: Sendable {
    static let shared: TickScheduler = {
        let scheduler = TickScheduler()
        scheduler.start()
        return scheduler
    }()

    struct Statistics: Sendable {
        var wakeups: UInt64 = 0
        var firedOneShots: UInt64 = 0
        var firedSources: UInt64 = 0
        var queued: Int = 0
    }

    private enum Payload {
        case oneShot(DeadlineToken, @Sendable () -> Void)
        case source(id: UInt64, generation: UInt64)
    }

    private struct Entry {
        let scheduledAt: MonotonicClock.Instant
        let tolerance: Duration
        let sequence: UInt64
        let payload: Payload

        static func precedes(_ lhs: Entry, _ rhs: Entry) -> Bool {
            lhs.scheduledAt != rhs.scheduledAt ? lhs.scheduledAt < rhs.scheduledAt : lhs.sequence < rhs.sequence
        }
    }

    private struct SourceSlot {
        weak var source: (any DeadlineSource)?
        var generation: UInt64 = 0
        var queuedAt: MonotonicClock.Instant?
    }

    private struct State {
        var heap: [Entry] = []
        var sources: [UInt64: SourceSlot] = [:]
        var nextSequence: UInt64 = 1
        var suspended = false
        var statistics = Statistics()

        var head: Entry? { heap.first }

        mutating func push(_ entry: Entry) {
            heap.append(entry)
            var index = heap.count - 1
            while index > 0 {
                let parent = (index - 1) / 2
                guard Entry.precedes(heap[index], heap[parent]) else { break }
                heap.swapAt(index, parent)
                index = parent
            }
        }

        @discardableResult
        mutating func popHead() -> Entry? {
            guard !heap.isEmpty else { return nil }
            let head = heap[0]
            let last = heap.removeLast()
            if !heap.isEmpty {
                heap[0] = last
                var index = 0
                while true {
                    let left = 2 * index + 1
                    let right = left + 1
                    var smallest = index
                    if left < heap.count, Entry.precedes(heap[left], heap[smallest]) { smallest = left }
                    if right < heap.count, Entry.precedes(heap[right], heap[smallest]) { smallest = right }
                    guard smallest != index else { break }
                    heap.swapAt(index, smallest)
                    index = smallest
                }
            }
            return head
        }
    }

    private static let minimumRearm: Duration = .milliseconds(100)

    private let state = Mutex(State())
    private let wakeups = AsyncInbox<Void>(capacity: 1)
    private let driver = Mutex<Task<Void, Never>?>(nil)
    private let nextSourceID = Atomic<UInt64>(1)

    private init() { }

    private func start() {
        let task = Task.detached(priority: .utility) { [self] in await run() }
        driver.withLock { $0 = task }
    }

    var statistics: Statistics {
        state.withLock { state in
            var statistics = state.statistics
            statistics.queued = state.heap.count
            return statistics
        }
    }

    // MARK: - One-shot deadlines

    @discardableResult
    func schedule(_ deadline: Deadline, _ fire: @escaping @Sendable () -> Void) -> DeadlineToken {
        let now = MonotonicClock.instant
        let scheduledAt = max(deadline.scheduledAt, now)
        let tolerance = deadline.precision.tolerance(forRemaining: now.duration(to: scheduledAt))
        let (token, wake): (DeadlineToken, Bool) = state.withLock { state in
            let sequence = state.nextSequence
            state.nextSequence &+= 1
            let token = DeadlineToken(sequence: sequence, scheduler: self)
            let wasHead = state.head?.scheduledAt
            state.push(Entry(scheduledAt: scheduledAt, tolerance: tolerance, sequence: sequence, payload: .oneShot(token, fire)))
            return (token, wasHead.map { scheduledAt < $0 } ?? true)
        }
        if wake { wakeups.yield(()) }
        return token
    }

    @discardableResult
    func schedule(in duration: Duration, precision: TimerPrecision, _ fire: @escaping @Sendable () -> Void) -> DeadlineToken {
        schedule(Deadline(in: duration, precision: precision), fire)
    }

    fileprivate func noteCancelled(_ token: DeadlineToken) {
        let wake: Bool = state.withLock { state in
            guard let head = state.head, case .oneShot(let queued, _) = head.payload, queued === token else { return false }
            state.popHead()
            return true
        }
        if wake { wakeups.yield(()) }
    }

    // MARK: - Pull-model sources

    func register(_ source: any DeadlineSource) -> DeadlineRegistration {
        let id = nextSourceID.wrappingAdd(1, ordering: .relaxed).oldValue
        state.withLock { $0.sources[id] = SourceSlot(source: source) }
        let registration = DeadlineRegistration(id: id, scheduler: self)
        poke(id: id)
        return registration
    }

    fileprivate func unregister(id: UInt64) {
        let wake: Bool = state.withLock { state in
            state.sources[id] = nil
            if let head = state.head, case .source(let headID, _) = head.payload, headID == id {
                state.popHead()
                return true
            }
            return false
        }
        if wake { wakeups.yield(()) }
    }

    fileprivate func poke(id: UInt64) {
        let (source, queuedAt): ((any DeadlineSource)?, MonotonicClock.Instant?) = state.withLock { state in
            guard let slot = state.sources[id] else { return (nil, nil) }
            return (slot.source, slot.queuedAt)
        }
        guard let source else { return }
        guard let deadline = source.nextDeadline() else { return }
        if let queuedAt, queuedAt <= deadline.scheduledAt { return }
        requeue(id: id, deadline, now: MonotonicClock.instant, wake: true)
    }

    private func requeue(id: UInt64, _ deadline: Deadline?, now: MonotonicClock.Instant, wake: Bool) {
        guard let deadline else { return }
        var scheduledAt = deadline.scheduledAt
        if scheduledAt <= now {
            scheduledAt = now.advanced(by: deadline.precision.grid ?? Self.minimumRearm)
        }
        let tolerance = deadline.precision.tolerance(forRemaining: now.duration(to: scheduledAt))
        let becameHead: Bool = state.withLock { state in
            guard var slot = state.sources[id] else { return false }
            slot.generation &+= 1
            slot.queuedAt = scheduledAt
            state.sources[id] = slot
            let sequence = state.nextSequence
            state.nextSequence &+= 1
            let wasHead = state.head?.scheduledAt
            state.push(Entry(
                scheduledAt: scheduledAt,
                tolerance: tolerance,
                sequence: sequence,
                payload: .source(id: id, generation: slot.generation)
            ))
            return wasHead.map { scheduledAt < $0 } ?? true
        }
        if wake, becameHead { wakeups.yield(()) }
    }

    // MARK: - Sleep / wake

    func suspend() {
        state.withLock { $0.suspended = true }
        wakeups.yield(())
    }

    func resume() {
        state.withLock { $0.suspended = false }
        wakeups.yield(())
    }

    // MARK: - Driver

    private func run() async {
        while !Task.isCancelled {
            let next: (at: MonotonicClock.Instant, tolerance: Duration)? = state.withLock { state in
                guard !state.suspended, let head = state.head else { return nil }
                return (head.scheduledAt, head.tolerance)
            }
            if let next {
                let now = MonotonicClock.instant
                if next.at > now {
                    await sleep(until: next.at, tolerance: next.tolerance)
                }
            } else {
                _ = try? await wakeups.next()
            }
            if Task.isCancelled { return }
            fireDue()
        }
    }

    private func sleep(until instant: MonotonicClock.Instant, tolerance: Duration) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                try? await Task.sleep(
                    until: MonotonicClock.continuousInstant(for: instant),
                    tolerance: tolerance,
                    clock: .continuous
                )
            }
            group.addTask { _ = try? await self.wakeups.next() }
            _ = await group.next()
            group.cancelAll()
        }
    }

    private enum Due {
        case oneShot(@Sendable () -> Void)
        case source(id: UInt64, any DeadlineSource)
    }

    private func fireDue() {
        let now = MonotonicClock.instant
        let due: [Due] = state.withLock { state in
            guard !state.suspended else { return [] }
            var due: [Due] = []
            while let head = state.head, head.scheduledAt <= now {
                state.popHead()
                switch head.payload {
                case .oneShot(let token, let fire):
                    guard !token.isCancelled else { continue }
                    due.append(.oneShot(fire))
                case .source(let id, let generation):
                    guard var slot = state.sources[id], slot.generation == generation else { continue }
                    slot.queuedAt = nil
                    guard let source = slot.source else {
                        state.sources[id] = nil
                        continue
                    }
                    state.sources[id] = slot
                    due.append(.source(id: id, source))
                }
            }
            if !due.isEmpty { state.statistics.wakeups &+= 1 }
            return due
        }
        guard !due.isEmpty else { return }
        var firedOneShots: UInt64 = 0
        var firedSources: UInt64 = 0
        for item in due {
            switch item {
            case .oneShot(let fire):
                firedOneShots &+= 1
                fire()
            case .source(let id, let source):
                var deadline = source.nextDeadline()
                if let current = deadline, current.scheduledAt <= now {
                    firedSources &+= 1
                    source.fire(now: now)
                    deadline = source.nextDeadline()
                }
                requeue(id: id, deadline, now: now, wake: false)
            }
        }
        state.withLock { state in
            state.statistics.firedOneShots &+= firedOneShots
            state.statistics.firedSources &+= firedSources
        }
    }
}

extension Task where Success == Never, Failure == Never {
    nonisolated static func suspendUntilCancelled() async {
        let parked = Mutex<CheckedContinuation<Void, Never>?>(nil)
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let resumeNow: Bool = parked.withLock { slot in
                    if Task.isCancelled { return true }
                    slot = continuation
                    return false
                }
                if resumeNow { continuation.resume() }
            }
        } onCancel: {
            parked.withLock { slot -> CheckedContinuation<Void, Never>? in
                defer { slot = nil }
                return slot
            }?.resume()
        }
    }
}
