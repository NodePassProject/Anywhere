//
//  MITMRegexConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

nonisolated final class MITMRegexConcurrencyBridge: Sendable {
    static let shared = MITMRegexConcurrencyBridge()

    private let queue = DispatchQueue(
        label: "com.argsment.Anywhere.MITMRegexConcurrencyBridge",
        qos: .userInitiated,
        attributes: .concurrent
    )

    private let deadlineQueue = DispatchQueue(
        label: "com.argsment.Anywhere.MITMRegexConcurrencyBridge.Deadline",
        qos: .userInitiated
    )

    enum Outcome<T: Sendable>: Sendable {
        case completed(T)
        case timedOut
    }

    enum GateMatch: Sendable {
        case noMatch
        case match([String?]?)
    }

    struct GateRequest: Sendable {
        let regex: NSRegularExpression
        let wantsCaptures: Bool
        let onResolved: @Sendable (GateMatch) -> Void
        let hardCapMessage: @Sendable () -> String
    }

    // MARK: - Regex operations

    func firstMatches(
        _ requests: [GateRequest],
        in string: String,
        deadlineMillis: Int,
        hardCapSeconds: Int
    ) async -> [Outcome<GateMatch>] {
        let abortAfterSeconds = Self.abortAfterSeconds(hardCapSeconds: hardCapSeconds)
        var outcomes: [Outcome<GateMatch>] = []
        outcomes.reserveCapacity(requests.count)
        while outcomes.count < requests.count {
            let remaining = Array(requests[outcomes.count...])
            let run = await runSteps(
                remaining.count,
                deadlineMillis: deadlineMillis,
                hardCapSeconds: hardCapSeconds,
                hardCapMessage: { remaining[$0].hardCapMessage() }
            ) { index -> GateMatch in
                let request = remaining[index]
                guard let match = Self.match(request, in: string, abortAfterSeconds: abortAfterSeconds) else {
                    return .noMatch
                }
                request.onResolved(match)
                return match
            }
            outcomes.append(contentsOf: run.completed.map { .completed($0) })
            guard run.timedOut else { break }
            outcomes.append(.timedOut)
        }
        return outcomes
    }

    func applyingSubstitution(
        _ regex: NSRegularExpression,
        to text: String,
        template: String,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        onResolved: (@Sendable () -> Void)? = nil
    ) async -> Outcome<String?> {
        let run = await runSteps(
            1,
            deadlineMillis: deadlineMillis,
            hardCapSeconds: hardCapSeconds,
            hardCapMessage: { _ in hardCapMessage() }
        ) { _ -> String? in
            let range = NSRange(text.startIndex..., in: text)
            let out = regex.firstMatch(in: text, options: [], range: range) == nil
                ? nil
                : regex.stringByReplacingMatches(in: text, options: [], range: range, withTemplate: template)
            onResolved?()
            return out
        }
        guard let out = run.completed.first else { return .timedOut }
        return .completed(out)
    }

    private enum ScanResult {
        case match(NSTextCheckingResult)
        case noMatch
        case aborted
    }

    private static func abortAfterSeconds(hardCapSeconds: Int) -> Int {
        max(1, hardCapSeconds / 2)
    }

    private static func match(_ request: GateRequest, in string: String, abortAfterSeconds: Int) -> GateMatch? {
        switch scanFirstMatch(request.regex, in: string, abortAfterSeconds: abortAfterSeconds) {
        case .aborted:
            return nil
        case .noMatch:
            return .noMatch
        case .match(let result):
            return .match(request.wantsCaptures ? captureGroups(of: result, in: string) : nil)
        }
    }

    private static func scanFirstMatch(_ regex: NSRegularExpression, in string: String, abortAfterSeconds: Int) -> ScanResult {
        let range = NSRange(string.startIndex..., in: string)
        let abortAt = MonotonicClock.nanoseconds + UInt64(abortAfterSeconds) * 1_000_000_000
        var outcome = ScanResult.noMatch
        regex.enumerateMatches(in: string, options: [.reportProgress], range: range) { result, _, stop in
            if let result {
                outcome = .match(result)
                stop.pointee = true
            } else if MonotonicClock.nanoseconds >= abortAt {
                outcome = .aborted
                stop.pointee = true
            }
        }
        return outcome
    }

    private static func captureGroups(of match: NSTextCheckingResult, in string: String) -> [String?] {
        var groups: [String?] = []
        groups.reserveCapacity(match.numberOfRanges)
        for index in 0..<match.numberOfRanges {
            let nsRange = match.range(at: index)
            if nsRange.location == NSNotFound {
                groups.append(nil)
            } else if let range = Range(nsRange, in: string) {
                groups.append(String(string[range]))
            } else {
                groups.append(nil)
            }
        }
        return groups
    }

    // MARK: - Bounded worker

    private struct StepRun<T: Sendable> {
        let completed: [T]
        let timedOut: Bool
    }

    private final class Steps<T: Sendable>: Sendable {
        struct State {
            var completed: [T] = []
            var stepStartedAt: UInt64
            var isAbandoned = false
            var isFinished = false
            var waiter: CheckedContinuation<Void, Never>?
        }

        let state: Mutex<State>
        let returnedCount = Atomic<Int>(0)

        init(startedAt: UInt64) {
            state = Mutex(State(stepStartedAt: startedAt))
        }
    }

    private func runSteps<T: Sendable>(
        _ count: Int,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable (Int) -> String,
        step: @escaping @Sendable (Int) -> T
    ) async -> StepRun<T> {
        guard count > 0 else { return StepRun(completed: [], timedOut: false) }
        let steps = Steps<T>(startedAt: MonotonicClock.nanoseconds)
        queue.async {
            for index in 0..<count {
                let value = step(index)
                steps.returnedCount.store(index + 1, ordering: .releasing)
                let (waiter, proceed): (CheckedContinuation<Void, Never>?, Bool) = steps.state.withLock { state in
                    guard !state.isAbandoned else { return (nil, false) }
                    state.completed.append(value)
                    state.stepStartedAt = MonotonicClock.nanoseconds
                    guard state.completed.count == count else { return (nil, true) }
                    state.isFinished = true
                    defer { state.waiter = nil }
                    return (state.waiter, false)
                }
                waiter?.resume()
                guard proceed else { return }
            }
        }

        let budget = UInt64(max(deadlineMillis, 1)) * 1_000_000
        let checkInterval = DispatchTimeInterval.nanoseconds(Int(max(budget / 4, 1_000_000)))
        let timer = DispatchSource.makeTimerSource(queue: deadlineQueue)
        timer.setEventHandler {
            let waiter: CheckedContinuation<Void, Never>? = steps.state.withLock { state in
                guard !state.isFinished, !state.isAbandoned,
                      MonotonicClock.nanoseconds &- state.stepStartedAt >= budget else { return nil }
                state.isAbandoned = true
                defer { state.waiter = nil }
                return state.waiter
            }
            waiter?.resume()
        }
        timer.schedule(deadline: .now() + .nanoseconds(Int(budget)), repeating: checkInterval, leeway: checkInterval)
        timer.resume()

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let ready = steps.state.withLock { state -> Bool in
                guard !state.isFinished, !state.isAbandoned else { return true }
                state.waiter = continuation
                return false
            }
            if ready { continuation.resume() }
        }
        timer.cancel()

        let (completed, isAbandoned) = steps.state.withLock { ($0.completed, $0.isAbandoned) }
        if isAbandoned {
            let stuck = completed.count
            deadlineQueue.asyncAfter(deadline: .now() + .seconds(hardCapSeconds)) {
                guard steps.returnedCount.load(ordering: .acquiring) <= stuck else { return }
                MITMScriptDiskStore.shared.flush()
                fatalError(hardCapMessage(stuck))
            }
        }
        return StepRun(completed: completed, timedOut: isAbandoned)
    }
}
