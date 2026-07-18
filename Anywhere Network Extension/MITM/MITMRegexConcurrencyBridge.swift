//
//  MITMRegexConcurrencyBridge.swift
//  Anywhere
//
//  Created by NodePassProject on 7/17/26.
//

import Foundation
import Synchronization

extension Regex: @unchecked @retroactive Sendable { }

nonisolated final class MITMRegexConcurrencyBridge: Sendable {

    static let shared = MITMRegexConcurrencyBridge()

    /// Worker pool for uninterruptible evaluations. Concurrent, so independent evaluations
    /// parallelize and an abandoned (pinned) worker can't head-of-line-block later ones.
    /// Dispatch is the right tool precisely because a pinned worker must burn a queue thread —
    /// not a cooperative-pool lane — while the hard-cap watchdog decides its fate.
    private let queue = DispatchQueue(
        label: "com.argsment.Anywhere.MITMRegexConcurrencyBridge",
        qos: .userInitiated,
        attributes: .concurrent
    )

    enum Outcome<T: Sendable>: Sendable {
        case completed(T)
        case timedOut
    }

    /// Completion flag shared between the worker and the hard-cap watchdog: the worker
    /// publishes `true` before signalling, so a watchdog that still reads `false` at the hard
    /// cap has found a permanently pinned worker.
    private final class DoneFlag: Sendable {
        let finished = Atomic<Bool>(false)
    }

    // MARK: - Regex operations (the uninterruptible ICU work — kept inside this boundary)

    /// Whether `regex` has an (unanchored) first match in `string`. Fail-closed on `.timedOut` is
    /// the caller's decision. `onResolved` runs on the worker with the verdict — even for an
    /// abandoned (timed-out) worker that finishes late — so the caller can memoize the result
    /// without ever re-running the match itself.
    func firstMatch(
        _ regex: NSRegularExpression,
        in string: String,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        onResolved: (@Sendable (Bool) -> Void)? = nil
    ) async -> Outcome<Bool> {
        await run(deadlineMillis: deadlineMillis, hardCapSeconds: hardCapSeconds, hardCapMessage: hardCapMessage) {
            let range = NSRange(string.startIndex..., in: string)
            let matched = regex.firstMatch(in: string, options: [], range: range) != nil
            onResolved?(matched)
            return matched
        }
    }

    /// Capture groups of the first match (index 0 = whole match), or `nil` on no match. The match
    /// and the group-range reads both run on the worker, so only value-typed strings escape.
    func firstMatchCaptureGroups(
        _ regex: NSRegularExpression,
        in string: String,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String
    ) async -> Outcome<[String?]?> {
        await run(deadlineMillis: deadlineMillis, hardCapSeconds: hardCapSeconds, hardCapMessage: hardCapMessage) {
            Self.captureGroups(regex, in: string)
        }
    }

    /// Applies `regex` substitution over `text`, replacing each match with `staticReplacement`
    /// (when non-nil) or with `expand(match output)`. The substitution *traversal* is the
    /// uninterruptible ICU work and stays inside this boundary; `expand` only builds a replacement
    /// string from an already-computed match. `onResolved` runs on the worker after the traversal
    /// (even if abandoned), for the caller's single-flight bookkeeping.
    func applyingSubstitution(
        _ regex: Regex<AnyRegexOutput>,
        to text: String,
        staticReplacement: String?,
        expand: @escaping @Sendable (AnyRegexOutput) -> String,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        onResolved: (@Sendable () -> Void)? = nil
    ) async -> Outcome<String> {
        await run(deadlineMillis: deadlineMillis, hardCapSeconds: hardCapSeconds, hardCapMessage: hardCapMessage) {
            let out: String
            if let staticReplacement {
                out = text.replacing(regex, with: staticReplacement)
            } else {
                out = text.replacing(regex) { match in expand(match.output) }
            }
            onResolved?()
            return out
        }
    }

    /// Extracts the first match's groups (index 0 = whole match); a non-participating group is
    /// `nil`, and `nil` overall means the pattern did not match. Runs on the worker.
    private static func captureGroups(_ regex: NSRegularExpression, in string: String) -> [String?]? {
        let range = NSRange(string.startIndex..., in: string)
        guard let match = regex.firstMatch(in: string, options: [], range: range) else { return nil }
        var groups: [String?] = []
        groups.reserveCapacity(match.numberOfRanges)
        for i in 0..<match.numberOfRanges {
            let nsRange = match.range(at: i)
            if nsRange.location == NSNotFound {
                groups.append(nil)
            } else if let r = Range(nsRange, in: string) {
                groups.append(String(string[r]))
            } else {
                groups.append(nil)
            }
        }
        return groups
    }

    // MARK: - Bounded worker

    /// Runs `body` on the worker pool and suspends the caller until it completes or
    /// `deadlineMillis` elapses. On timeout the worker is abandoned — the evaluation is
    /// uninterruptible, so nothing can stop it — and a watchdog crashes the process
    /// (`hardCapMessage`) if the worker still hasn't returned `hardCapSeconds` later.
    ///
    /// Cancellation of the calling task reads as `.timedOut` (the deadline sleep returns early);
    /// the worker itself is unaffected either way.
    private func run<T: Sendable>(
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        _ body: @escaping @Sendable () -> T
    ) async -> Outcome<T> {
        // One-shot signal: the stream's iterator is cancellation-aware, so losing the race
        // unblocks the caller immediately while the worker keeps spinning toward the hard cap.
        let (done, doneSignal) = AsyncStream.makeStream(of: T.self)
        let flag = DoneFlag()
        queue.async {
            let value = body()
            flag.finished.store(true, ordering: .sequentiallyConsistent)
            doneSignal.yield(value)
            doneSignal.finish()
        }
        let outcome = await withTaskGroup(of: Outcome<T>.self) { group in
            group.addTask {
                var iterator = done.makeAsyncIterator()
                if let value = await iterator.next() { return .completed(value) }
                return .timedOut
            }
            group.addTask {
                try? await Task.sleep(for: .milliseconds(deadlineMillis))
                return .timedOut
            }
            let first = await group.next() ?? .timedOut
            group.cancelAll()
            return first
        }
        if case .timedOut = outcome {
            scheduleHardCapCheck(flag, hardCapSeconds: hardCapSeconds, message: hardCapMessage)
        }
        return outcome
    }

    private func scheduleHardCapCheck(
        _ flag: DoneFlag,
        hardCapSeconds: Int,
        message: @escaping @Sendable () -> String
    ) {
        Task.detached(priority: .utility) {
            try? await Task.sleep(for: .seconds(hardCapSeconds))
            // A worker still pinned by catastrophic backtracking never published `finished`.
            guard !flag.finished.load(ordering: .sequentiallyConsistent) else { return }
            fatalError(message())
        }
    }
}
