//
//  MITMBodyReplace.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMBodyReplace")

/// A body decodable as neither UTF-8 nor latin-1 is returned unchanged.
enum MITMBodyReplace {

    /// Pre-compiled so the per-message hot path skips pattern + template parsing.
    struct CompiledOp {
        let search: Regex<AnyRegexOutput>
        let template: MITMCaptureTemplate
        /// Non-nil when the replacement references no captures — lets the hot path use the
        /// verbatim `String.replacing(_:with:)` overload.
        let staticReplacement: String?
    }

    /// Returns nil on an uncompilable pattern; the replacement template never fails to parse.
    static func compile(search: String, replacement: String) -> CompiledOp? {
        guard let regex = try? Regex(search) else { return nil }
        let template = MITMCaptureTemplate(replacement)
        return CompiledOp(search: regex, template: template, staticReplacement: template.staticReplacement)
    }

    /// Applies every compiled edit in order; fail-closed on an undecodable body or blown budget.
    /// Decodes UTF-8, else latin-1 (round-trips any bytes losslessly, so single-byte charsets are
    /// edited in place) and re-encodes in that charset — an unrepresentable edit is abandoned.
    /// Multi-byte charsets (UTF-16, GBK, …) pass through unedited.
    static func applyAll(_ ops: [CompiledOp], to body: Data) async -> Data {
        guard !ops.isEmpty else { return body }
        let encoding: String.Encoding
        let text: String
        if let utf8 = String(data: body, encoding: .utf8) {
            encoding = .utf8
            text = utf8
        } else if let latin1 = String(data: body, encoding: .isoLatin1) {
            encoding = .isoLatin1
            text = latin1
        } else {
            return body
        }
        var current = text
        for op in ops {
            guard let replaced = await boundedReplace(current, op: op) else {
                // Fail closed rather than emit a half-applied chain.
                return body
            }
            current = replaced
        }
        guard let out = current.data(using: encoding) else { return body }
        return out
    }

    /// Soft budget per substitution (seconds); Swift Regex has no execution limit, so a runaway
    /// pattern is abandoned to avoid head-of-line blocking. Generous for the 4 MiB body cap.
    private static let substitutionTimeLimitSeconds = 1

    /// Hard crash deadline after the soft budget: a Regex match is uninterruptible and the
    /// stuck in-flight flag leaves bodyReplace disabled process-wide, so crash for a clean relaunch.
    static let hardCapSeconds = 30

    private static let substitutionInFlight = Atomic<Bool>(false)

    /// Runs one substitution under the soft budget; nil on timeout or while a prior runaway is still burning.
    private static func boundedReplace(_ text: String, op: CompiledOp) async -> String? {
        guard substitutionInFlight.compareExchange(
            expected: false, desired: true, ordering: .sequentiallyConsistent
        ).exchanged else { return nil }

        let box = SubstitutionBox()
        // The uninterruptible regex runs fully detached — a Regex match ignores task cancellation — so
        // the soft-deadline race below can abandon it without the structured group blocking on it.
        // `substitutionInFlight` bounds a runaway to one busy core with no backlog.
        Task.detached(priority: .userInitiated) {
            let out: String
            if let literal = op.staticReplacement {
                out = text.replacing(op.search, with: literal)
            } else {
                out = text.replacing(op.search) { match in
                    op.template.expand(output: match.output)
                }
            }
            box.finish(out)
            substitutionInFlight.store(false, ordering: .sequentiallyConsistent)
        }

        // Race the worker's completion against the soft deadline. The worker branch is
        // cancellation-aware (see `SubstitutionBox.waitDone`), so losing the race doesn't block here.
        let finishedInTime = await withTaskGroup(of: Bool.self) { group in
            group.addTask { await box.waitDone(); return true }
            group.addTask {
                try? await Task.sleep(for: .seconds(substitutionTimeLimitSeconds))
                return false
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }

        if finishedInTime {
            return box.value
        }
        logger.warning("bodyReplace: regex substitution exceeded its time budget over a \(text.utf8.count) B body; leaving the body unchanged (possible catastrophic backtracking in the pattern)")
        // The worker is still spinning with the in-flight flag stuck; arm the hard-cap crash.
        Self.scheduleHardCapCheck(box, byteCount: text.utf8.count)
        return nil
    }

    /// One-shot crash check after the hard cap: a finished substitution flips the box's done flag and
    /// makes this a no-op; one still running is crashed to recover.
    private static func scheduleHardCapCheck(_ box: SubstitutionBox, byteCount: Int) {
        Task.detached(priority: .utility) {
            try? await Task.sleep(for: .seconds(hardCapSeconds))
            guard !box.isDone else { return }
            fatalError("bodyReplace regex substitution did not return \(hardCapSeconds)s after blowing its soft budget over a \(byteCount) B body — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed, leaving bodyReplace disabled process-wide. Crashing the Network Extension so the system relaunches it clean.")
        }
    }

    /// Carries the (possibly runaway) substitution's result and a cancellation-aware completion gate.
    /// State is guarded by a `Mutex`, so `@unchecked Sendable` is safe.
    private final class SubstitutionBox: @unchecked Sendable {
        private struct State {
            var value: String?
            var done = false
            var waiter: CheckedContinuation<Void, Never>?
        }
        private let state = Mutex(State())

        var value: String? { state.withLock { $0.value } }
        var isDone: Bool { state.withLock { $0.done } }

        /// Called by the worker on completion; records the result and wakes any pending `waitDone`.
        func finish(_ value: String) {
            let waiter: CheckedContinuation<Void, Never>? = state.withLock { state in
                state.value = value
                state.done = true
                let waiter = state.waiter
                state.waiter = nil
                return waiter
            }
            waiter?.resume()
        }

        /// Suspends until the worker finishes, or until the task is cancelled (the soft-deadline race
        /// cancels it). Cancellation resumes the continuation so the structured group never blocks on
        /// the uninterruptible worker.
        func waitDone() async {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                    let alreadyDone: Bool = state.withLock { state in
                        if state.done { return true }
                        state.waiter = continuation
                        return false
                    }
                    if alreadyDone { continuation.resume() }
                }
            } onCancel: {
                let waiter: CheckedContinuation<Void, Never>? = state.withLock { state in
                    let waiter = state.waiter
                    state.waiter = nil
                    return waiter
                }
                waiter?.resume()
            }
        }
    }
}
