//
//  MITMBodyReplace.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMBodyReplace")

enum MITMBodyReplace {
    
    struct CompiledOperation {
        let search: Regex<AnyRegexOutput>
        let template: MITMCaptureTemplate
        let staticReplacement: String?
    }
    
    static func compile(search: String, replacement: String) -> CompiledOperation? {
        guard let regex = try? Regex(search) else { return nil }
        let template = MITMCaptureTemplate(replacement)
        return CompiledOperation(search: regex, template: template, staticReplacement: template.staticReplacement)
    }
    
    static func applyAll(_ operations: [CompiledOperation], to body: Data) async -> Data {
        guard !operations.isEmpty else { return body }
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
        for operation in operations {
            guard let replaced = await boundedReplace(current, operation: operation) else {
                return body
            }
            current = replaced
        }
        guard let out = current.data(using: encoding) else { return body }
        return out
    }
    
    private static let substitutionTimeLimitSeconds = 1
    private static let hardCapSeconds = 30

    private static let substitutionInFlight = Atomic<Bool>(false)
    
    private static func boundedReplace(_ text: String, operation: CompiledOperation) async -> String? {
        guard substitutionInFlight.compareExchange(
            expected: false, desired: true, ordering: .sequentiallyConsistent
        ).exchanged else { return nil }

        let box = SubstitutionBox()
        Task.detached(priority: .userInitiated) {
            let out: String
            if let literal = operation.staticReplacement {
                out = text.replacing(operation.search, with: literal)
            } else {
                out = text.replacing(operation.search) { match in
                    operation.template.expand(output: match.output)
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
    
    private final class SubstitutionBox: Sendable {
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
