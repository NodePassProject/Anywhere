//
//  MITMBodyReplace.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMBodyReplace")

nonisolated enum MITMBodyReplace {
    
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

        // The regex substitution is uninterruptible; run it on its own detached worker and signal the
        // result through a one-shot `AsyncStream`. Racing that stream (its iterator is cancellation-
        // aware) against the soft deadline means losing the race unblocks here without waiting on the
        // worker, which keeps spinning until the regex returns (or the hard cap crashes a stuck one).
        let (doneStream, doneSignal) = AsyncStream.makeStream(of: String.self)
        Task.detached(priority: .userInitiated) {
            let out: String
            if let literal = operation.staticReplacement {
                out = text.replacing(operation.search, with: literal)
            } else {
                out = text.replacing(operation.search) { match in
                    operation.template.expand(output: match.output)
                }
            }
            substitutionInFlight.store(false, ordering: .sequentiallyConsistent)
            doneSignal.yield(out)
            doneSignal.finish()
        }

        enum RaceResult { case done(String); case timedOut }
        let result: RaceResult = await withTaskGroup(of: RaceResult.self) { group in
            group.addTask {
                var iterator = doneStream.makeAsyncIterator()
                if let out = await iterator.next() { return .done(out) }
                return .timedOut
            }
            group.addTask {
                try? await Task.sleep(for: .seconds(substitutionTimeLimitSeconds))
                return .timedOut
            }
            let first = await group.next() ?? .timedOut
            group.cancelAll()
            return first
        }

        switch result {
        case .done(let out):
            return out
        case .timedOut:
            logger.warning("bodyReplace: regex substitution exceeded its time budget over a \(text.utf8.count) B body; leaving the body unchanged (possible catastrophic backtracking in the pattern)")
            // The worker is still spinning with the in-flight flag stuck; arm the hard-cap crash.
            Self.scheduleHardCapCheck(byteCount: text.utf8.count)
            return nil
        }
    }

    /// One-shot crash check after the hard cap: a substitution that finished cleared the in-flight
    /// flag and makes this a no-op; one still running (flag stuck `true`) is crashed to recover.
    private static func scheduleHardCapCheck(byteCount: Int) {
        Task.detached(priority: .utility) {
            try? await Task.sleep(for: .seconds(hardCapSeconds))
            guard substitutionInFlight.load(ordering: .sequentiallyConsistent) else { return }
            fatalError("bodyReplace regex substitution did not return \(hardCapSeconds)s after blowing its soft budget over a \(byteCount) B body — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed, leaving bodyReplace disabled process-wide. Crashing the Network Extension so the system relaunches it clean.")
        }
    }
}
