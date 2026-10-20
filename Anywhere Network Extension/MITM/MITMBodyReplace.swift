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
        ).exchanged else {
            logger.warning("bodyReplace: another substitution is in flight; leaving this \(text.utf8.count) B body unchanged")
            return nil
        }

        let byteCount = text.utf8.count
        let search = operation.search
        let staticReplacement = operation.staticReplacement
        let template = operation.template
        let outcome = await MITMRegexConcurrencyBridge.shared.applyingSubstitution(
            search, to: text,
            staticReplacement: staticReplacement,
            expand: { output in template.expand(output: output) },
            deadlineMillis: substitutionTimeLimitSeconds * 1000,
            hardCapSeconds: hardCapSeconds,
            hardCapMessage: {
                "bodyReplace regex substitution did not return \(hardCapSeconds)s after blowing its soft budget over a \(byteCount) B body — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed, leaving bodyReplace disabled process-wide. Crashing the Network Extension so the system relaunches it clean."
            },
            onResolved: { substitutionInFlight.store(false, ordering: .sequentiallyConsistent) }
        )

        switch outcome {
        case .completed(let out):
            return out
        case .timedOut:
            logger.warning("bodyReplace: regex substitution exceeded its time budget over a \(text.utf8.count) B body; leaving the body unchanged (possible catastrophic backtracking in the pattern)")
            return nil
        }
    }
}
