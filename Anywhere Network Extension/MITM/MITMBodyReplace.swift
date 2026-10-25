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
        let search: NSRegularExpression
        let template: String
    }

    static func compile(search: String, replacement: String) -> CompiledOperation? {
        guard let regex = try? NSRegularExpression(pattern: search, options: []) else { return nil }
        let template = MITMCaptureTemplate(replacement).regularExpressionTemplate(captureGroupCount: regex.numberOfCaptureGroups)
        return CompiledOperation(search: regex, template: template)
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
        var replacedAny = false
        for operation in operations {
            switch await boundedReplace(current, operation: operation) {
            case .failed:
                return body
            case .unmatched:
                continue
            case .replaced(let replaced):
                current = replaced
                replacedAny = true
            }
        }
        guard replacedAny else { return body }
        guard let out = current.data(using: encoding) else { return body }
        return out
    }

    private enum Substitution {
        case replaced(String)
        case unmatched
        case failed
    }

    private static let substitutionTimeLimitSeconds = 1
    private static let hardCapSeconds = 30

    private static let substitutionInFlight = Atomic<Bool>(false)

    private static func boundedReplace(_ text: String, operation: CompiledOperation) async -> Substitution {
        guard substitutionInFlight.compareExchange(
            expected: false, desired: true, ordering: .sequentiallyConsistent
        ).exchanged else {
            logger.warning("[MITM] bodyReplace: Concurrent substitution limit reached")
            return .failed
        }

        let byteCount = text.utf8.count
        let outcome = await MITMRegexConcurrencyBridge.shared.applyingSubstitution(
            operation.search, to: text,
            template: operation.template,
            deadlineMillis: substitutionTimeLimitSeconds * 1000,
            hardCapSeconds: hardCapSeconds,
            hardCapMessage: {
                "bodyReplace regex substitution did not return \(hardCapSeconds)s after blowing its soft budget over a \(byteCount) B body — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed, leaving bodyReplace disabled process-wide. Crashing the Network Extension so the system relaunches it clean."
            },
            onResolved: { substitutionInFlight.store(false, ordering: .sequentiallyConsistent) }
        )

        switch outcome {
        case .completed(let out?):
            return .replaced(out)
        case .completed(nil):
            return .unmatched
        case .timedOut:
            logger.warning("[MITM] bodyReplace: Regex timed out: \(operation.search.pattern)")
            return .failed
        }
    }
}
