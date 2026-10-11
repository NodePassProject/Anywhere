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

    enum Outcome<T: Sendable>: Sendable {
        case completed(T)
        case timedOut
    }
    
    private final class DoneFlag: Sendable {
        let finished = Atomic<Bool>(false)
    }

    // MARK: - Regex operations
    
    func firstMatch(
        _ regex: NSRegularExpression,
        in string: String,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        onResolved: (@Sendable (Bool) -> Void)? = nil
    ) async -> Outcome<Bool> {
        let abortAfterSeconds = Self.abortAfterSeconds(hardCapSeconds: hardCapSeconds)
        return await run(deadlineMillis: deadlineMillis, hardCapSeconds: hardCapSeconds, hardCapMessage: hardCapMessage) {
            let matched: Bool
            switch Self.scanFirstMatch(regex, in: string, abortAfterSeconds: abortAfterSeconds) {
            case .match: matched = true
            case .noMatch: matched = false
            case .aborted: return false
            }
            onResolved?(matched)
            return matched
        }
    }
    
    func firstMatchCaptureGroups(
        _ regex: NSRegularExpression,
        in string: String,
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String
    ) async -> Outcome<[String?]?> {
        let abortAfterSeconds = Self.abortAfterSeconds(hardCapSeconds: hardCapSeconds)
        return await run(deadlineMillis: deadlineMillis, hardCapSeconds: hardCapSeconds, hardCapMessage: hardCapMessage) {
            Self.captureGroups(regex, in: string, abortAfterSeconds: abortAfterSeconds)
        }
    }
    
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

    private enum ScanResult {
        case match(NSTextCheckingResult)
        case noMatch
        case aborted
    }
    
    private static func abortAfterSeconds(hardCapSeconds: Int) -> Int {
        max(1, hardCapSeconds / 2)
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
    
    private static func captureGroups(_ regex: NSRegularExpression, in string: String, abortAfterSeconds: Int) -> [String?]? {
        guard case .match(let match) = scanFirstMatch(regex, in: string, abortAfterSeconds: abortAfterSeconds) else {
            return nil
        }
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
    
    private func run<T: Sendable>(
        deadlineMillis: Int,
        hardCapSeconds: Int,
        hardCapMessage: @escaping @Sendable () -> String,
        _ body: @escaping @Sendable () -> T
    ) async -> Outcome<T> {
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
                try? await Task.sleep(for: .milliseconds(deadlineMillis), precision: .prompt)
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
            try? await Task.sleep(for: .seconds(hardCapSeconds), precision: .lazy)
            guard !flag.finished.load(ordering: .sequentiallyConsistent) else { return }
            fatalError(message())
        }
    }
}
