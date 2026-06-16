//
//  MITMBodyReplace.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMBodyReplace")

/// Native regex find-and-replace over a text body. Replacements are literal — no `$1`
/// capture expansion; a body decodable as neither UTF-8 nor latin-1 is returned unchanged.
enum MITMBodyReplace {

    /// Pre-compiled so the per-message hot path skips pattern parsing.
    struct CompiledOp {
        let search: Regex<AnyRegexOutput>
        let replacement: String
    }

    /// Returns nil when the pattern won't compile; the replacement is never validated.
    static func compile(search: String, replacement: String) -> CompiledOp? {
        guard let regex = try? Regex(search) else { return nil }
        return CompiledOp(search: regex, replacement: replacement)
    }

    /// Applies every compiled edit in order; fail-closed on an undecodable body or a blown budget.
    ///
    /// Decodes as UTF-8 first; on failure falls back to ISO-8859-1 (latin-1), which round-trips any
    /// byte sequence losslessly, so single-byte-charset bodies (Windows-125x / ISO-8859-x) are
    /// edited in place instead of silently passing through (mitmproxy's latin-1 fallback). The body
    /// is re-encoded in the same charset; if the replacement introduced characters that charset
    /// can't represent, the edit is abandoned and the original body is returned unchanged.
    /// Multi-byte charsets (UTF-16, GBK, …) are still not covered — those bodies pass through.
    static func applyAll(_ ops: [CompiledOp], to body: Data) -> Data {
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
            guard let replaced = boundedReplace(current, op: op) else {
                // Fail closed rather than emit a half-applied chain.
                return body
            }
            current = replaced
        }
        // Re-encode in the source charset; a replacement that isn't representable there fails closed.
        guard let out = current.data(using: encoding) else { return body }
        return out
    }

    /// Soft budget per substitution; Swift Regex has no execution limit, so a runaway
    /// pattern is abandoned to avoid head-of-line blocking. Generous for the 4 MiB body cap.
    private static let substitutionTimeLimit: DispatchTimeInterval = .seconds(1)

    /// Hard crash deadline after the soft budget: a Regex match is uninterruptible and the
    /// stuck in-flight flag leaves bodyReplace disabled process-wide, so crash for a clean relaunch.
    static let hardCapSeconds = 30

    /// Carries the (possibly runaway) substitution off the shared script queue;
    /// `substitutionInFlight` bounds a runaway to one busy core with no backlog.
    private static let watchdogQueue = DispatchQueue(
        label: AWCore.Identifier.mitmBodyWatchdogQueue,
        qos: .userInitiated
    )

    private static let inFlightLock = NSLock()
    private static var substitutionInFlight = false

    /// Runs one substitution under the soft budget; nil on timeout or while a prior runaway is still burning.
    private static func boundedReplace(_ text: String, op: CompiledOp) -> String? {
        inFlightLock.lock()
        if substitutionInFlight {
            inFlightLock.unlock()
            return nil
        }
        substitutionInFlight = true
        inFlightLock.unlock()

        let box = ResultBox()
        let done = DispatchSemaphore(value: 0)
        watchdogQueue.async {
            box.value = text.replacing(op.search, with: op.replacement)
            inFlightLock.lock()
            substitutionInFlight = false
            inFlightLock.unlock()
            done.signal()
        }
        // The semaphore establishes happens-before for the unsynchronized box.
        guard done.wait(timeout: .now() + substitutionTimeLimit) == .success else {
            logger.warning("bodyReplace: regex substitution exceeded its time budget over a \(text.utf8.count) B body; leaving the body unchanged (possible catastrophic backtracking in the pattern)")
            // The worker is still spinning with the in-flight flag stuck; arm the hard-cap crash.
            Self.scheduleHardCapCheck(done, byteCount: text.utf8.count)
            return nil
        }
        return box.value
    }

    /// One-shot crash check after the hard cap: a finished substitution signals the
    /// semaphore and makes this a no-op; one still running is crashed to recover.
    private static func scheduleHardCapCheck(_ done: DispatchSemaphore, byteCount: Int) {
        MITMWatchdogMonitor.queue.asyncAfter(deadline: .now() + .seconds(hardCapSeconds)) {
            guard done.wait(timeout: .now()) != .success else { return }
            fatalError("bodyReplace regex substitution did not return \(hardCapSeconds)s after blowing its soft budget over a \(byteCount) B body — a worker thread is permanently pinned by catastrophic backtracking and can't be reclaimed, leaving bodyReplace disabled process-wide. Crashing the Network Extension so the system relaunches it clean.")
        }
    }

    /// Synchronized by the semaphore (written before `signal`, read after `wait`) — hence `@unchecked Sendable`.
    private final class ResultBox: @unchecked Sendable {
        var value: String?
    }
}
