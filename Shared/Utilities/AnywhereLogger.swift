//
//  AnywhereLogger.swift
//  Anywhere
//
//  Created by NodePassProject on 4/8/26.
//

import Foundation
import os.log

/// Unified logger for the Anywhere app and its extensions.
///
/// Severity rule
/// =============
/// Every log line picks exactly one level. The level decides **where the line
/// goes** and, implicitly, **who it is for**:
///
/// | Level     | os.log            | User log viewer | Use for                                    |
/// | --------- | ----------------- | --------------- | ------------------------------------------ |
/// | `error`   | always            | yes             | An operation failed and the user feels it  |
/// | `warning` | always            | yes             | Degraded but recovered / recoverable       |
/// | `info`    | always            | yes             | Lifecycle milestones — low volume          |
/// | `debug`   | DEBUG builds only | no              | Per-connection / per-packet / per-request  |
///
/// Two destinations, two audiences:
/// - **os.log** (Console.app) is the developer firehose. It receives every
///   level; `debug` is compiled out of release builds so the field never pays
///   for verbose diagnostics.
/// - **The user-facing log viewer** (Network Extension only) is a *bounded*,
///   in-memory ring buffer surfaced in the app. It only receives lines at or
///   above ``minimumSinkLevel``. Keeping it legible is the whole point of the
///   floor: reserve `info` for genuine milestones (tunnel start/stop/restart,
///   configuration switch, network-path changes, settings reloads). Anything
///   that fires once per connection, packet, or request is `debug` — otherwise
///   a busy session floods the small buffer and evicts the warnings and errors
///   a user actually needs.
///
/// `info`, `warning`, and `error` write to os.log and, when at or above the
/// sink floor, to ``logSink``. `debug` writes to os.log only.
struct AnywhereLogger {
    private let osLogger: Logger

    /// Sink for the user-facing log viewer. Set by the Network Extension at
    /// startup to forward lines into the in-app log buffer; nil in the main
    /// app, where logging is os.log only.
    static var logSink: ((String, Level) -> Void)?

    /// Lowest severity that reaches ``logSink``. os.log still receives every
    /// level regardless of this floor — it governs only the bounded in-app
    /// buffer, keeping it focused on actionable lines rather than letting
    /// `info` churn evict warnings and errors. `debug` sits below the floor by
    /// design, so it never reaches the viewer.
    static let minimumSinkLevel: Level = .info

    /// Severity, ordered low → high so a line can be gated against a floor.
    enum Level: Int, Comparable, Sendable {
        case debug = 0
        case info = 1
        case warning = 2
        case error = 3

        static func < (lhs: Level, rhs: Level) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    init(category: String) {
        self.osLogger = Logger(subsystem: "com.argsment.Anywhere", category: category)
    }

    /// Per-connection / per-packet churn and other verbose diagnostics. os.log
    /// only (DEBUG builds), never the user-facing viewer.
    ///
    /// ``message`` is an `@autoclosure`, so the (usually interpolated) string is
    /// built only when it will actually be logged. In release the body compiles
    /// away entirely and the closure is never invoked — a `debug` call on a
    /// per-packet path costs nothing, not even the string construction.
    func debug(_ message: @autoclosure () -> String) {
#if DEBUG
        let text = message()
        osLogger.debug("\(text, privacy: .public)")
#endif
    }

    /// Lifecycle milestones. Keep these low volume — they share the bounded
    /// user-facing buffer with warnings and errors.
    func info(_ message: @autoclosure () -> String) { emit(message(), level: .info) }

    /// Degraded-but-recoverable conditions worth surfacing to the user.
    func warning(_ message: @autoclosure () -> String) { emit(message(), level: .warning) }

    /// A failure the user can feel. Connection teardown errors should flow
    /// through `ConnectionFailureReporter` so each connection logs at most once.
    func error(_ message: @autoclosure () -> String) { emit(message(), level: .error) }

    /// Routes one line to os.log and, when it meets ``minimumSinkLevel``, to the
    /// user-facing sink. Only `info` / `warning` / `error` reach here; `debug`
    /// logs to os.log directly (DEBUG only) so it never pays for the sink check.
    private func emit(_ message: String, level: Level) {
        switch level {
        case .debug: break // unreachable: debug() logs to os.log directly
        case .info: osLogger.info("\(message, privacy: .public)")
        case .warning: osLogger.warning("\(message, privacy: .public)")
        case .error: osLogger.error("\(message, privacy: .public)")
        }

        if level >= Self.minimumSinkLevel {
            Self.logSink?(message, level)
        }
    }
}
