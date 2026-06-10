//
//  AnywhereLogger.swift
//  Anywhere
//
//  Created by NodePassProject on 4/8/26.
//

import Foundation
import os.log

/// Unified logger. Every level goes to os.log (`debug` in DEBUG builds only);
/// `info` and above also reach the bounded user-facing log viewer, so keep
/// `info` to low-volume milestones or it evicts the warnings and errors.
struct AnywhereLogger {
    private let osLogger: Logger

    /// Sink for the user-facing log viewer; set by the Network Extension at
    /// startup, nil in the main app.
    static var logSink: ((String, Level) -> Void)?

    /// Lowest severity that reaches `logSink`; os.log receives every level
    /// regardless of this floor.
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

    /// Verbose per-connection/per-packet diagnostics, os.log only. Compiled out
    /// of release, where the autoclosure message is never even built.
    func debug(_ message: @autoclosure () -> String) {
#if DEBUG
        let text = message()
        osLogger.debug("\(text, privacy: .public)")
#endif
    }

    /// Lifecycle milestones; keep low volume — they share the bounded
    /// user-facing buffer with warnings and errors.
    func info(_ message: @autoclosure () -> String) { emit(message(), level: .info) }

    /// Degraded-but-recoverable conditions worth surfacing to the user.
    func warning(_ message: @autoclosure () -> String) { emit(message(), level: .warning) }

    /// A failure the user can feel. Route connection teardown errors through
    /// `ConnectionFailureReporter` so each connection logs at most once.
    func error(_ message: @autoclosure () -> String) { emit(message(), level: .error) }

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
