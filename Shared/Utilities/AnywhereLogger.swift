//
//  AnywhereLogger.swift
//  Anywhere
//
//  Created by NodePassProject on 4/8/26.
//

import Foundation
import Synchronization
import os.log

/// `info`+ also reach the bounded user-facing viewer; keep `info` low-volume or
/// it evicts warnings and errors.
nonisolated struct AnywhereLogger {
    private let osLogger: Logger

    /// The user-facing viewer sink, guarded because it is installed on one thread and read from
    /// every logging thread. Not exposed as a synchronous `var`: writers call ``installLogSink``
    /// and ``emit`` snapshots it under the lock, then invokes the closure off-lock.
    private static let _logSink = Mutex<((String, Level) -> Void)?>(nil)

    /// Installs (or, with `nil`, removes) the log sink. Set by the Network Extension at
    /// startup; the main app never installs one.
    static func installLogSink(_ sink: ((String, Level) -> Void)?) {
        _logSink.withLock { $0 = sink }
    }

    /// Floor for `logSink` only; os.log receives every level regardless.
    static let minimumSinkLevel: Level = .info

    /// Ordered low → high so a line can be gated against a floor.
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

    /// os.log only; compiled out of release, where the autoclosure is never built.
    func debug(_ message: @autoclosure () -> String) {
#if DEBUG
        let text = message()
        osLogger.debug("\(text, privacy: .public)")
#endif
    }

    /// Keep low volume — shares the bounded user-facing buffer with warnings/errors.
    func info(_ message: @autoclosure () -> String) { emit(message(), level: .info) }

    func warning(_ message: @autoclosure () -> String) { emit(message(), level: .warning) }

    /// Route connection teardown errors through `ConnectionFailureReporter` so
    /// each connection logs at most once.
    func error(_ message: @autoclosure () -> String) { emit(message(), level: .error) }

    private func emit(_ message: String, level: Level) {
        switch level {
        case .debug: break // unreachable: debug() logs to os.log directly
        case .info: osLogger.info("\(message, privacy: .public)")
        case .warning: osLogger.warning("\(message, privacy: .public)")
        case .error: osLogger.error("\(message, privacy: .public)")
        }

        if level >= Self.minimumSinkLevel {
            let sink = Self._logSink.withLock { $0 }
            sink?(message, level)
        }
    }
}
