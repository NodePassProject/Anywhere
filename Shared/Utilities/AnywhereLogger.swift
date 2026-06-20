//
//  AnywhereLogger.swift
//  Anywhere
//
//  Created by NodePassProject on 4/8/26.
//

import Foundation
import os.log

/// `info`+ also reach the bounded user-facing viewer; keep `info` low-volume or
/// it evicts warnings and errors.
nonisolated struct AnywhereLogger {
    private let osLogger: Logger

    /// Set by the Network Extension at startup; nil in the main app.
    static var logSink: ((String, Level) -> Void)?

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
            Self.logSink?(message, level)
        }
    }
}
