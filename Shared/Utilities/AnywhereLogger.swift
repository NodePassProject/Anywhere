//
//  AnywhereLogger.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/8/26.
//

import Foundation
import os.log

/// Unified logger for the Anywhere app and its extensions.
///
/// `info`, `warning`, and `error` write to os.log (Console.app) and optionally
/// to a log sink (user-facing log viewer in the Network Extension).
/// `debug` writes to os.log only — use for verbose/internal diagnostics.
struct AnywhereLogger {
    private let osLogger: Logger

    /// Optional log sink for dual logging. Set by the Network Extension at
    /// startup to forward logs to the user-facing log buffer; nil in the
    /// main app (os.log only).
    static var logSink: ((String, Level) -> Void)?

    enum Level: String {
        case info, warning, error
    }

    init(category: String) {
        self.osLogger = Logger(subsystem: "com.argsment.Anywhere", category: category)
    }

    func info(_ message: String) {
        osLogger.info("\(message, privacy: .public)")
        Self.logSink?(message, .info)
    }

    func warning(_ message: String) {
        osLogger.warning("\(message, privacy: .public)")
        Self.logSink?(message, .warning)
    }

    func error(_ message: String) {
        osLogger.error("\(message, privacy: .public)")
        Self.logSink?(message, .error)
    }

    /// Logs to os.log only. Not shown in the user-facing log viewer.
    func debug(_ message: String) {
        osLogger.debug("\(message, privacy: .public)")
    }
}
