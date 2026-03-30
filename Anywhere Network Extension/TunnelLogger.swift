//
//  TunnelLogger.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation
import os.log

/// Unified logger for the network extension.
///
/// `info`, `warning`, and `error` write to both os.log (Console.app)
/// and the ``LWIPStack`` log buffer (user-facing log viewer).
/// `debug` writes to os.log only — use for verbose/internal diagnostics.
struct TunnelLogger {
    private let osLogger: Logger

    init(category: String) {
        self.osLogger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: category)
    }

    /// Logs to both os.log and the user-facing log buffer.
    func info(_ message: String) {
        osLogger.info("\(message, privacy: .public)")
        LWIPStack.shared?.appendLog(message, level: .info)
    }

    func warning(_ message: String) {
        osLogger.warning("\(message, privacy: .public)")
        LWIPStack.shared?.appendLog(message, level: .warning)
    }

    func error(_ message: String) {
        osLogger.error("\(message, privacy: .public)")
        LWIPStack.shared?.appendLog(message, level: .error)
    }

    /// Logs to os.log only. Not shown in the user-facing log viewer.
    func debug(_ message: String) {
        osLogger.debug("\(message, privacy: .public)")
    }
}
