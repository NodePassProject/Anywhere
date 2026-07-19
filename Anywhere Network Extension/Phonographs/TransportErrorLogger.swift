//
//  TransportErrorLogger.swift
//  Anywhere
//
//  Created by NodePassProject on 4/18/26.
//

import Foundation

/// Shared error-reporting helper for TCP/UDP connections: terminal failures log
/// exactly once via ConnectionFailureReporter, transient sends log at warning,
/// and inner transport layers propagate errors instead of logging.
nonisolated enum TransportErrorLogger {

    // MARK: - Formatting

    /// Concise text for a log line that already names its operation. `AnywhereError`s
    /// drop their subsystem tag; legacy enums get their baked-in prefix stripped.
    static func conciseErrorDescription(_ error: Error) -> String {
        if let error = error as? AnywhereError { return error.conciseDescription }
        var message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        let redundantPrefixes = [
            "Connection failed: ",
            "Send failed: ",
            "Receive failed: ",
            "DNS resolution failed: "
        ]

        for prefix in redundantPrefixes where message.hasPrefix(prefix) {
            message.removeFirst(prefix.count)
            break
        }

        return message
    }

    // MARK: - Terminal Failure Logging

    fileprivate static func logTerminal(
        operation: String,
        endpoint: String,
        error: Error,
        logger: AnywhereLogger,
        prefix: String,
        context: String? = nil
    ) {
        let errorDescription = conciseErrorDescription(error)
        let suffix = context.map { " [\($0)]" } ?? ""

        if case AnywhereError.proxy(.naive, _) = error {
            logger.debug("\(prefix) \(operation) error: \(endpoint): \(errorDescription)\(suffix)")
            return
        }

        // Peer-initiated closes get distinct wording; the error's suggested level
        // covers everything else (unmigrated error types default to .error).
        switch (error as? AnywhereError)?.peerClose {
        case .cascade:
            logger.debug("\(prefix) \(operation) after peer close: \(endpoint): \(errorDescription)\(suffix)")
            return
        case .reset:
            logger.info("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)\(suffix)")
            return
        case .none:
            break
        }

        let line = "\(prefix) \(operation) failed: \(endpoint): \(errorDescription)\(suffix)"
        switch AnywhereError.severity(of: error) {
        case .debug: logger.debug(line)
        case .info: logger.info(line)
        case .warning: logger.warning(line)
        case .error: logger.error(line)
        }
    }

    // MARK: - Transient Failure Logging

    static func logTransientSend(
        endpoint: String,
        error: Error,
        logger: AnywhereLogger,
        prefix: String
    ) {
        let errorDescription = conciseErrorDescription(error)
        logger.warning("\(prefix) Send failed: \(endpoint): \(errorDescription)")
    }
}

// MARK: - DialDiagnostics

/// Kernel-flow-ledger snapshots appended to TCP connect-failure logs.
nonisolated enum DialDiagnostics {

    /// E.g. `flows=312/384 pending=6 udp=96 lwip=205`. Must run on
    /// lwipQueue (the PCB count is lwipQueue-confined). The active-pcb count is
    /// read through the bridge's wrapper so the raw `lwip_bridge_*` C symbol
    /// stays inside ``LWIPConcurrencyBridge``.
    static func snapshot(bridge: LWIPConcurrencyBridge) -> String {
        "flows=\(FlowGauge.live)/\(TunnelLimits.flowBudget) "
            + "pending=\(FlowGauge.pendingTCP) udp=\(FlowGauge.liveUDP) "
            + "lwip=\(bridge.activeTCPCount())"
    }
}

// MARK: - ConnectionFailureReporter

/// Emits exactly one terminal-failure line per connection; later reports no-op.
nonisolated final class ConnectionFailureReporter {
    private let prefix: String
    private let logger: AnywhereLogger
    private var reported = false

    init(prefix: String, logger: AnywhereLogger) {
        self.prefix = prefix
        self.logger = logger
    }
    
    func report(operation: String, endpoint: @autoclosure () -> String, error: Error,
                context: @autoclosure () -> String? = nil) {
        guard !reported else { return }
        reported = true
        TransportErrorLogger.logTerminal(
            operation: operation,
            endpoint: endpoint(),
            error: error,
            logger: logger,
            prefix: prefix,
            context: context()
        )
    }

    /// Marks reported without logging, so a non-error close suppresses any
    /// spurious error log later in teardown.
    func markReported() {
        reported = true
    }
}
