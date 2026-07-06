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

    /// Strips the operation prefix `TransportError.errorDescription` bakes in; the log line repeats it.
    static func conciseErrorDescription(_ error: Error) -> String {
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

    /// Classifies a `TransportError`'s errno as a peer-initiated close, or nil.
    private static func peerCloseClass(for error: Error) -> PeerCloseClass? {
        guard let errno = (error as? TransportError)?.posixErrno else { return nil }
        switch errno {
        case EPIPE:        return .cascade     // write after we've seen EOF/RST
        case ECONNRESET:   return .reset       // remote sent RST
        default:           return nil
        }
    }

    private enum PeerCloseClass {
        /// Secondary failure behind an earlier RST/EOF; logging would double-report.
        case cascade
        /// Peer-initiated RST — expected termination, not our failure.
        case reset
    }

    // MARK: - lwIP Error Codes

    /// Human-readable lwIP `err_t` description. Must mirror lwip/src/include/lwip/err.h.
    static func describeLwIPError(_ err: Int32) -> String {
        switch err {
        case 0:   return "ERR_OK"
        case -1:  return "ERR_MEM (out of memory)"
        case -2:  return "ERR_BUF (buffer error)"
        case -3:  return "ERR_TIMEOUT (timed out)"
        case -4:  return "ERR_RTE (routing problem)"
        case -5:  return "ERR_INPROGRESS"
        case -6:  return "ERR_VAL (illegal value)"
        case -7:  return "ERR_WOULDBLOCK"
        case -8:  return "ERR_USE (address in use)"
        case -9:  return "ERR_ALREADY (already connecting)"
        case -10: return "ERR_ISCONN (already connected)"
        case -11: return "ERR_CONN (not connected)"
        case -12: return "ERR_IF (low-level netif error)"
        case -13: return "ERR_ABRT (aborted locally)"
        case -14: return "ERR_RST (reset by peer)"
        case -15: return "ERR_CLSD (connection closed)"
        case -16: return "ERR_ARG (illegal argument)"
        default:  return "lwIP err=\(err)"
        }
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

        if error is NaiveHTTP2Error {
            logger.debug("\(prefix) \(operation) error: \(endpoint): \(errorDescription)\(suffix)")
            return
        }

        switch peerCloseClass(for: error) {
        case .cascade:
            logger.debug("\(prefix) \(operation) after peer close: \(endpoint): \(errorDescription)\(suffix)")
            return
        case .reset:
            logger.info("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)\(suffix)")
            return
        case .none:
            break
        }

        logger.error("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)\(suffix)")
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

    /// E.g. `flows=312/384 pending=6 udp=96 lwip=205 brake=12s`. Must run on
    /// lwipQueue (the PCB count is lwipQueue-confined).
    static func snapshot() -> String {
        var parts = "flows=\(FlowGauge.live)/\(TunnelLimits.flowBudget) "
            + "pending=\(FlowGauge.pendingTCP) udp=\(FlowGauge.liveUDP) "
            + "lwip=\(Int(lwip_bridge_active_tcp_count()))"
        let braked = FlowExhaustionBrake.shared.remainingSeconds
        if braked > 0 {
            parts += " brake=\(Int(braked.rounded(.up)))s"
        }
        return parts
    }
}

// MARK: - ConnectionFailureReporter

/// Emits exactly one terminal-failure line per connection; later reports no-op.
final class ConnectionFailureReporter {
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
