//
//  TransportErrorLogger.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/18/26.
//

import Foundation

/// Shared error-reporting helper for TCP/UDP connections.
///
/// Logging policy
/// ==============
/// - Connection failures (TCP connect/send/receive, UDP connect/receive) are
///   terminal events. The user-facing connection (``LWIPTCPConnection`` /
///   ``LWIPUDPFlow``) owns a ``ConnectionFailureReporter`` that logs them
///   exactly once.
/// - Non-terminal send failures (UDP datagram drops, control-frame sends on a
///   still-alive transport) use ``logTransientSend`` and log at warning level.
/// - Inner transport / session / handshake layers must not call
///   ``AnywhereLogger.error`` directly. They propagate errors via
///   `Result`/`Error`; the LWIP boundary logs once.
enum TransportErrorLogger {

    // MARK: - Formatting

    /// Strips the `"<Operation>: "` prefix that `SocketError.errorDescription`
    /// already bakes in, because the operation word is also in our log line.
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

    /// Classifies a ``SocketError``'s POSIX errno (if any) into a log demotion
    /// bucket. Returns `nil` when the error doesn't carry an errno or its
    /// errno isn't one we recognize as a peer-initiated close.
    private static func peerCloseClass(for error: Error) -> PeerCloseClass? {
        guard let errno = (error as? SocketError)?.posixErrno else { return nil }
        switch errno {
        case EPIPE:        return .cascade     // write after we've seen EOF/RST
        case ECONNRESET:   return .reset       // remote sent RST
        default:           return nil
        }
    }

    private enum PeerCloseClass {
        /// Secondary failure after the peer has already dropped — logging it
        /// would double-report behind an earlier RST/EOF.
        case cascade
        /// Primary notification of a peer-initiated RST — expected
        /// termination from the remote's side, not our failure.
        case reset
    }

    // MARK: - lwIP Error Codes

    /// Human-readable description for an lwIP `err_t` value delivered via the
    /// `tcp_err` callback. Mirrors the definitions in
    /// `lwip/src/include/lwip/err.h`.
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

    /// Logs a terminal connection failure with consistent shape and level.
    /// Used by ``ConnectionFailureReporter``; not intended for direct use.
    ///
    /// Classification, in order:
    /// 1. `HTTP2Error` is downgraded to `debug` — GOAWAY/stream-reset is normal
    ///    churn in a long-lived h2 tunnel and doesn't indicate a user-visible
    ///    problem.
    /// 2. `SocketError` carrying `EPIPE` is demoted to `debug` — by definition
    ///    a cascade behind an earlier receive error or RST. Logging it would
    ///    double-report.
    /// 3. `SocketError` carrying `ECONNRESET` is demoted to `info` — expected
    ///    termination from the remote's side, not our failure.
    /// 4. Otherwise the failure logs at `error`.
    fileprivate static func logTerminal(
        operation: String,
        endpoint: String,
        error: Error,
        logger: AnywhereLogger,
        prefix: String
    ) {
        let errorDescription = conciseErrorDescription(error)

        if error is HTTP2Error {
            logger.debug("\(prefix) \(operation) error: \(endpoint): \(errorDescription)")
            return
        }

        switch peerCloseClass(for: error) {
        case .cascade:
            logger.debug("\(prefix) \(operation) after peer close: \(endpoint): \(errorDescription)")
            return
        case .reset:
            logger.info("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)")
            return
        case .none:
            break
        }

        logger.error("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)")
    }

    // MARK: - Transient Failure Logging

    /// Logs a non-terminal send failure at warning level.
    ///
    /// Use this for UDP datagram sends that don't tear the flow down (UDP is
    /// lossy by design) or for control-frame sends on a still-alive transport
    /// where the failure is recoverable.
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

// MARK: - ConnectionFailureReporter

/// One-shot terminal-failure reporter owned by an LWIP-layer connection.
///
/// The first ``report(operation:endpoint:error:)`` call logs at error level
/// (subject to ``TransportErrorLogger``'s peer-close demotion rules);
/// subsequent calls no-op. Guarantees that exactly one error line is emitted
/// for any given connection's death, regardless of how many failure paths
/// fire during teardown.
///
/// Not thread-safe by itself. Intended to be owned by a connection that
/// serializes access through its own queue (`lwipQueue`).
final class ConnectionFailureReporter {
    private let prefix: String
    private let logger: AnywhereLogger
    private var reported = false

    init(prefix: String, logger: AnywhereLogger) {
        self.prefix = prefix
        self.logger = logger
    }

    /// Logs the terminal failure the first time it's called. Subsequent calls
    /// are no-ops. `endpoint` is supplied at call time so callers can surface
    /// the most current endpoint description (e.g. post-SNI hostname).
    func report(operation: String, endpoint: @autoclosure () -> String, error: Error) {
        guard !reported else { return }
        reported = true
        TransportErrorLogger.logTerminal(
            operation: operation,
            endpoint: endpoint(),
            error: error,
            logger: logger,
            prefix: prefix
        )
    }

    /// Marks the connection as reported without logging. Use when the
    /// connection is ending for a non-error reason (graceful close, deliberate
    /// reject, system pressure abort with its own warning) but we want to
    /// suppress any spurious error log that might fire later in teardown.
    func markReported() {
        reported = true
    }
}
