//
//  TransportErrorLogger.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/18/26.
//

import Foundation

/// Shared error-reporting helper for TCP/UDP connections.
///
/// Consolidates the classification logic that both ``LWIPTCPConnection`` and
/// ``LWIPUDPFlow`` used to duplicate: trimming redundant prefixes from
/// `SocketError` descriptions, demoting expected cascade errors so one peer
/// reset doesn't produce a wall of lines, and attributing failures to a recent
/// tunnel interruption when one is in the attribution window.
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

    // MARK: - Classified Logging

    /// Logs a transport-level failure with a consistent shape and level.
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
    /// 4. Otherwise the failure logs at `defaultLevel`.
    ///
    /// - Parameters:
    ///   - operation: "Connect", "Send", "Receive", etc.
    ///   - endpoint: Human-readable endpoint identifier (host:port or flow key).
    ///   - error: The failure.
    ///   - logger: Category logger (LWIP-TCP / LWIP-UDP / …).
    ///   - prefix: Log-line prefix (e.g., "[TCP]", "[UDP]").
    ///   - defaultLevel: Level used when none of the demotion rules apply.
    static func log(
        operation: String,
        endpoint: String,
        error: Error,
        logger: AnywhereLogger,
        prefix: String,
        defaultLevel: LWIPStack.LogLevel = .error
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
            // Peer-initiated RST: normal termination from their side, not a
            // failure of ours — keep it visible but out of the error stream.
            logger.info("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)")
            return
        case .none:
            break
        }

        switch defaultLevel {
        case .info:
            logger.info("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)")
        case .warning:
            logger.warning("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)")
        case .error:
            logger.error("\(prefix) \(operation) failed: \(endpoint): \(errorDescription)")
        }
    }
}
