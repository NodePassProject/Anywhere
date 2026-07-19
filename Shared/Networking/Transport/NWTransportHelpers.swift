//
//  NWTransportHelpers.swift
//  Anywhere
//
//  Created by NodePassProject on 7/6/26.
//

import Foundation
import Network

// MARK: - NWError

extension NWError {

    /// The `AnywhereError` equivalent of this error for operation `op`.
    nonisolated func anywhereError(op: AnywhereError.Transport.Operation) -> AnywhereError {
        switch self {
        case .posix(let code):
            return .transport(.posix(op, errno: code.rawValue))
        case .dns:
            return .dns(.resolutionFailed(host: nil, detail: localizedDescription))
        default:
            // .tls and any SDK-newer cases (e.g. .wifiAware) fold to a generic failure.
            return .transport(.connectionFailed(endpoint: nil, detail: localizedDescription))
        }
    }

    /// Diagnostic description of a `.waiting` state report, decoding the
    /// underlying errno/DNS code.
    nonisolated var connectWaitingDescription: String {
        switch self {
        case .posix(let code):
            return "waiting(errno \(code.rawValue): \(String(cString: strerror(code.rawValue))))"
        case .dns(let code):
            return "waiting(dns \(code))"
        default:
            return "waiting(\(localizedDescription))"
        }
    }

}

// MARK: - AnywhereError mapping

extension AnywhereError {

    /// Maps an arbitrary throw from a `NetworkConnection` connect/send/receive to
    /// an `AnywhereError` for operation `op`. Shared by the byte-stream and
    /// datagram transports.
    nonisolated static func networkFailure(_ error: Error, op: Transport.Operation) -> AnywhereError {
        if error is CancellationError { return .transport(.terminated) }
        if let nwError = error as? NWError { return nwError.anywhereError(op: op) }
        if let anywhereError = error as? AnywhereError { return anywhereError }
        return .transport(.connectionFailed(endpoint: nil, detail: error.localizedDescription))
    }

    /// The raw `errno` for such a throw; the QUIC datagram carrier feeds a code to
    /// ngtcp2 rather than an `AnywhereError`.
    nonisolated static func errnoCode(from error: Error) -> Int32 {
        if error is CancellationError { return ECANCELED }
        if let nwError = error as? NWError, case .posix(let posix) = nwError { return posix.rawValue }
        return -1
    }
}

// MARK: - NWEndpoint.Host

extension NWEndpoint.Host {

    /// The `.ipv4`/`.ipv6` host for an IP literal; nil when `ip` isn't one.
    nonisolated init?(ipLiteral ip: String) {
        if ip.contains(":") {
            guard let address = IPv6Address(ip) else { return nil }
            self = .ipv6(address)
        } else {
            guard let address = IPv4Address(ip) else { return nil }
            self = .ipv4(address)
        }
    }
}
