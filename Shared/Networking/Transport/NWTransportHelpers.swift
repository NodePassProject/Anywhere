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
    nonisolated func anywhereError(operation: AnywhereError.Transport.Operation) -> AnywhereError {
        switch self {
        case .posix(let code):
            return .transport(.posix(operation, errno: code.rawValue))
        case .dns:
            return .dns(.resolutionFailed(host: nil, detail: localizedDescription))
        default:
            return .transport(.connectionFailed(endpoint: nil, detail: localizedDescription))
        }
    }
    
    nonisolated func legacyEngineError(operation: AnywhereError.Transport.Operation) -> any Error {
        if case .posix(.ECANCELED) = self { return CancellationError() }
        return anywhereError(operation: operation)
    }
    
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

// MARK: - AnywhereError

extension AnywhereError {
    nonisolated static func networkFailure(_ error: Error, operation: Transport.Operation) -> AnywhereError {
        if error is CancellationError { return .transport(.terminated) }
        if let nwError = error as? NWError { return nwError.anywhereError(operation: operation) }
        if let anywhereError = error as? AnywhereError { return anywhereError }
        return .transport(.connectionFailed(endpoint: nil, detail: error.localizedDescription))
    }
    
    nonisolated static func errnoCode(from error: Error) -> Int32 {
        if error is CancellationError { return ECANCELED }
        if let nwError = error as? NWError, case .posix(let posix) = nwError { return posix.rawValue }
        return -1
    }
}

// MARK: - NWEndpoint.Host

extension NWEndpoint.Host {
    nonisolated init?(ipLiteral ip: String) {
        if ip.contains(":") {
            guard let address = IPv6Address(ip) else { return nil }
            self = .ipv6(address)
        } else {
            guard let address = IPv4Address(ip) else { return nil }
            self = .ipv4(address)
        }
    }
    
    nonisolated static func dialHost(for host: String, viaProxyDNS: Bool) async -> NWEndpoint.Host {
        if let literal = NWEndpoint.Host(ipLiteral: host) { return literal }
        guard viaProxyDNS,
              let resolved = await DNSResolver.shared.resolveDialAddress(for: host),
              let literal = NWEndpoint.Host(ipLiteral: resolved)
        else { return .name(host, nil) }
        return literal
    }
}
