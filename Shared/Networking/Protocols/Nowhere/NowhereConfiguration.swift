//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Security
import Synchronization

enum NowhereNetwork: String, Codable, CaseIterable {
    case udp
    case tcp
}

enum NowherePool {
    static let validRange = 0...9
    static let sliderRange = 1...9
    static let enabledDefault = 5
}

struct NowhereTransportIdentityKey: Hashable {
    let configurationID: UUID
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let spec: String?
    let uplink: NowhereNetwork
    let downlink: NowhereNetwork
    let tls: TLSConfiguration
}

struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let spec: String?
    let uplink: NowhereNetwork
    let downlink: NowhereNetwork
    let pool: Int
    let sessionID: Data
    let tls: TLSConfiguration
    let protocolSpec: NowhereProtocol.EffectiveSpec

    init(
        proxyHost: String,
        proxyPort: UInt16,
        key: String,
        spec: String?,
        uplink: NowhereNetwork,
        downlink: NowhereNetwork,
        pool: Int,
        sessionID: Data,
        tls: TLSConfiguration
    ) throws {
        let supportsPreconnect = uplink == .tcp && downlink == .tcp
        guard (!supportsPreconnect && pool == 0)
                || (supportsPreconnect && NowherePool.validRange.contains(pool)) else {
            throw ProxyError.protocolError("Invalid Nowhere pool value")
        }
        guard sessionID.count == 16 else {
            throw ProxyError.protocolError("Invalid Nowhere session ID")
        }
        let effectiveSpec = NowhereProtocol.normalizedSpec(spec)
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.key = key
        self.spec = effectiveSpec
        self.uplink = uplink
        self.downlink = downlink
        self.pool = pool
        self.sessionID = sessionID
        self.tls = tls
        self.protocolSpec = try NowhereProtocol.buildEffectiveSpec(
            key: key,
            spec: effectiveSpec,
            alpn: tls.alpn?.first
        )
    }
}

nonisolated final class NowhereTransportIdentityRegistry {
    static let shared = NowhereTransportIdentityRegistry()

    private struct State {
        let sessionID: Data
        var nextFlowID: UInt64
    }

    private let states = Mutex<[NowhereTransportIdentityKey: State]>([:])

    init() {}

    func identity(for identityKey: NowhereTransportIdentityKey) throws -> Data {
        try states.withLock { states in
            if let state = states[identityKey] { return state.sessionID }
            var bytes = Data(count: 16)
            let status = bytes.withUnsafeMutableBytes { raw -> Int32 in
                guard let base = raw.baseAddress else { return errSecAllocate }
                return SecRandomCopyBytes(kSecRandomDefault, 16, base)
            }
            guard status == errSecSuccess else {
                throw NowhereError.connectionFailed("Failed to generate session ID")
            }
            states[identityKey] = State(sessionID: bytes, nextFlowID: 1)
            return bytes
        }
    }

    func nextFlowID(
        for identityKey: NowhereTransportIdentityKey,
        sessionID expectedSessionID: Data
    ) throws -> UInt64 {
        return try states.withLock { states in
            guard var state = states[identityKey],
                  state.sessionID == expectedSessionID else {
                // reset()/reclaim invalidated the identity used to construct
                // this in-flight configuration. Never recreate it here: that
                // would pair an old session ID with a new flow counter.
                throw NowhereError.streamClosed
            }
            let value = state.nextFlowID
            guard value != UInt64.max else {
                throw NowhereError.connectionFailed("Nowhere flow ID space exhausted")
            }
            state.nextFlowID = value + 1
            states[identityKey] = state
            return value
        }
    }

    func reset() {
        states.withLock { $0.removeAll(keepingCapacity: false) }
    }
}
