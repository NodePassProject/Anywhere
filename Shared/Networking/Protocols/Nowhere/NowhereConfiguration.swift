//
//  NowhereConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Security
import Synchronization

nonisolated enum NowhereNetwork: String, Codable, CaseIterable {
    case udp
    case tcp
}

nonisolated enum NowherePool {
    static let validRange = 0...9
    static let sliderRange = 1...9
    static let enabledDefault = 5
}

nonisolated struct NowhereTransportIdentityKey: Hashable {
    let configurationID: UUID
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let uplink: NowhereNetwork
    let downlink: NowhereNetwork
    let tls: TLSConfiguration
}

nonisolated struct NowhereConfiguration: Hashable {
    let proxyHost: String
    let proxyPort: UInt16
    let key: String
    let uplink: NowhereNetwork
    let downlink: NowhereNetwork
    let pool: Int
    let sessionID: Data
    let tls: TLSConfiguration
    let alpn: String
    let authKey: NowhereProtocol.AuthKey

    init(
        proxyHost: String,
        proxyPort: UInt16,
        key: String,
        uplink: NowhereNetwork,
        downlink: NowhereNetwork,
        pool: Int,
        sessionID: Data,
        tls: TLSConfiguration
    ) throws {
        let supportsPool = uplink == .tcp && downlink == .tcp
        guard (!supportsPool && pool == 0)
                || (supportsPool && NowherePool.validRange.contains(pool)) else {
            throw ProxyError.protocolError("Invalid Nowhere pool value")
        }
        guard sessionID.count == 16 else {
            throw ProxyError.protocolError("Invalid Nowhere session ID")
        }
        let alpn = tls.alpn?.first ?? NowhereProtocol.defaultALPN
        guard !alpn.isEmpty, alpn.utf8.count <= UInt8.max else {
            throw ProxyError.protocolError("Invalid Nowhere ALPN")
        }
        self.proxyHost = proxyHost
        self.proxyPort = proxyPort
        self.key = key
        self.uplink = uplink
        self.downlink = downlink
        self.pool = pool
        self.sessionID = sessionID
        self.tls = tls
        self.alpn = alpn
        self.authKey = try NowhereProtocol.deriveAuthKey(sharedKey: key)
    }
}

nonisolated final class NowhereFlowIDLease: @unchecked Sendable {
    let flowID: UInt32
    private let releaseImpl: @Sendable (UInt32) -> Void
    private let released = Mutex(false)

    init(flowID: UInt32, release: @escaping @Sendable (UInt32) -> Void) {
        self.flowID = flowID
        self.releaseImpl = release
    }

    func release() {
        let shouldRelease = released.withLock { released in
            guard !released else { return false }
            released = true
            return true
        }
        if shouldRelease { releaseImpl(flowID) }
    }

    deinit { release() }
}

nonisolated final class NowhereTransportIdentityRegistry {
    static let shared = NowhereTransportIdentityRegistry()

    private struct State {
        let sessionID: Data
        var nextFlowID: UInt32
        var activeFlowIDs: Set<UInt32>
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
            states[identityKey] = State(sessionID: bytes, nextFlowID: 1, activeFlowIDs: [])
            return bytes
        }
    }

    func leaseFlowID(
        for identityKey: NowhereTransportIdentityKey,
        sessionID expectedSessionID: Data
    ) throws -> NowhereFlowIDLease {
        let flowID = try states.withLock { states -> UInt32 in
            guard var state = states[identityKey], state.sessionID == expectedSessionID else {
                throw NowhereError.streamClosed
            }
            var candidate = max(state.nextFlowID, 1)
            for _ in 0...state.activeFlowIDs.count {
                if candidate != 0, !state.activeFlowIDs.contains(candidate) {
                    state.activeFlowIDs.insert(candidate)
                    state.nextFlowID = candidate &+ 1
                    if state.nextFlowID == 0 { state.nextFlowID = 1 }
                    states[identityKey] = state
                    return candidate
                }
                candidate &+= 1
                if candidate == 0 { candidate = 1 }
            }
            throw NowhereError.connectionFailed("Nowhere flow ID space exhausted")
        }
        return NowhereFlowIDLease(flowID: flowID) { [weak self] released in
            self?.releaseFlowID(released, for: identityKey, sessionID: expectedSessionID)
        }
    }

    private func releaseFlowID(
        _ flowID: UInt32,
        for identityKey: NowhereTransportIdentityKey,
        sessionID expectedSessionID: Data
    ) {
        states.withLock { states in
            guard var state = states[identityKey], state.sessionID == expectedSessionID else { return }
            state.activeFlowIDs.remove(flowID)
            states[identityKey] = state
        }
    }

    func reset() {
        states.withLock { $0.removeAll(keepingCapacity: false) }
    }
}
