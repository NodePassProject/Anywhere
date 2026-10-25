//
//  RFCMultiplexerRegistry.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import Foundation
import Synchronization

nonisolated final class RFCMultiplexerRegistry: Sendable {
    nonisolated static let shared = RFCMultiplexerRegistry()
    
    private struct Key: Hashable {
        let host: String
        let port: UInt16
        let serverName: String
        let alpn: String
        let fingerprint: String
        let insecureSkipVerify: Bool
        let echEnabled: Bool
        let echConfig: String
        let chain: [ProxyConfiguration]
    }

    private struct State {
        var pools: [Key: RFCMultiplexerPool] = [:]
        var sealed = false
    }
    private let state = Mutex(State())

    private init() {}
    
    func seal() { state.withLock { $0.sealed = true } }

    func unseal() { state.withLock { $0.sealed = false } }
    
    func pool(for configuration: ProxyConfiguration) -> RFCMultiplexerPool? {
        guard case .rfc(let rfc) = configuration.outbound,
              let tls = rfc.tlsConfiguration else {
            return nil
        }

        let key = Key(
            host: configuration.serverAddress,
            port: configuration.serverPort,
            serverName: tls.serverName,
            alpn: (tls.alpn ?? RFCProtocol.defaultALPN).joined(separator: ","),
            fingerprint: tls.fingerprint.rawValue,
            insecureSkipVerify: tls.insecureSkipVerify,
            echEnabled: tls.echEnabled,
            echConfig: tls.echConfig ?? "",
            chain: configuration.chain ?? []
        )
        
        let pool = state.withLock { state -> RFCMultiplexerPool? in
            if let existing = state.pools[key] { return existing }
            guard !state.sealed else { return nil }
            let created = RFCMultiplexerPool()
            state.pools[key] = created
            return created
        }

        guard let pool else {
            return nil
        }
        return pool
    }

    func closeAll() {
        let snapshot = state.withLock { state -> [RFCMultiplexerPool] in
            let values = Array(state.pools.values)
            state.pools.removeAll(keepingCapacity: false)
            return values
        }
        for pool in snapshot {
            pool.closeAll()
        }
    }
}

nonisolated extension RFCMultiplexerRegistry: TransportPool {
    func reclaim() { closeAll() }
}
