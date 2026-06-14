//
//  ProxyChain.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

/// A named, ordered proxy chain: the last proxy is the exit (talks to the
/// target), preceding proxies are tunneled through in order.
struct ProxyChain: Identifiable, Codable, Hashable {
    let id: UUID
    var name: String
    /// Ordered proxy IDs. First is the entry (outermost TCP), last is the exit.
    var proxyIds: [UUID]
    var deletedAt: Date? = nil

    init(id: UUID = UUID(), name: String, proxyIds: [UUID] = []) {
        self.id = id
        self.name = name
        self.proxyIds = proxyIds
    }

    /// Resolves the ordered proxy IDs against the pool; missing IDs are skipped.
    func resolveProxies(from pool: [ProxyConfiguration]) -> [ProxyConfiguration] {
        proxyIds.compactMap { id in pool.first(where: { $0.id == id }) }
    }

    /// Resolves into a single composite configuration (last = exit, rest fill `chain`);
    /// nil if any proxy is missing or fewer than 2 resolve.
    func resolveComposite(from pool: [ProxyConfiguration]) -> ProxyConfiguration? {
        let configs = resolveProxies(from: pool)
        guard configs.count == proxyIds.count, configs.count >= 2 else { return nil }
        let exit = configs.last!
        return ProxyConfiguration(
            name: name,
            serverAddress: exit.serverAddress,
            serverPort: exit.serverPort,
            outbound: exit.outbound,
            chain: Array(configs.dropLast())
        )
    }

    /// Display summary for a chain row, resolved against the pool: the member names,
    /// whether the chain is complete (≥2 proxies, none missing), and the entry/exit addresses.
    func listDisplayInfo(configurations: [ProxyConfiguration]) -> (names: [String], isValid: Bool, entry: String?, exit: String?) {
        let proxies = resolveProxies(from: configurations)
        let isValid = proxies.count == proxyIds.count && proxies.count >= 2
        let entry = proxies.count >= 2 ? proxies.first?.serverAddress : nil
        let exit = proxies.count >= 2 ? proxies.last?.serverAddress : nil
        return (proxies.map(\.name), isValid, entry, exit)
    }
}
