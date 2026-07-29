//
//  ProxyChain.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

nonisolated struct ProxyChain: Identifiable, Codable, Hashable, SoftDeletable {
    let id: UUID
    var name: String
    var proxyIds: [UUID]
    var updatedAt: Date
    var deletedAt: Date? = nil

    init(id: UUID = UUID(), name: String, proxyIds: [UUID] = [], updatedAt: Date = .now) {
        self.id = id
        self.name = name
        self.proxyIds = proxyIds
        self.updatedAt = updatedAt
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        proxyIds = try container.decode([UUID].self, forKey: .proxyIds)
        updatedAt = try container.decodeIfPresent(Date.self, forKey: .updatedAt) ?? deletedAt ?? .distantPast
        deletedAt = try container.decodeIfPresent(Date.self, forKey: .deletedAt)
    }
    
    func resolveProxies(from pool: [ProxyConfiguration]) -> [ProxyConfiguration] {
        proxyIds.compactMap { id in pool.first(where: { $0.id == id }) }
    }
    
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
    
    func listDisplayInfo(configurations: [ProxyConfiguration]) -> (names: [String], isValid: Bool, entry: String?, exit: String?) {
        let proxies = resolveProxies(from: configurations)
        let isValid = proxies.count == proxyIds.count && proxies.count >= 2
        let entry = proxies.count >= 2 ? proxies.first?.serverAddress : nil
        let exit = proxies.count >= 2 ? proxies.last?.serverAddress : nil
        return (proxies.map(\.name), isValid, entry, exit)
    }
}
