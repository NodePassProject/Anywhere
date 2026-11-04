//
//  ProxyEntity.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation

// MARK: - Kind

nonisolated enum ProxyKind: String, AppEnum {
    case server
    case chain

    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "Proxy Kind")

    static let caseDisplayRepresentations: [ProxyKind: DisplayRepresentation] = [
        .server: DisplayRepresentation(title: "Server", image: .init(systemName: "server.rack")),
        .chain: DisplayRepresentation(title: "Chain", image: .init(systemName: "link")),
    ]

    var symbolName: String {
        switch self {
        case .server: "server.rack"
        case .chain: "link"
        }
    }
}

// MARK: - Entity

struct ProxyEntity: AppEntity {
    static let typeDisplayRepresentation = TypeDisplayRepresentation(
        name: "Proxy",
        numericFormat: "\(placeholder: .int) proxies"
    )

    static let defaultQuery = ProxyEntityQuery()

    let id: UUID

    @Property(title: "Name")
    var name: String

    @Property(title: "Kind")
    var kind: ProxyKind

    @Property(title: "Subscription")
    var subscriptionName: String?

    @Property(title: "Selected")
    var isSelected: Bool

    let detail: String?

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(
            title: "\(name)",
            subtitle: detail.map { "\($0)" },
            image: .init(systemName: kind.symbolName)
        )
    }

    init(server configuration: ProxyConfiguration, subscriptionName: String?, isSelected: Bool) {
        id = configuration.id
        detail = subscriptionName
        name = configuration.name
        kind = .server
        self.subscriptionName = subscriptionName
        self.isSelected = isSelected
    }

    init(chain: ProxyChain, configurations: [ProxyConfiguration], isSelected: Bool) {
        let hops = chain.resolveProxies(from: configurations)
        id = chain.id
        detail = hops.map(\.name).joined(separator: " → ")
        name = chain.name
        kind = .chain
        subscriptionName = nil
        self.isSelected = isSelected
    }
}

// MARK: - Query

struct ProxyEntityQuery: EntityQuery, EntityStringQuery, EnumerableEntityQuery {
    @Dependency var container: AppContainer

    @MainActor
    func entities(for identifiers: [UUID]) async throws -> [ProxyEntity] {
        let catalog = try await ProxyCatalog.load(from: container)
        return identifiers.compactMap { catalog.entity(for: $0) }
    }

    @MainActor
    func entities(matching string: String) async throws -> [ProxyEntity] {
        try await ProxyCatalog.load(from: container).entities.filter {
            $0.name.localizedCaseInsensitiveContains(string)
        }
    }

    @MainActor
    func suggestedEntities() async throws -> [ProxyEntity] {
        try await ProxyCatalog.load(from: container).entities
    }

    @MainActor
    func allEntities() async throws -> [ProxyEntity] {
        try await ProxyCatalog.load(from: container).entities
    }
}

// MARK: - Catalog

@MainActor
struct ProxyCatalog {
    let entities: [ProxyEntity]

    static func load(from container: AppContainer) async throws -> ProxyCatalog {
        try await container.awaitStoresLoaded()
        return ProxyCatalog(container: container)
    }

    init(container: AppContainer) {
        let configurations = container.configurationStore.configurations
        let chains = container.chainStore.chains
        let subscriptionNames = Dictionary(
            container.subscriptionStore.subscriptions.map { ($0.id, $0.name) },
            uniquingKeysWith: { first, _ in first }
        )
        let selectedId = container.selection.selectedChainId ?? container.selection.selectedConfiguration?.id

        var entities: [ProxyEntity] = []
        entities.reserveCapacity(configurations.count + chains.count)
        for configuration in configurations {
            entities.append(
                ProxyEntity(
                    server: configuration,
                    subscriptionName: configuration.subscriptionId.flatMap { subscriptionNames[$0] },
                    isSelected: configuration.id == selectedId
                )
            )
        }
        for chain in chains {
            entities.append(
                ProxyEntity(
                    chain: chain,
                    configurations: configurations,
                    isSelected: chain.id == selectedId
                )
            )
        }
        self.entities = entities
    }

    func entity(for id: UUID) -> ProxyEntity? {
        entities.first { $0.id == id }
    }
}

// MARK: - Selection

@MainActor
enum ProxySelector {
    @discardableResult
    static func select(_ entity: ProxyEntity, container: AppContainer, operations: Operations) throws -> ProxyConfiguration {
        let configurations = container.configurationStore.configurations
        switch entity.kind {
        case .server:
            guard let configuration = configurations.first(where: { $0.id == entity.id }) else {
                throw AnywhereIntentError.proxyNotFound
            }
            operations.selection.select(configuration)
            return configuration
        case .chain:
            guard let chain = container.chainStore.chains.first(where: { $0.id == entity.id }) else {
                throw AnywhereIntentError.proxyNotFound
            }
            guard let composite = chain.resolveComposite(from: configurations) else {
                throw AnywhereIntentError.chainUnavailable(chain.name)
            }
            operations.selection.selectChain(chain, configurations: configurations)
            return composite
        }
    }
}
