//
//  ConnectIntent.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation
import NetworkExtension

struct ConnectIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect"
    static let description = IntentDescription(
        "Connects the VPN. Pick a proxy to switch to it first; otherwise the current selection is used."
    )

    static var parameterSummary: some ParameterSummary {
        When(\.$proxy, .hasAnyValue) {
            Summary("Connect to \(\.$proxy)")
        } otherwise: {
            Summary("Connect")
        }
    }

    @Parameter(title: "Proxy")
    var proxy: ProxyEntity?

    @Dependency var container: AppContainer
    @Dependency var operations: Operations

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        try await container.awaitStoresLoaded()
        try await container.awaitTunnelReady()

        let configuration: ProxyConfiguration
        if let proxy {
            configuration = try ProxySelector.select(proxy, container: container, operations: operations)
        } else if let selected = container.selection.selectedConfiguration {
            configuration = selected
        } else {
            throw AnywhereIntentError.noProxySelected
        }

        let tunnel = container.tunnel
        await tunnel.awaitSettled(timeout: .seconds(15))
        if tunnel.rawStatus == .connected {
            return .result(dialog: "Connected to \(configuration.name).")
        }

        tunnel.startError = nil
        operations.tunnel.connect()
        try await tunnel.awaitConnected(timeout: .seconds(20))
        return .result(dialog: "Connected to \(configuration.name).")
    }
}
