//
//  SelectProxyIntent.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation
import NetworkExtension

struct SelectProxyIntent: AppIntent {
    static let title: LocalizedStringResource = "Select Proxy"
    static let description = IntentDescription(
        "Makes a proxy the active one. If the VPN is connected, traffic switches to it right away."
    )

    static var parameterSummary: some ParameterSummary {
        Summary("Select \(\.$proxy)")
    }

    @Parameter(title: "Proxy", requestValueDialog: "Which proxy?")
    var proxy: ProxyEntity

    @Dependency var container: AppContainer
    @Dependency var operations: Operations

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<ProxyEntity> & ProvidesDialog {
        try await container.awaitStoresLoaded()

        let configuration = try ProxySelector.select(proxy, container: container, operations: operations)
        let updated = ProxyCatalog(container: container).entity(for: configuration.id) ?? proxy
        let dialog: IntentDialog = container.tunnel.rawStatus == .connected
            ? "Switched to \(configuration.name)."
            : "Selected \(configuration.name)."
        return .result(value: updated, dialog: dialog)
    }
}
