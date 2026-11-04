//
//  DisconnectIntent.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation
import NetworkExtension

struct DisconnectIntent: AppIntent {
    static let title: LocalizedStringResource = "Disconnect"
    static let description = IntentDescription("Disconnects the VPN.")

    @Dependency var container: AppContainer
    @Dependency var operations: Operations

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        try await container.awaitTunnelReady()

        let tunnel = container.tunnel
        if tunnel.rawStatus == .disconnected || tunnel.rawStatus == .invalid {
            return .result(dialog: "Anywhere is not connected.")
        }

        operations.tunnel.disconnect()
        try await tunnel.awaitDisconnected(timeout: .seconds(10))
        return .result(dialog: "Disconnected.")
    }
}
