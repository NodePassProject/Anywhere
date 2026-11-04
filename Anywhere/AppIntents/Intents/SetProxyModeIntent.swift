//
//  SetProxyModeIntent.swift
//  Anywhere
//
//  Created by NodePassProject on 11/3/26.
//

import AppIntents
import Foundation

struct SetProxyModeIntent: AppIntent {
    static let title: LocalizedStringResource = "Set Mode"
    static let description = IntentDescription(
        "Switches between Proxy Mode and Global Mode."
    )

    static var parameterSummary: some ParameterSummary {
        Summary("Set mode to \(\.$mode)")
    }

    @Parameter(title: "Mode", requestValueDialog: "Which mode?")
    var mode: ProxyModeOption

    @Dependency var settings: AppSettings

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        settings.proxyMode = mode.proxyMode
        switch mode {
        case .rule:
            return .result(dialog: "Switched to Proxy Mode.")
        case .global:
            return .result(dialog: "Switched to Global Mode.")
        }
    }
}
