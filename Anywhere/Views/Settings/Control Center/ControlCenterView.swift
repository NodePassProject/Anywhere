//
//  ControlCenterView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct ControlCenterView: View {
    @Environment(VoyagerStore.self) private var voyagerStore
    @Environment(AppSettings.self) private var settings

    var body: some View {
        Form {
            if !voyagerStore.isMember {
                VoyagerNotice("Control Center is available to Anywhere Voyager members.")
            }

            Section("App") {
                row(.iCloudSync)
                row(.personalization)
            }

            Section("VPN") {
                row(.alwaysOn)
            }

            Section("Routing") {
                row(.globalMode)
                row(.adBlocking)
                row(.countryBypass)
                row(.routingRules)
            }

            Section("Security") {
                row(.allowInsecure)
                row(.trustedCertificates)
                row(.trustedNetwork)
            }

            Section("Utilities") {
                row(.purify)
                row(.reflection)
                if settings.experimentalEnabled {
                    row(.mitm)
                }
            }
        }
        .navigationTitle("Control Center")
    }

    private func row(_ item: SettingsItem) -> some View {
        Toggle(isOn: Binding(
            get: { settings.isVisible(item) },
            set: { settings.setVisible(item, $0) }
        )) {
            item.label
        }
        .disabled(!voyagerStore.isMember)
    }
}
