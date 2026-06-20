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
                voyagerNotice
            }

            Section("App") {
                row(.iCloudSync)
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

    @ViewBuilder
    private var voyagerNotice: some View {
        Section {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "sparkles.2")
                        .foregroundStyle(Color(hex: 0x5060F0))
                    Text("Voyager Only")
                        .font(.headline)
                }
                Text("Control Center is available to Anywhere Voyager members.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                JoinVoyagerButton {
                    voyagerStore.isPresentingVoyager = true
                }
            }
            .padding(.vertical, 4)
        }
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
