//
//  TunnelSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import SwiftUI

struct TunnelSettingsView: View {
    @Environment(VPNViewModel.self) private var viewModel

    var body: some View {
        @Bindable var settings = AppSettings.shared
        Form {
            Section {
                Toggle("Include All Networks", isOn: $settings.includeAllNetworks)
            }

            Section {
                Toggle("Include Local Networks", isOn: $settings.includeLocalNetworks)
                Toggle("Include APNs", isOn: $settings.includeAPNs)
                Toggle("Include Cellular Services", isOn: $settings.includeCellularServices)
            }
            .disabled(!settings.includeAllNetworks)
        }
        .navigationTitle("Tunnel")
        .disabled(viewModel.pendingReconnect)
    }
}
