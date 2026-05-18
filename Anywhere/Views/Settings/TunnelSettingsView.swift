//
//  TunnelSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import SwiftUI

struct TunnelSettingsView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared

    @State private var includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
    @State private var includeLocalNetworks = AWCore.getTunnelIncludeLocalNetworks()
    @State private var includeAPNs = AWCore.getTunnelIncludeAPNs()
    @State private var includeCellularServices = AWCore.getTunnelIncludeCellularServices()

    var body: some View {
        Form {
            Section {
                Toggle("Include All Networks", isOn: $includeAllNetworks)
            }

            Section {
                Toggle("Include Local Networks", isOn: $includeLocalNetworks)
                Toggle("Include APNs", isOn: $includeAPNs)
                Toggle("Include Cellular Services", isOn: $includeCellularServices)
            }
            .disabled(!includeAllNetworks)
        }
        .navigationTitle("Tunnel")
        .disabled(viewModel.pendingReconnect)
        .onAppear {
            includeAllNetworks = AWCore.getTunnelIncludeAllNetworks()
            includeLocalNetworks = AWCore.getTunnelIncludeLocalNetworks()
            includeAPNs = AWCore.getTunnelIncludeAPNs()
            includeCellularServices = AWCore.getTunnelIncludeCellularServices()
        }
        .onChange(of: includeAllNetworks) { _, newValue in
            AWCore.setTunnelIncludeAllNetworks(newValue)
            viewModel.reconnectVPN()
        }
        .onChange(of: includeLocalNetworks) { _, newValue in
            AWCore.setTunnelIncludeLocalNetworks(newValue)
            viewModel.reconnectVPN()
        }
        .onChange(of: includeAPNs) { _, newValue in
            AWCore.setTunnelIncludeAPNs(newValue)
            viewModel.reconnectVPN()
        }
        .onChange(of: includeCellularServices) { _, newValue in
            AWCore.setTunnelIncludeCellularServices(newValue)
            viewModel.reconnectVPN()
        }
    }
}
