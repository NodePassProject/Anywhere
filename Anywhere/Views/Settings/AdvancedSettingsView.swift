//
//  AdvancedSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/26/26.
//

import SwiftUI

struct AdvancedSettingsView: View {
    @State private var experimentalEnabled = AWCore.getExperimentalEnabled()

    var body: some View {
        List {
            Section("App") {
                Toggle("Experimental Features", isOn: $experimentalEnabled)
                    .onChange(of: experimentalEnabled) { _, newValue in
                        AWCore.setExperimentalEnabled(newValue)
                    }
            }
            
            Section("Network") {
                NavigationLink("IPv6") {
                    IPv6SettingsView()
                }
                NavigationLink("Encrypted DNS") {
                    EncryptedDNSSettingsView()
                }
            }

            Section("Diagnostics") {
                NavigationLink("Logs") {
                    LogListView()
                }
            }
        }
        .navigationTitle("Advanced Settings")
    }
}
