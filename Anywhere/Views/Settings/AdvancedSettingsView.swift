//
//  AdvancedSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/26/26.
//

import SwiftUI

struct AdvancedSettingsView: View {
    @AppStorage("experimentalEnabled", store: AWCore.userDefaults)
    private var experimentalEnabled = false
    
    var body: some View {
        List {
            Section("App") {
                Toggle("Experimental Features", isOn: $experimentalEnabled)
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
