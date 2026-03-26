//
//  AdvancedSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/26/26.
//

import SwiftUI

struct AdvancedSettingsView: View {
    var body: some View {
        List {
            NavigationLink("IPv6") {
                IPv6SettingsView()
            }
            NavigationLink("Encrypted DNS") {
                EncryptedDNSSettingsView()
            }
        }
        .navigationTitle("Advanced Settings")
    }
}
