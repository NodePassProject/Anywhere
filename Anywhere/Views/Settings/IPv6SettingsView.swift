//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    @State private var ipv6DNSEnabled = AWCore.getIPv6DNSEnabled()

    var body: some View {
        Form {
            Section {
                Toggle("Advertise IPv6 to Apps", isOn: $ipv6DNSEnabled)
            }
        }
        .navigationTitle("IPv6")
        .onAppear {
            ipv6DNSEnabled = AWCore.getIPv6DNSEnabled()
        }
        .onChange(of: ipv6DNSEnabled) { _, newValue in
            AWCore.setIPv6DNSEnabled(newValue)
            AWCore.notifyTunnelSettingsChanged()
        }
    }
}
