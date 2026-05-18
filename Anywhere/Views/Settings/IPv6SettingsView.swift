//
//  IPv6SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/10/26.
//

import SwiftUI

struct IPv6SettingsView: View {
    @State private var advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()

    var body: some View {
        Form {
            Section {
                Toggle("Advertise IPv6 to Apps", isOn: $advertiseIPv6ToApps)
            }
        }
        .navigationTitle("IPv6")
        .onAppear {
            advertiseIPv6ToApps = AWCore.getAdvertiseIPv6ToApps()
        }
        .onChange(of: advertiseIPv6ToApps) { _, newValue in
            AWCore.setAdvertiseIPv6ToApps(newValue)
            AWCore.notifyTunnelSettingsChanged()
        }
    }
}
