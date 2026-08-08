//
//  PurifySettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/18/26.
//

import SwiftUI

struct PurifySettingsView: View {
    @Environment(AppSettings.self) private var appSettings
    
    var body: some View {
        @Bindable var appSettings = appSettings
        Form {
            Section {
                Toggle("Block UDP", isOn: $appSettings.blockUDP)
            }
            
            Section {
                Picker("Block QUIC", selection: $appSettings.quicPolicy) {
                    ForEach(QUICPolicy.allCases, id: \.self) { policy in
                        Text(policy.title).tag(policy)
                    }
                }
                .disabled(appSettings.blockUDP)
            } footer: {
                Text("QUIC connections through proxies may cause instability and increased wait time.")
            }
            Section {
                Toggle("Block WebRTC", isOn: $appSettings.blockWebRTC)
                    .disabled(appSettings.blockUDP)
            } footer: {
                Text("Stop your device from being a CDN node without permission.")
            }

            Section {
                Toggle("Prevent DNS Leak", isOn: $appSettings.preventDNSLeak)
            } footer: {
                Text("Provide extra DNS security.")
            }
        }
        .navigationTitle("Purify")
    }
}
