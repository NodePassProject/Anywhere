//
//  PurifySettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/18/26.
//

import SwiftUI

struct PurifySettingsView: View {
    @Environment(AppSettings.self) private var settings
    
    var body: some View {
        @Bindable var settings = settings
        Form {
            Section {
                Toggle("Block UDP", isOn: $settings.blockUDP)
            }
            
            Section {
                Picker("Block QUIC", selection: $settings.quicPolicy) {
                    ForEach(QUICPolicy.allCases, id: \.self) { policy in
                        Text(policy.title).tag(policy)
                    }
                }
                .disabled(settings.blockUDP)
            } footer: {
                Text("QUIC connections through proxies may cause instability and increased wait time.")
            }
            
            Section {
                Toggle("Block WebRTC", isOn: $settings.blockWebRTC)
                    .disabled(settings.blockUDP)
            } footer: {
                Text("Stop your device from being a CDN node without permission.")
            }
        }
        .navigationTitle("Purify")
    }
}
