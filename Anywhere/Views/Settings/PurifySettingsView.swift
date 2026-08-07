//
//  PurifySettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/18/26.
//

import SwiftUI

struct PurifySettingsView: View {
    @Environment(AppSettings.self) private var appSettings
    @Environment(RoutingRuleSetStore.self) private var routingRuleSetStore
    
    private var adBlockEnabled: Binding<Bool> {
        Binding(
            get: { routingRuleSetStore.adBlockRuleSet?.assignedConfigurationId == "REJECT" },
            set: { enabled in
                guard let adBlockRuleSet = routingRuleSetStore.adBlockRuleSet else { return }
                routingRuleSetStore.updateAssignment(adBlockRuleSet, configurationId: enabled ? "REJECT" : nil)
            }
        )
    }
    
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
            
            Toggle("Block Advertisements", isOn: adBlockEnabled)
            
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
