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
            Picker("Block QUIC", selection: $settings.quicPolicy) {
                ForEach(QUICPolicy.allCases, id: \.self) { policy in
                    Text(policy.title).tag(policy)
                }
            }
            Toggle("Block WebRTC", isOn: $settings.blockWebRTC)
        }
        .navigationTitle("Purify")
    }
}
