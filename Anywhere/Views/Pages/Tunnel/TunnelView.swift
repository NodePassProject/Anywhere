//
//  TunnelView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct TunnelView: View {
    @Environment(AppSettings.self) private var appSettings
    @Environment(TunnelController.self) private var tunnelController
    
    var body: some View {
        @Bindable var appSettings = appSettings
        NavigationStack {
            List {
                Section {
                    Toggle(isOn: $appSettings.alwaysOnEnabled) {
                        TextWithColorfulIcon(title: "Always On", systemName: "poweron", foregroundStyle: .white, backgroundStyle: .green.gradient)
                    }
                    .disabled(tunnelController.pendingReconnect)
                }
                
                Section {
                    NavigationLink {
                        TunnelScopeView()
                    } label: {
                        TextWithColorfulIcon(title: "Tunnel Scope", systemName: "scope", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                    }
                }
            }
            .navigationTitle("Tunnel")
        }
    }
}
