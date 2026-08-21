//
//  DataView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct DataView: View {
    @Environment(AppSettings.self) private var appSettings
    
    @State private var showICloudRestartAlert = false
    
    var body: some View {
        @Bindable var appSettings = appSettings
        List {
            Toggle(isOn: $appSettings.iCloudSyncEnabled) {
                TextWithColorfulIcon(title: "iCloud Sync", systemName: "icloud.fill", foregroundStyle: .blue, backgroundStyle: .white.gradient)
            }
        }
        .navigationTitle("Data")
        .alert("Restart Required", isPresented: $showICloudRestartAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Restart Anywhere for the change to take effect.")
        }
        .onChange(of: appSettings.iCloudSyncEnabled) { _, newValue in
            showICloudRestartAlert = newValue != SyncStore.shared.usesCloudKit
        }
    }
}
