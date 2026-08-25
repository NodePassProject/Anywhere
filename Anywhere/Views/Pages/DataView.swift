//
//  DataView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct DataView: View {
    @Environment(AppSettings.self) private var appSettings

    var body: some View {
        @Bindable var appSettings = appSettings
        List {
            Toggle(isOn: $appSettings.iCloudSyncEnabled) {
                TextWithColorfulIcon(title: "iCloud Sync", systemName: "icloud.fill", foregroundStyle: .blue, backgroundStyle: .white.gradient)
            }
        }
        .navigationTitle("Data")
    }
}
