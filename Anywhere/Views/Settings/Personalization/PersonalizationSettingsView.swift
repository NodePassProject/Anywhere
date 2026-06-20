//
//  PersonalizationSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct PersonalizationSettingsView: View {
    var body: some View {
        Form {
            Section {
                NavigationLink {
                    CustomizeAppIconView()
                } label: {
                    TextWithColorfulIcon(title: "App Icon", comment: nil, systemName: "app.fill", foregroundColor: .white, backgroundColor: .blue)
                }
                NavigationLink {
                    CustomizeThemeView()
                } label: {
                    TextWithColorfulIcon(title: "Theme", comment: nil, systemName: "paintbrush.fill", foregroundColor: .white, backgroundColor: .pink)
                }
            }
        }
        .navigationTitle("Personalization")
    }
}
