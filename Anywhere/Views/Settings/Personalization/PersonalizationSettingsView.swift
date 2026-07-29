//
//  PersonalizationSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/20/26.
//

import SwiftUI

struct PersonalizationSettingsView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(VoyagerStore.self) private var voyagerStore

    var body: some View {
        @Bindable var settings = settings
        Form {
            if voyagerStore.isMember {
                Section {
                    Toggle(isOn: $settings.showVoyagerCard) {
                        TextWithColorfulIcon(title: "Voyager Member Card", comment: nil, systemName: "creditcard.rewards.fill", foregroundStyle: .white, backgroundStyle: .indigo.gradient)
                    }
                }
            }
            
            Section {
                NavigationLink {
                    CustomizeAppIconView()
                } label: {
                    TextWithColorfulIcon(title: "App Icon", comment: nil, systemName: "app.fill", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                }
                NavigationLink {
                    CustomizeThemeView()
                } label: {
                    TextWithColorfulIcon(title: "Theme", comment: nil, systemName: "paintbrush.fill", foregroundStyle: .white, backgroundStyle: .pink.gradient)
                }
            }
        }
        .navigationTitle("Personalization")
    }
}
