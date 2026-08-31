//
//  AboutView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/21/26.
//

import SwiftUI

struct AboutView: View {
    @Environment(AppSettings.self) private var settings

    var body: some View {
        NavigationStack {
            List {
                if settings.showVoyagerCard {
                    Section {
                        VoyagerMemberCard()
                            .listRowInsets(EdgeInsets())
                            .listRowBackground(VoyagerCardBackground())
                    }
                }
                
                Section {
                    Link(destination: URL(string: "https://t.me/anywhere_official_group")!) {
                        HStack {
                            TextWithColorfulIconAndCustomImage(title: "Join Telegram Group", imageName: "TelegramSymbol", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                            Spacer()
                            Image(systemName: "arrow.up.right")
                                .font(.footnote.bold())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                
                Section {
                    NavigationLink {
                        AcknowledgementsView()
                    } label: {
                        TextWithColorfulIcon(title: "Acknowledgements", systemName: "doc.text.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                    }
                } footer: {
                    NavigationLink {
                        AdvancedSettingsView()
                    } label: {
                        HStack {
                            Text("Advanced Settings")
                                .font(.body)
                            Image(systemName: "chevron.right")
                                .font(.footnote.bold())
                        }
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 10)
                    }
                    .buttonStyle(.plain)
                }
            }
            .navigationTitle("About")
        }
    }
}
