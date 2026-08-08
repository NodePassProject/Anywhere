//
//  SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 2/21/26.
//

import SwiftUI
import WidgetKit

struct SettingsView: View {
    @Environment(AppSettings.self) private var appSettings
    @Environment(TunnelController.self) private var tunnelController
    @Environment(RoutingRuleSetStore.self) private var routingRuleSetStore

    @State private var showICloudRestartAlert = false

    var body: some View {
        @Bindable var appSettings = appSettings
        @Bindable var routingRuleSetStore = routingRuleSetStore
        Form {
            if appSettings.showVoyagerCard {
                Section {
                    VoyagerSettingsCard()
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(VoyagerCardBackground())
                }
            }
            
            Section {
                Toggle(isOn: $appSettings.iCloudSyncEnabled) {
                    SettingsItem.iCloudSync.label
                }
                NavigationLink {
                    PersonalizationSettingsView()
                } label: {
                    SettingsItem.personalization.label
                }
            }
            
            Section {
                Toggle(isOn: $appSettings.alwaysOnEnabled) {
                    SettingsItem.alwaysOn.label
                }
                .disabled(tunnelController.pendingReconnect)
            }
            
            Section {
                Toggle(isOn: $appSettings.isGlobalMode) {
                    SettingsItem.globalMode.label
                }
                .onChange(of: appSettings.isGlobalMode) {
                    ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
                }
                NavigationLink {
                    PurifySettingsView()
                } label: {
                    SettingsItem.purify.label
                }
                if !appSettings.isGlobalMode {
                    NavigationLink {
                        RuleSetListView()
                    } label: {
                        SettingsItem.routingRules.label
                    }
                }
            }
            
            Section {
                NavigationLink {
                    TrustedCertificatesView()
                } label: {
                    SettingsItem.trustedCertificates.label
                }
                NavigationLink {
                    TrustedNetworkSettingsView()
                } label: {
                    SettingsItem.trustedNetwork.label
                }
            }
            
            Section {
                NavigationLink {
                    MITMSettingsView()
                } label: {
                    SettingsItem.mitm.label
                }
            }
            
            Section {
                NavigationLink {
                    LogListView()
                } label: {
                    SettingsItem.logs.label
                }
                NavigationLink {
                    RequestsView()
                } label: {
                    SettingsItem.requests.label
                }
            }
            
            Section {
                Link(destination: URL(string: "https://t.me/anywhere_official_group")!) {
                    HStack {
                        TextWithColorfulIconAndCustomImage(title: "Join Telegram Group", comment: nil, imageName: "TelegramSymbol", foregroundStyle: .white, backgroundStyle: .blue.gradient)
                        Spacer()
                        Image(systemName: "arrow.up.right")
                            .font(.footnote.bold())
                            .foregroundStyle(.secondary)
                    }
                }
                NavigationLink {
                    AcknowledgementsView()
                } label: {
                    TextWithColorfulIcon(title: "Acknowledgements", comment: nil, systemName: "doc.text.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
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
        .navigationTitle("Settings")
        .onChange(of: appSettings.iCloudSyncEnabled) { _, newValue in
            showICloudRestartAlert = newValue != JSONBlobStore.shared.usesCloudKit
        }
        .alert("Restart Required", isPresented: $showICloudRestartAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Restart Anywhere for the change to take effect.")
        }
    }
}
