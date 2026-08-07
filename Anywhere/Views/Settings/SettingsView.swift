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
    @State private var showInsecureAlert = false

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
                if !appSettings.isGlobalMode {
                    Toggle(isOn: adBlockEnabled) {
                        SettingsItem.adBlocking.label
                    }
                    Picker(selection: $routingRuleSetStore.bypassCountryCode) {
                        Text("Disable").tag("")
                        ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                            Text(countryLabel(for: code)).tag(code)
                        }
                    } label: {
                        SettingsItem.countryBypass.label
                    }
                    NavigationLink {
                        RuleSetListView(ruleSetStore: routingRuleSetStore)
                    } label: {
                        SettingsItem.routingRules.label
                    }
                }
            }
            
            Section {
                Toggle(isOn: Binding(
                    get: { appSettings.allowInsecure },
                    set: { newValue in
                        if newValue {
                            showInsecureAlert = true
                        } else {
                            appSettings.allowInsecure = false
                        }
                    }
                )) {
                    SettingsItem.allowInsecure.label
                }
                .tint(.red)
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
                    PurifySettingsView()
                } label: {
                    SettingsItem.purify.label
                }
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
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                appSettings.allowInsecure = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
    }

    private func flag(for countryCode: String) -> String {
        String(countryCode.unicodeScalars.compactMap {
            UnicodeScalar(127397 + $0.value)
        }.map(Character.init))
    }

    private func countryLabel(for code: String) -> String {
        let name = Locale.current.localizedString(forRegionCode: code) ?? code
        return "\(flag(for: code)) \(name)"
    }
}
