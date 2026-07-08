//
//  SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 2/21/26.
//

import SwiftUI
import WidgetKit

struct SettingsView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore

    @State private var adBlockEnabled = RoutingRuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
    
    @State private var showICloudRestartAlert = false
    @State private var showInsecureAlert = false

    var body: some View {
        Form {
            Section {
                VoyagerSettingsCard()
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(VoyagerCardBackground())
            }
            appSection
            vpnSection
            routingSection
            securitySection
            utilitiesSection
            diagnosisSection
            aboutSection
        }
        .navigationTitle("Settings")
        .onChange(of: adBlockEnabled) { _, newValue in
            if let adBlockRuleSet = RoutingRuleSetStore.shared.adBlockRuleSet {
                RoutingRuleSetStore.shared.updateAssignment(adBlockRuleSet, configurationId: newValue ? "REJECT" : nil)
            }
        }
        .onChange(of: settings.iCloudSyncEnabled) { _, newValue in
            showICloudRestartAlert = newValue != JSONBlobStore.shared.usesCloudKit
        }
        .onAppear {
            adBlockEnabled = RoutingRuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
        }
        .alert("Restart Required", isPresented: $showICloudRestartAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Restart Anywhere for the change to take effect.")
        }
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                settings.allowInsecure = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
    }
    
    @ViewBuilder
    private var appSection: some View {
        @Bindable var settings = settings
        Section("App") {
            Toggle(isOn: $settings.iCloudSyncEnabled) {
                SettingsItem.iCloudSync.label
            }
            NavigationLink {
                PersonalizationSettingsView()
            } label: {
                SettingsItem.personalization.label
            }
        }
    }

    @ViewBuilder
    private var vpnSection: some View {
        @Bindable var settings = settings
        Section("VPN") {
            Toggle(isOn: $settings.alwaysOnEnabled) {
                SettingsItem.alwaysOn.label
            }
            .disabled(viewModel.pendingReconnect)
        }
    }

    @ViewBuilder
    private var routingSection: some View {
        @Bindable var settings = settings
        Section("Routing") {
            Toggle(isOn: $settings.isGlobalMode) {
                SettingsItem.globalMode.label
            }
            .onChange(of: settings.isGlobalMode) {
                ControlCenter.shared.reloadControls(ofKind: "com.argsment.Anywhere.Widget.VPNToggle")
            }
            if !settings.isGlobalMode {
                Toggle(isOn: $adBlockEnabled) {
                    SettingsItem.adBlocking.label
                }
                countryBypassPicker
                NavigationLink {
                    RuleSetListView()
                } label: {
                    SettingsItem.routingRules.label
                }
            }
        }
    }

    @ViewBuilder
    private var countryBypassPicker: some View {
        @Bindable var ruleSetStore = ruleSetStore
        Picker(selection: $ruleSetStore.bypassCountryCode) {
            Text("Disable").tag("")
            ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                Text(countryLabel(for: code)).tag(code)
            }
        } label: {
            SettingsItem.countryBypass.label
        }
    }

    @ViewBuilder
    private var securitySection: some View {
        Section("Security") {
            Toggle(isOn: Binding(
                get: { settings.allowInsecure },
                set: { newValue in
                    if newValue {
                        showInsecureAlert = true
                    } else {
                        settings.allowInsecure = false
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
    }

    @ViewBuilder
    private var utilitiesSection: some View {
        Section("Utilities") {
            NavigationLink {
                PurifySettingsView()
            } label: {
                SettingsItem.purify.label
            }
            NavigationLink {
                ReflectionSettingsView()
            } label: {
                SettingsItem.reflection.label
            }
            if settings.experimentalEnabled {
                NavigationLink {
                    MITMSettingsView()
                } label: {
                    SettingsItem.mitm.label
                }
            }
        }
    }

    @ViewBuilder
    private var diagnosisSection: some View {
        Section("Diagnostics") {
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
    }

    @ViewBuilder
    private var aboutSection: some View {
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
        } header: {
            Text("About")
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
