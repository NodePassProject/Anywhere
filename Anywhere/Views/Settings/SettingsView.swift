//
//  SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 2/21/26.
//

import SwiftUI

struct SettingsView: View {
    @Environment(VoyagerStore.self) private var voyagerStore
    @Environment(AppSettings.self) private var settings
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore

    @State private var adBlockEnabled = RoutingRuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
    
    @State private var showICloudRestartAlert = false
    @State private var showInsecureAlert = false

    var body: some View {
        Form {
            Section {
                voyagerRow
            }
            appSection
            vpnSection
            routingSection
            securitySection
            utilitiesSection
            aboutSection
        }
        .navigationTitle("Settings")
        .toolbar {
            settingsToolbar
        }
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
    
    @ToolbarContentBuilder
    private var settingsToolbar: some ToolbarContent {
        ToolbarItem {
            NavigationLink {
                ControlCenterView()
            } label: {
                Label("Control Center", systemImage: "switch.2")
            }
        }
    }
    
    private var showAppSection: Bool {
        settings.isVisible(.iCloudSync) || settings.isVisible(.personalization)
    }

    private var showVPNSection: Bool {
        settings.isVisible(.alwaysOn)
    }

    private var showRoutingSection: Bool {
        if settings.isVisible(.globalMode) { return true }
        return !settings.isGlobalMode && (
            settings.isVisible(.adBlocking)
                || settings.isVisible(.countryBypass)
                || settings.isVisible(.routingRules)
        )
    }

    private var showSecuritySection: Bool {
        settings.isVisible(.allowInsecure)
        || settings.isVisible(.trustedCertificates)
        || settings.isVisible(.trustedNetwork)
    }

    private var showUtilitiesSection: Bool {
        settings.isVisible(.purify)
            || settings.isVisible(.reflection)
            || (settings.experimentalEnabled && settings.isVisible(.mitm))
    }
    
    @ViewBuilder
    private var appSection: some View {
        @Bindable var settings = settings
        if showAppSection {
            Section("App") {
                if settings.isVisible(.iCloudSync) {
                    Toggle(isOn: $settings.iCloudSyncEnabled) {
                        SettingsItem.iCloudSync.label
                    }
                }
                if settings.isVisible(.personalization) {
                    NavigationLink {
                        PersonalizationSettingsView()
                    } label: {
                        SettingsItem.personalization.label
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var vpnSection: some View {
        @Bindable var settings = settings
        if showVPNSection {
            Section("VPN") {
                if settings.isVisible(.alwaysOn) {
                    Toggle(isOn: $settings.alwaysOnEnabled) {
                        SettingsItem.alwaysOn.label
                    }
                    .disabled(viewModel.pendingReconnect)
                }
            }
        }
    }

    @ViewBuilder
    private var routingSection: some View {
        @Bindable var settings = settings
        if showRoutingSection {
            Section("Routing") {
                if settings.isVisible(.globalMode) {
                    Toggle(isOn: $settings.isGlobalMode) {
                        SettingsItem.globalMode.label
                    }
                }
                if !settings.isGlobalMode {
                    if settings.isVisible(.adBlocking) {
                        Toggle(isOn: $adBlockEnabled) {
                            SettingsItem.adBlocking.label
                        }
                    }
                    if settings.isVisible(.countryBypass) {
                        countryBypassPicker
                    }
                    if settings.isVisible(.routingRules) {
                        NavigationLink {
                            RuleSetListView()
                        } label: {
                            SettingsItem.routingRules.label
                        }
                    }
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
        if showSecuritySection {
            Section("Security") {
                if settings.isVisible(.allowInsecure) {
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
                }
                if settings.isVisible(.trustedCertificates) {
                    NavigationLink {
                        TrustedCertificatesView()
                    } label: {
                        SettingsItem.trustedCertificates.label
                    }
                }
                if settings.isVisible(.trustedNetwork) {
                    NavigationLink {
                        TrustedNetworkSettingsView()
                    } label: {
                        SettingsItem.trustedNetwork.label
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var utilitiesSection: some View {
        if showUtilitiesSection {
            Section("Utilities") {
                if settings.isVisible(.purify) {
                    NavigationLink {
                        PurifySettingsView()
                    } label: {
                        SettingsItem.purify.label
                    }
                }
                if settings.isVisible(.reflection) {
                    NavigationLink {
                        ReflectionSettingsView()
                    } label: {
                        SettingsItem.reflection.label
                    }
                }
                if settings.experimentalEnabled, settings.isVisible(.mitm) {
                    NavigationLink {
                        MITMSettingsView()
                    } label: {
                        SettingsItem.mitm.label
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var aboutSection: some View {
        Section {
            Link(destination: URL(string: "https://t.me/anywhere_official_group")!) {
                HStack {
                    TextWithColorfulIconAndCustomImage(title: "Join Telegram Group", comment: nil, imageName: "TelegramSymbol", foregroundColor: .white, backgroundColor: .blue)
                    Spacer()
                    Image(systemName: "arrow.up.right")
                        .font(.footnote.bold())
                        .foregroundStyle(.secondary)
                }
            }
            NavigationLink {
                AcknowledgementsView()
            } label: {
                TextWithColorfulIcon(title: "Acknowledgements", comment: nil, systemName: "doc.text.fill", foregroundColor: .white, backgroundColor: .gray)
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

    @ViewBuilder
    private var voyagerRow: some View {
        HStack {
            TextWithColorfulIcon(title: "Anywhere Voyager", comment: nil, systemName: "sparkles.2", foregroundColor: .white, backgroundColor: Color(hex: 0x5060F0))
            Spacer()
            HStack {
                if voyagerStore.isMember {
                    Text("Member \(Image(systemName: "checkmark.seal.fill"))")
                        .textCase(.uppercase)
                        .font(.body.weight(.semibold))
                        .foregroundStyle(Color(hex: 0x5060F0))
                } else {
                    JoinVoyagerButton {
                        voyagerStore.isPresentingVoyagerView = true
                    }
                }
            }
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
