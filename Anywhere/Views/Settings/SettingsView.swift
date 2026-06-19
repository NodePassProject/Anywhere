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
    
    @State private var showVoyager = false
    @State private var showICloudRestartAlert = false
    @State private var showInsecureAlert = false

    var body: some View {
        @Bindable var settings = settings
        @Bindable var ruleSetStore = ruleSetStore
        Form {
            if settings.experimentalEnabled {
                Section {
                    voyagerRow
                }
            }
            
            Section("App") {
                Toggle(isOn: $settings.iCloudSyncEnabled) {
                    TextWithColorfulIcon(title: "iCloud Sync", comment: nil, systemName: "icloud.fill", foregroundColor: .blue, backgroundColor: .white)
                }
            }
            
            Section("VPN") {
                Toggle(isOn: $settings.alwaysOnEnabled) {
                    TextWithColorfulIcon(title: "Always On", comment: nil, systemName: "poweron", foregroundColor: .white, backgroundColor: .green)
                }
                .disabled(viewModel.pendingReconnect)
            }

            Section("Routing") {
                Toggle(isOn: $settings.isGlobalMode) {
                    TextWithColorfulIcon(title: "Global Mode", comment: nil, systemName: "arrow.merge", foregroundColor: .white, backgroundColor: .orange)
                }
                if !settings.isGlobalMode {
                    Toggle(isOn: $adBlockEnabled) {
                        TextWithColorfulIcon(title: "AD Blocking", comment: nil, systemName: "shield.checkered", foregroundColor: .white, backgroundColor: .red)
                    }
                    Picker(selection: $ruleSetStore.bypassCountryCode) {
                        Text("Disable").tag("")
                        ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                            Text("\(flag(for: code)) \(Locale.current.localizedString(forRegionCode: code) ?? code)").tag(code)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Country Bypass", comment: nil, systemName: "globe.americas.fill", foregroundColor: .white, backgroundColor: .blue)
                    }
                    NavigationLink {
                        RuleSetListView()
                    } label: {
                        TextWithColorfulIcon(title: "Routing Rules", comment: nil, systemName: "arrow.triangle.branch", foregroundColor: .white, backgroundColor: .purple)
                    }
                }
            }

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
                    TextWithColorfulIcon(title: "Allow Insecure", comment: nil, systemName: "exclamationmark.shield.fill", foregroundColor: .white, backgroundColor: .red)
                }
                .tint(.red)
                NavigationLink {
                    TrustedCertificatesView()
                } label: {
                    TextWithColorfulIcon(title: "Trusted Certificates", comment: nil, systemName: "checkmark.seal.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }
            
            Section("Utilities") {
                NavigationLink {
                    PurifySettingsView()
                } label: {
                    TextWithColorfulIcon(title: "Purify", comment: nil, systemName: "drop.fill", foregroundColor: .white, backgroundColor: .blue)
                }
                NavigationLink {
                    ReflectionSettingsView()
                } label: {
                    TextWithColorfulIcon(title: "Reflection", comment: nil, systemName: "arrow.turn.up.left", foregroundColor: .white, backgroundColor: .pink)
                }
                if settings.experimentalEnabled {
                    NavigationLink {
                        MITMSettingsView()
                    } label: {
                        TextWithColorfulIcon(title: "MITM", comment: nil, systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .indigo)
                    }
                }
            }

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
        .fullScreenCover(isPresented: $showVoyager) {
            AnywhereVoyagerView()
                .environment(voyagerStore)
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
                    Button {
                        showVoyager = true
                    } label: {
                        Text("Join")
                            .textCase(.uppercase)
                            .font(.system(size: 14).weight(.semibold))
                            .foregroundStyle(.white)
                            .padding(.vertical, 8)
                            .padding(.horizontal, 15)
                            .background(Color(hex: 0x5060F0).gradient, in: Capsule())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private func flag(for countryCode: String) -> String {
        String(countryCode.unicodeScalars.compactMap {
            UnicodeScalar(127397 + $0.value)
        }.map(Character.init))
    }
}
