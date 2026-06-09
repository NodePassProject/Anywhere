//
//  SettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 2/21/26.
//

import SwiftUI

struct SettingsView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(RoutingRuleSetStore.self) private var ruleSetStore
    
    @State private var adBlockEnabled = RoutingRuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"

    @State private var showInsecureAlert = false

    var body: some View {
        @Bindable var settings = settings
        @Bindable var ruleSetStore = ruleSetStore
        Form {
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

            if settings.experimentalEnabled {
                Section("Utilities") {
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
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                settings.allowInsecure = true
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
        .onAppear {
            adBlockEnabled = RoutingRuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
        }
    }

    private func flag(for countryCode: String) -> String {
        String(countryCode.unicodeScalars.compactMap {
            UnicodeScalar(127397 + $0.value)
        }.map(Character.init))
    }
}
