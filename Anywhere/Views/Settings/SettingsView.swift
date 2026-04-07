//
//  SettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 2/21/26.
//

import SwiftUI

/// Settings that affect the Network Extension are stored in App Group UserDefaults
/// and propagated via Darwin notifications:
///
/// - "settingsChanged": triggers LWIPStack restart. Posted when ipv6, encrypted DNS, or bypass changes.
///   LWIPStack re-reads all settings from UserDefaults during restart.
///   IPv6 and encrypted DNS changes also trigger tunnel settings re-apply.
///
/// - "routingChanged": triggers DomainRouter rule reload only (no restart).
///   Posted by RuleSetListView when routing rule assignments change.
///
/// - "alwaysOnEnabled": triggers VPN reconnect (if connected) so on-demand rules update immediately.
struct SettingsView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared
    
    @AppStorage("experimentalEnabled", store: AWCore.userDefaults)
    private var experimentalEnabled = false

    @AppStorage("alwaysOnEnabled", store: AWCore.userDefaults)
    private var alwaysOnEnabled = false

    @State private var proxyMode = AWCore.getProxyMode()
    
    @AppStorage("bypassCountryCode", store: AWCore.userDefaults)
    private var bypassCountryCode = ""

    @AppStorage("allowInsecure", store: AWCore.userDefaults)
    private var allowInsecure = false

    @State private var adBlockEnabled = RuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
    @State private var showInsecureAlert = false
    
    var body: some View {
        Form {
            Section("VPN") {
                Toggle(isOn: $alwaysOnEnabled) {
                    TextWithColorfulIcon(titleKey: "Always On", systemName: "bolt.circle.fill", foregroundColor: .white, backgroundColor: .green)
                }
                .disabled(viewModel.pendingReconnect)
            }

            Section("Routing") {
                Toggle(isOn: Binding(get: {
                    proxyMode == .global
                }, set: { newValue in
                    if newValue { proxyMode = .global } else { proxyMode = .rule }
                })) {
                    TextWithColorfulIcon(titleKey: "Global Mode", systemName: "arrow.merge", foregroundColor: .white, backgroundColor: .orange)
                }
                if proxyMode != .global {
                    Toggle(isOn: $adBlockEnabled) {
                        TextWithColorfulIcon(titleKey: "AD Blocking", systemName: "shield.checkered", foregroundColor: .white, backgroundColor: .red)
                    }
                    Picker(selection: $bypassCountryCode) {
                        Text("Disable").tag("")
                        ForEach(CountryBypassCatalog.shared.supportedCountryCodes, id: \.self) { code in
                            Text("\(flag(for: code)) \(Locale.current.localizedString(forRegionCode: code) ?? code)").tag(code)
                        }
                    } label: {
                        TextWithColorfulIcon(titleKey: "Country Bypass", systemName: "globe.americas.fill", foregroundColor: .white, backgroundColor: .blue)
                    }
                    NavigationLink {
                        RuleSetListView()
                    } label: {
                        TextWithColorfulIcon(titleKey: "Routing Rules", systemName: "arrow.triangle.branch", foregroundColor: .white, backgroundColor: .purple)
                    }
                }
            }
            
            Section("Security") {
                Toggle(isOn: Binding(
                    get: { allowInsecure },
                    set: { newValue in
                        if newValue {
                            showInsecureAlert = true
                        } else {
                            allowInsecure = false
                            AWCore.notifySettingsChanged()
                        }
                    }
                )) {
                    TextWithColorfulIcon(titleKey: "Allow Insecure", systemName: "exclamationmark.shield.fill", foregroundColor: .white, backgroundColor: .red)
                }
                .tint(.red)
                NavigationLink {
                    TrustedCertificatesView()
                } label: {
                    TextWithColorfulIcon(titleKey: "Trusted Certificates", systemName: "checkmark.seal.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }

            Section {
                Link(destination: URL(string: "https://t.me/anywhere_official_group")!) {
                    HStack {
                        TextWithColorfulIconAndCustomImage(titleKey: "Join Telegram Group", imageName: "TelegramSymbol", foregroundColor: .white, backgroundColor: .blue)
                        Spacer()
                        Image(systemName: "arrow.up.right")
                            .font(.footnote.bold())
                            .foregroundStyle(.secondary)
                    }
                }
                NavigationLink {
                    AcknowledgementsView()
                } label: {
                    TextWithColorfulIcon(titleKey: "Acknowledgements", systemName: "doc.text.fill", foregroundColor: .white, backgroundColor: .gray)
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
        .onAppear {
            proxyMode = AWCore.getProxyMode()
        }
        .onChange(of: alwaysOnEnabled) {
            viewModel.reconnectVPN()
        }
        .onChange(of: proxyMode) {
            AWCore.setProxyMode(proxyMode)
            AWCore.notifySettingsChanged()
        }
        .onChange(of: adBlockEnabled) { _, newValue in
            if let adBlockRuleSet = RuleSetStore.shared.adBlockRuleSet {
                if newValue {
                    RuleSetStore.shared.updateAssignment(adBlockRuleSet, configurationId: "REJECT")
                } else {
                    RuleSetStore.shared.updateAssignment(adBlockRuleSet, configurationId: nil)
                }
            }
            Task { await viewModel.syncRoutingConfigurationToNE() }
        }
        .onChange(of: bypassCountryCode) { _, _ in
            Task {
                await viewModel.syncRoutingConfigurationToNE()
                AWCore.notifySettingsChanged()
            }
        }
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                allowInsecure = true
                AWCore.notifySettingsChanged()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
        .onAppear {
            adBlockEnabled = RuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
        }
    }
    
    private func flag(for countryCode: String) -> String {
        String(countryCode.unicodeScalars.compactMap {
            UnicodeScalar(127397 + $0.value)
        }.map(Character.init))
    }
}
