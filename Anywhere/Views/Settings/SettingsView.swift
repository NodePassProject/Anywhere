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

    @AppStorage("proxyMode", store: AWCore.userDefaults)
    private var proxyMode = ProxyMode.rule
    
    @AppStorage("bypassCountryCode", store: AWCore.userDefaults)
    private var bypassCountryCode = ""

    @AppStorage("allowInsecure", store: AWCore.userDefaults)
    private var allowInsecure = false

    @State private var adBlockEnabled = RuleSetStore.shared.adBlockRuleSet?.assignedConfigurationId == "REJECT"
    @State private var showInsecureAlert = false

    // Countries with serious internet censorship (must match INCLUDED_COUNTRIES in build_geoip.py)
    private static let countryCodes: [String] = [
        "AE", "BY", "CN", "CU", "IR", "MM", "RU", "SA", "TM", "VN"
    ]
    
    var body: some View {
        Form {
            Section("VPN") {
                Toggle(isOn: $alwaysOnEnabled) {
                    TextWithColorfulIcon(titleKey: "Always On", systemName: "bolt.circle.fill", foregroundColor: .white, backgroundColor: .green)
                }
                .disabled(viewModel.pendingReconnect)
            }

            Section("Routing") {
                if experimentalEnabled {
                    Toggle(isOn: Binding(get: {
                        proxyMode == .rule
                    }, set: { newValue in
                        if newValue { proxyMode = .rule } else { proxyMode = .global }
                    })) {
                        TextWithColorfulIconAndCustomImage(titleKey: "ASR™ Smart Routing", imageName: "ASR", foregroundColor: .white, backgroundColor: .orange)
                    }
                } else {
                    Toggle(isOn: Binding(get: {
                        proxyMode == .global
                    }, set: { newValue in
                        if newValue { proxyMode = .global } else { proxyMode = .rule }
                    })) {
                        TextWithColorfulIcon(titleKey: "Global Mode", systemName: "arrow.trianglehead.merge", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
                if proxyMode != .global {
                    Toggle(isOn: $adBlockEnabled) {
                        TextWithColorfulIcon(titleKey: "AD Blocking", systemName: "shield.checkered", foregroundColor: .white, backgroundColor: .red)
                    }
                    Picker(selection: $bypassCountryCode) {
                        Text("Disable").tag("")
                        ForEach(Self.countryCodes, id: \.self) { code in
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
                            notifySettingsChanged()
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
        .onChange(of: alwaysOnEnabled) {
            viewModel.reconnectVPN()
        }
        .onChange(of: proxyMode) {
            notifySettingsChanged()
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
        .onChange(of: bypassCountryCode) {
            Task { await RuleSetStore.shared.syncBypassCountryRules() }
            notifySettingsChanged()
        }
        .alert("Allow Insecure", isPresented: $showInsecureAlert) {
            Button("Allow Anyway", role: .destructive) {
                allowInsecure = true
                notifySettingsChanged()
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
    
    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
