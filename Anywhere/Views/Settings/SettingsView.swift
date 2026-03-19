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

    @AppStorage("alwaysOnEnabled", store: AWCore.userDefaults)
    private var alwaysOnEnabled = false

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
                if viewModel.pendingReconnect {
                    HStack {
                        TextWithColorfulIcon(titleKey: "Always On", systemName: "bolt.shield.fill", foregroundColor: .white, backgroundColor: .green)
                        Spacer()
                        ProgressView()
                    }
                } else {
                    Toggle(isOn: $alwaysOnEnabled) {
                        TextWithColorfulIcon(titleKey: "Always On", systemName: "bolt.shield.fill", foregroundColor: .white, backgroundColor: .green)
                    }
                }
            }
            
            Section("Network") {
                NavigationLink {
                    IPv6SettingsView()
                } label: {
                    TextWithColorfulIcon(titleKey: "IPv6", systemName: "6.circle.fill", foregroundColor: .white, backgroundColor: .blue)
                }
                NavigationLink {
                    EncryptedDNSSettingsView()
                } label: {
                    TextWithColorfulIcon(titleKey: "Encrypted DNS", systemName: "lock.shield.fill", foregroundColor: .white, backgroundColor: .teal)
                }
            }

            Section("Routing") {
                Picker(selection: $bypassCountryCode) {
                    Text("Disable").tag("")
                    ForEach(Self.countryCodes, id: \.self) { code in
                        Text("\(flag(for: code)) \(Locale.current.localizedString(forRegionCode: code) ?? code)").tag(code)
                    }
                } label: {
                    TextWithColorfulIcon(titleKey: "Country Bypass", systemName: "globe.americas.fill", foregroundColor: .white, backgroundColor: .orange)
                }
                Toggle(isOn: $adBlockEnabled) {
                    TextWithColorfulIcon(titleKey: "AD Blocking", systemName: "shield.checkered", foregroundColor: .white, backgroundColor: .red)
                }
                .onChange(of: adBlockEnabled) { _, newValue in
                    if let adBlockRuleSet = RuleSetStore.shared.adBlockRuleSet {
                        if newValue {
                            RuleSetStore.shared.updateAssignment(adBlockRuleSet, configurationId: "REJECT")
                        } else {
                            RuleSetStore.shared.updateAssignment(adBlockRuleSet, configurationId: nil)
                        }
                    }
                    viewModel.syncRoutingConfigurationToNE()
                }
                NavigationLink {
                    RuleSetListView()
                } label: {
                    TextWithColorfulIcon(titleKey: "Routing Rules", systemName: "arrow.triangle.branch", foregroundColor: .white, backgroundColor: .purple)
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
                NavigationLink {
                    TrustedCertificatesView()
                } label: {
                    TextWithColorfulIcon(titleKey: "Trusted Certificates", systemName: "checkmark.seal.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }

            Section("About") {
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
            }
        }
        .navigationTitle("Settings")
        .onChange(of: alwaysOnEnabled) {
            viewModel.reconnectVPN()
        }
        .onChange(of: bypassCountryCode) {
            RuleSetStore.shared.syncBypassCountryRules()
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
