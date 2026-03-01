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
/// - "settingsChanged": triggers LWIPStack restart. Posted when ipv6, doh, or bypass changes.
///   LWIPStack re-reads all settings from UserDefaults during restart.
///   IPv6 also triggers tunnel settings re-apply (routes + DNS servers).
///
/// - "routingChanged": triggers DomainRouter rule reload only (no restart).
///   Posted by RuleSetListView when routing rule assignments change.
///
/// - "alwaysOnEnabled": read by VPNViewModel only; does not affect the running NE.
struct SettingsView: View {
    @AppStorage("alwaysOnEnabled", store: APCore.userDefaults)
    private var alwaysOnEnabled = false

    @AppStorage("ipv6Enabled", store: APCore.userDefaults)
    private var ipv6Enabled = false

    @AppStorage("dohEnabled", store: APCore.userDefaults)
    private var dohEnabled = false

    @AppStorage("bypassCountryCode", store: APCore.userDefaults)
    private var bypassCountryCode = ""

    @State private var showDoHAlert = false

    // Countries with serious internet censorship (must match INCLUDED_COUNTRIES in build_geoip.py)
    private static let countryCodes: [String] = [
        "AE", "BY", "CN", "CU", "IR", "MM", "RU", "SA", "TM", "VN"
    ]

    private var hasRoutingRules: Bool {
        RuleSetStore.shared.ruleSets.contains { $0.assignedConfigurationId != nil }
    }

    var body: some View {
        Form {
            Section("VPN") {
                Toggle(isOn: $alwaysOnEnabled) {
                    TextWithColorfulIcon(titleKey: "Always On", systemName: "bolt.shield.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }

            Section("Network") {
                Toggle(isOn: $ipv6Enabled) {
                    TextWithColorfulIcon(titleKey: "IPv6", systemName: "6.circle.fill", foregroundColor: .white, backgroundColor: .blue)
                }
                Toggle(isOn: Binding(
                    get: { dohEnabled },
                    set: { newValue in
                        if newValue && hasRoutingRules {
                            showDoHAlert = true
                        } else {
                            dohEnabled = newValue
                            notifySettingsChanged()
                        }
                    }
                )) {
                    TextWithColorfulIcon(titleKey: "DNS over HTTPS", systemName: "lock.shield.fill", foregroundColor: .white, backgroundColor: .teal)
                }
            }

            Section("Routing") {
                NavigationLink {
                    RuleSetListView()
                } label: {
                    TextWithColorfulIcon(titleKey: "Routing Rules", systemName: "arrow.triangle.branch", foregroundColor: .white, backgroundColor: .purple)
                }
                Picker(selection: $bypassCountryCode) {
                    Text("Disable").tag("")
                    ForEach(Self.countryCodes, id: \.self) { code in
                        Text("\(flag(for: code)) \(Locale.current.localizedString(forRegionCode: code) ?? code)").tag(code)
                    }
                } label: {
                    TextWithColorfulIcon(titleKey: "Country Bypass", systemName: "globe.americas.fill", foregroundColor: .white, backgroundColor: .orange)
                }
            }
        }
        .navigationTitle("Settings")
        .onChange(of: ipv6Enabled) { notifySettingsChanged() }
        .onChange(of: bypassCountryCode) { notifySettingsChanged() }
        .alert(String(localized: "DNS over HTTPS"), isPresented: $showDoHAlert) {
            Button(String(localized: "Enable Anyway"), role: .destructive) {
                dohEnabled = true
                notifySettingsChanged()
            }
            Button(String(localized: "Cancel"), role: .cancel) {}
        } message: {
            Text("Enabling DNS over HTTPS will prevent routing rules from working. Domain-based routing requires plain DNS to intercept queries.")
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
