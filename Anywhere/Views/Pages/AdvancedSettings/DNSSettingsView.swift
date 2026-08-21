//
//  DNSSettingsView.swift
//  Anywhere
//
//  Created by Takuma Kirishima on 7/24/26.
//

import SwiftUI

private struct ServerDrafts: Equatable {
    var subscriptionPlain = DNSUpstream.defaultPlainServer
    var subscriptionDoH = DNSUpstream.defaultDoHURL
    var ipRulePlain = DNSUpstream.defaultPlainServer
    var ipRuleDoH = DNSUpstream.defaultDoHURL
    var proxyPlain = DNSUpstream.defaultPlainServer
    var proxyDoH = DNSUpstream.defaultDoHURL
    var echPlain = DNSUpstream.defaultPlainServer
    var echDoH = DNSUpstream.defaultDoHURL
    var fallback = DNSUpstream.defaultPlainServer
}

struct DNSSettingsView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(\.editMode) private var editMode

    @State private var drafts = ServerDrafts()

    private var isEditing: Bool {
        editMode?.wrappedValue.isEditing == true
    }

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section("Subscriptions") {
                Picker("Resolver", selection: $settings.subscriptionDNSMode) {
                    ForEach(DNSMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                switch settings.subscriptionDNSMode {
                case .default:
                    EmptyView()
                case .plain:
                    plainRow($drafts.subscriptionPlain)
                case .doh:
                    dohRow($drafts.subscriptionDoH)
                }
            }

            Section("IP Rules") {
                Picker("Resolver", selection: $settings.ipRuleDNSMode) {
                    ForEach(DNSMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                switch settings.ipRuleDNSMode {
                case .default:
                    EmptyView()
                case .plain:
                    plainRow($drafts.ipRulePlain)
                case .doh:
                    dohRow($drafts.ipRuleDoH)
                }
            }

            Section("Proxies") {
                Picker("Resolver", selection: $settings.proxyDNSMode) {
                    ForEach(DNSMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                switch settings.proxyDNSMode {
                case .default:
                    EmptyView()
                case .plain:
                    plainRow($drafts.proxyPlain)
                case .doh:
                    dohRow($drafts.proxyDoH)
                }
            }

            Section("ECH") {
                Picker("Resolver", selection: $settings.echDNSMode) {
                    ForEach(DNSMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                switch settings.echDNSMode {
                case .default:
                    EmptyView()
                case .plain:
                    plainRow($drafts.echPlain)
                case .doh:
                    dohRow($drafts.echDoH)
                }
            }

            Section("Fallback") {
                Picker("Resolver", selection: $settings.fallbackDNSMode) {
                    ForEach(FallbackDNSMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                switch settings.fallbackDNSMode {
                case .default:
                    EmptyView()
                case .plain:
                    plainRow($drafts.fallback)
                }
            }
        }
        .navigationTitle("DNS")
        .toolbar {
            ToolbarItem {
                EditButton()
            }
        }
        .onAppear { loadInitial() }
        .onChange(of: isEditing) { _, newValue in
            if !newValue {
                save()
            }
        }
        .onDisappear { save() }
    }

    // MARK: - Rows

    @ViewBuilder
    private func plainRow(_ draft: Binding<String>) -> some View {
        serverRow(draft, placeholder: String("1.1.1.1"), keyboard: .numbersAndPunctuation) {
            DNSUpstream.parsePlain($0) != nil
        }
    }

    @ViewBuilder
    private func dohRow(_ draft: Binding<String>) -> some View {
        serverRow(draft, placeholder: String("https://cloudflare-dns.com/dns-query"), keyboard: .URL) {
            DNSUpstream.parseDoH($0) != nil
        }
    }
    
    @ViewBuilder
    private func serverRow(_ draft: Binding<String>, placeholder: String,
                           keyboard: UIKeyboardType, isValid: (String) -> Bool) -> some View {
        if isEditing {
            TextField(placeholder, text: draft)
                .keyboardType(keyboard)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        } else {
            HStack {
                Text(draft.wrappedValue)
                if !isValid(draft.wrappedValue) {
                    Spacer()
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    // MARK: - Persistence

    private func loadInitial() {
        drafts = ServerDrafts(
            subscriptionPlain: settings.subscriptionDNSPlainServer,
            subscriptionDoH: settings.subscriptionDNSDoHURL,
            ipRulePlain: settings.ipRuleDNSPlainServer,
            ipRuleDoH: settings.ipRuleDNSDoHURL,
            proxyPlain: settings.proxyDNSPlainServer,
            proxyDoH: settings.proxyDNSDoHURL,
            echPlain: settings.echDNSPlainServer,
            echDoH: settings.echDNSDoHURL,
            fallback: settings.fallbackDNSServer
        )
    }

    private func save() {
        drafts = ServerDrafts(
            subscriptionPlain: Self.normalized(drafts.subscriptionPlain, empty: DNSUpstream.defaultPlainServer),
            subscriptionDoH: Self.normalized(drafts.subscriptionDoH, empty: DNSUpstream.defaultDoHURL),
            ipRulePlain: Self.normalized(drafts.ipRulePlain, empty: DNSUpstream.defaultPlainServer),
            ipRuleDoH: Self.normalized(drafts.ipRuleDoH, empty: DNSUpstream.defaultDoHURL),
            proxyPlain: Self.normalized(drafts.proxyPlain, empty: DNSUpstream.defaultPlainServer),
            proxyDoH: Self.normalized(drafts.proxyDoH, empty: DNSUpstream.defaultDoHURL),
            echPlain: Self.normalized(drafts.echPlain, empty: DNSUpstream.defaultPlainServer),
            echDoH: Self.normalized(drafts.echDoH, empty: DNSUpstream.defaultDoHURL),
            fallback: Self.normalized(drafts.fallback, empty: DNSUpstream.defaultPlainServer)
        )
        
        if settings.subscriptionDNSPlainServer != drafts.subscriptionPlain {
            settings.subscriptionDNSPlainServer = drafts.subscriptionPlain
        }
        if settings.subscriptionDNSDoHURL != drafts.subscriptionDoH {
            settings.subscriptionDNSDoHURL = drafts.subscriptionDoH
        }
        if settings.ipRuleDNSPlainServer != drafts.ipRulePlain {
            settings.ipRuleDNSPlainServer = drafts.ipRulePlain
        }
        if settings.ipRuleDNSDoHURL != drafts.ipRuleDoH {
            settings.ipRuleDNSDoHURL = drafts.ipRuleDoH
        }
        if settings.proxyDNSPlainServer != drafts.proxyPlain {
            settings.proxyDNSPlainServer = drafts.proxyPlain
        }
        if settings.proxyDNSDoHURL != drafts.proxyDoH {
            settings.proxyDNSDoHURL = drafts.proxyDoH
        }
        if settings.echDNSPlainServer != drafts.echPlain {
            settings.echDNSPlainServer = drafts.echPlain
        }
        if settings.echDNSDoHURL != drafts.echDoH {
            settings.echDNSDoHURL = drafts.echDoH
        }
        if settings.fallbackDNSServer != drafts.fallback {
            settings.fallbackDNSServer = drafts.fallback
        }
    }
    
    private static func normalized(_ value: String, empty fallback: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? fallback : trimmed
    }
}
