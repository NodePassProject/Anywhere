//
//  DNSSettingsView.swift
//  Anywhere
//
//  Created by Takuma Kirishima on 7/24/26.
//

import SwiftUI

private struct ServerDrafts: Equatable {
    var subscriptionUDP = DNSUpstream.defaultUDPServer
    var subscriptionDoH = DNSUpstream.defaultDoHURL
    var proxyUDP = DNSUpstream.defaultUDPServer
    var proxyDoH = DNSUpstream.defaultDoHURL
    var echUDP = DNSUpstream.defaultUDPServer
    var echDoH = DNSUpstream.defaultDoHURL
    var fallback = DNSUpstream.defaultUDPServer
}

struct DNSSettingsView: View {
    @Environment(\.editMode) private var editMode
    @Environment(AppSettings.self) private var settings

    @State private var drafts = ServerDrafts()

    private var isEditing: Bool {
        editMode?.wrappedValue.isEditing == true
    }

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section {
                NavigationLink("Host Mappings") {
                    HostMappingsView()
                }
            }

            Section("Subscriptions") {
                Picker("Resolver", selection: $settings.subscriptionDNSMode) {
                    ForEach(DNSMode.allCases, id: \.self) { mode in
                        Text(mode.title).tag(mode)
                    }
                }
                switch settings.subscriptionDNSMode {
                case .default:
                    EmptyView()
                case .udp:
                    udpRow($drafts.subscriptionUDP)
                case .doh:
                    dohRow($drafts.subscriptionDoH)
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
                case .udp:
                    udpRow($drafts.proxyUDP)
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
                case .udp:
                    udpRow($drafts.echUDP)
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
                case .udp:
                    udpRow($drafts.fallback)
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
    private func udpRow(_ draft: Binding<String>) -> some View {
        serverRow(draft, placeholder: String("1.1.1.1"), keyboard: .numbersAndPunctuation) {
            DNSUpstream.parseUDP($0) != nil
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
            subscriptionUDP: settings.subscriptionDNSUDPServer,
            subscriptionDoH: settings.subscriptionDNSDoHURL,
            proxyUDP: settings.proxyDNSUDPServer,
            proxyDoH: settings.proxyDNSDoHURL,
            echUDP: settings.echDNSUDPServer,
            echDoH: settings.echDNSDoHURL,
            fallback: settings.fallbackDNSServer
        )
    }

    private func save() {
        drafts = ServerDrafts(
            subscriptionUDP: Self.normalized(drafts.subscriptionUDP, empty: DNSUpstream.defaultUDPServer),
            subscriptionDoH: Self.normalized(drafts.subscriptionDoH, empty: DNSUpstream.defaultDoHURL),
            proxyUDP: Self.normalized(drafts.proxyUDP, empty: DNSUpstream.defaultUDPServer),
            proxyDoH: Self.normalized(drafts.proxyDoH, empty: DNSUpstream.defaultDoHURL),
            echUDP: Self.normalized(drafts.echUDP, empty: DNSUpstream.defaultUDPServer),
            echDoH: Self.normalized(drafts.echDoH, empty: DNSUpstream.defaultDoHURL),
            fallback: Self.normalized(drafts.fallback, empty: DNSUpstream.defaultUDPServer)
        )
        
        if settings.subscriptionDNSUDPServer != drafts.subscriptionUDP {
            settings.subscriptionDNSUDPServer = drafts.subscriptionUDP
        }
        if settings.subscriptionDNSDoHURL != drafts.subscriptionDoH {
            settings.subscriptionDNSDoHURL = drafts.subscriptionDoH
        }
        if settings.proxyDNSUDPServer != drafts.proxyUDP {
            settings.proxyDNSUDPServer = drafts.proxyUDP
        }
        if settings.proxyDNSDoHURL != drafts.proxyDoH {
            settings.proxyDNSDoHURL = drafts.proxyDoH
        }
        if settings.echDNSUDPServer != drafts.echUDP {
            settings.echDNSUDPServer = drafts.echUDP
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
