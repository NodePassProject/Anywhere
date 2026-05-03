//
//  MITMSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import SwiftUI

struct MITMSettingsView: View {
    @StateObject private var store = MITMStore.shared

    @State private var showAdd = false
    @State private var editing: MITMRule?

    var body: some View {
        Form {
            Section {
                Toggle("Enable MITM", isOn: $store.enabled)
            } footer: {
                Text("MITM intercepts and decrypts TLS traffic for matched hostnames. Apps with certificate pinning will fail. Only enable for hostnames you understand.")
            }

            Section("Certificate") {
                NavigationLink {
                    MITMCertificateView()
                } label: {
                    Label("Root Certificate", systemImage: "lock.shield")
                }
            }

            Section {
                if store.rules.isEmpty {
                    Text("No rules")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.rules) { rule in
                        Button {
                            editing = rule
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(rule.value)
                                    .foregroundStyle(.primary)
                                Text(typeLabel(rule.type))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .onDelete { offsets in
                        store.remove(atOffsets: offsets)
                    }
                }
            } header: {
                Text("Hostnames")
            } footer: {
                Text("Use \"Domain Suffix\" for label-aligned matches (\"example.com\" matches \"www.example.com\"). Use \"Domain Keyword\" for substring matches.")
            }
        }
        .navigationTitle("MITM")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showAdd = true
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .sheet(isPresented: $showAdd) {
            NavigationStack {
                MITMRuleEditorView(rule: nil) { rule in
                    if let rule { store.add(rule) }
                }
            }
        }
        .sheet(item: $editing) { rule in
            NavigationStack {
                MITMRuleEditorView(rule: rule) { updated in
                    if let updated { store.update(updated) }
                }
            }
        }
    }

    private func typeLabel(_ type: DomainRuleType) -> String {
        switch type {
        case .domainSuffix:  return String(localized: "Domain Suffix")
        case .domainKeyword: return String(localized: "Domain Keyword")
        case .ipCIDR, .ipCIDR6: return String(localized: "Unsupported")
        }
    }
}
