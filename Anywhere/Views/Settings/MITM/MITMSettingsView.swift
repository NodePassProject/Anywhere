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
    @State private var editing: MITMRuleSet?

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $store.enabled) {
                    TextWithColorfulIcon(title: "MITM", comment: nil, systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .indigo)
                }
            }

            Section {
                NavigationLink {
                    MITMCertificateView()
                } label: {
                    TextWithColorfulIcon(title: "Root Certificate", comment: nil, systemName: "lock.rectangle.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }

            Section {
                if store.ruleSets.isEmpty {
                    Text("No rule sets")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(store.ruleSets) { ruleSet in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(ruleSet.domainSuffix)
                                .foregroundStyle(.primary)
                            Text(summary(for: ruleSet))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            editing = ruleSet
                        }
                    }
                    .onDelete { offsets in
                        store.removeRuleSets(atOffsets: offsets)
                    }
                    .onMove { source, destination in
                        store.moveRuleSets(fromOffsets: source, toOffset: destination)
                    }
                }
            } header: {
                Text("Rule Sets")
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
            ToolbarItem(placement: .automatic) {
                if !store.ruleSets.isEmpty {
                    EditButton()
                }
            }
        }
        .sheet(isPresented: $showAdd) {
            NavigationStack {
                MITMRuleSetEditorView(ruleSet: nil) { ruleSet in
                    if let ruleSet { store.addRuleSet(ruleSet) }
                }
            }
        }
        .sheet(item: $editing) { ruleSet in
            NavigationStack {
                MITMRuleSetEditorView(ruleSet: ruleSet) { updated in
                    if let updated { store.updateRuleSet(updated) }
                }
            }
        }
    }

    private func summary(for ruleSet: MITMRuleSet) -> String {
        let count = ruleSet.rules.count
        let rulesPart = count == 1
            ? String(localized: "1 rule")
            : String(localized: "\(count) rules")
        if let target = ruleSet.rewriteTarget {
            let authority = target.port.map { "\(target.host):\($0)" } ?? target.host
            return "→ \(authority) · \(rulesPart)"
        }
        return rulesPart
    }
}
