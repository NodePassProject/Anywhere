//
//  MITMSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import SwiftUI

struct MITMSettingsView: View {
    @StateObject private var store = MITMRuleSetStore.shared

    @State private var showAddSheet = false
    @State private var newRuleSetName = ""
    
    @State private var showImportSheet = false

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

            Section("Rule Sets") {
                ForEach(store.ruleSets) { ruleSet in
                    NavigationLink {
                        MITMRuleSetDetailView(ruleSet: ruleSet)
                    } label: {
                        VStack(alignment: .leading) {
                            Text(ruleSet.name)
                                .foregroundStyle(.primary)
                            Text(summary(for: ruleSet))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .truncationMode(.middle)
                                .lineLimit(1)
                        }
                    }
                }
                .onDelete { offsets in
                    store.removeRuleSets(atOffsets: offsets)
                }
                .onMove { source, destination in
                    store.moveRuleSets(fromOffsets: source, toOffset: destination)
                }
            }
        }
        .navigationTitle("MITM")
        .toolbar {
            ToolbarItem {
                EditButton()
            }
            ToolbarItem {
                Menu("More", systemImage: "ellipsis") {
                    Button {
                        showAddSheet = true
                    } label: {
                        Label("Add Rule Set", systemImage: "plus")
                    }
                    Button {
                        showImportSheet = true
                    } label: {
                        Label("Import Rule Set", systemImage: "square.and.arrow.down")
                    }
                }
            }
        }
        .alert("Add Rule Set", isPresented: $showAddSheet) {
            TextField("Name", text: $newRuleSetName)
            Button("Add") {
                let name = newRuleSetName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                store.addRuleSet(MITMRuleSet(name: name))
                newRuleSetName = ""
            }
            Button("Cancel", role: .cancel) {
                newRuleSetName = ""
            }
        }
        .sheet(isPresented: $showImportSheet) {
            ImportMITMRuleSetView { ruleSet in
                store.addRuleSet(ruleSet)
            }
        }
    }

    private func summary(for ruleSet: MITMRuleSet) -> String {
        let count = ruleSet.rules.count
        let rulesPart = String(localized: "\(count) rule(s)")
        if let target = ruleSet.rewriteTarget {
            let authority = target.port.map { "\(target.host):\($0)" } ?? target.host
            return "→ \(authority) · \(rulesPart)"
        }
        return rulesPart
    }
}
