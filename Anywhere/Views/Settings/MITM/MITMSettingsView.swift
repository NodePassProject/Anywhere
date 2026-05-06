//
//  MITMSettingsView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import SwiftUI

struct MITMSettingsView: View {
    @StateObject private var store = MITMRuleSetStore.shared
    
    @State private var showAdd = false

    @State private var editMode: EditMode = .inactive
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
                ForEach(store.ruleSets) { ruleSet in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(ruleSet.domainSuffix)
                            .foregroundStyle(.primary)
                        Text(summary(for: ruleSet))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .truncationMode(.middle)
                            .lineLimit(1)
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
                Button {
                    showAdd = true
                } label: {
                    Label("Add", systemImage: "plus")
                }
            } header: {
                HStack {
                    Text("Rule Sets")
                    Spacer()
                    Button(editMode == .active ? "Done" : "Edit") {
                        if editMode == .active {
                            editMode = .inactive
                        } else {
                            editMode = .active
                        }
                    }
                }
            }
        }
        .environment(\.editMode, $editMode)
        .navigationTitle("MITM")
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
        let rulesPart = String(localized: "\(count) rule(s)")
        if let target = ruleSet.rewriteTarget {
            let authority = target.port.map { "\(target.host):\($0)" } ?? target.host
            return "→ \(authority) · \(rulesPart)"
        }
        return rulesPart
    }
}
