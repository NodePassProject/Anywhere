//
//  ModuleContentView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/12/26.
//

import SwiftUI

struct ModuleContentView: View {
    @Environment(Operations.self) private var operations
    @Environment(ModuleStore.self) private var moduleStore
    @Environment(MITMRuleSetStore.self) private var mitmStore

    let moduleId: UUID

    @State private var showAddRoutingAlert = false
    @State private var newRoutingName = ""

    @State private var showAddMITMAlert = false
    @State private var newMITMName = ""

    private var module: Module? { moduleStore.module(id: moduleId) }
    private var isSubscribed: Bool { module?.isSubscribed ?? false }
    private var canAddRuleSet: Bool { !isSubscribed && (module?.ruleSetCount ?? 0) < Module.maxRuleSetCount }
    private var showsEditButton: Bool { !isSubscribed && (module?.ruleSetCount ?? 0) > 0 }

    var body: some View {
        List {
            if let module {
                if !module.routingRuleSets.isEmpty {
                    Section("Routing Rule Sets") {
                        ForEach(module.routingRuleSets) { ruleSet in
                            NavigationLink {
                                CustomRuleSetDetailView(target: .module(moduleId: moduleId, ruleSetId: ruleSet.id))
                            } label: {
                                routingRow(for: ruleSet)
                            }
                        }
                        .onDelete(perform: isSubscribed ? nil : { offsets in
                            operations.modules.removeRoutingRuleSets(atOffsets: offsets, in: moduleId)
                        })
                        .onMove(perform: isSubscribed ? nil : { source, destination in
                            operations.modules.moveRoutingRuleSets(fromOffsets: source, toOffset: destination, in: moduleId)
                        })
                    }
                }

                if !module.mitmRuleSets.isEmpty {
                    Section {
                        ForEach(module.mitmRuleSets) { ruleSet in
                            NavigationLink {
                                MITMRuleSetDetailView(target: .module(moduleId: moduleId, ruleSetId: ruleSet.id))
                            } label: {
                                mitmRow(for: ruleSet)
                            }
                        }
                        .onDelete(perform: isSubscribed ? nil : { offsets in
                            operations.modules.removeMITMRuleSets(atOffsets: offsets, in: moduleId)
                        })
                        .onMove(perform: isSubscribed ? nil : { source, destination in
                            operations.modules.moveMITMRuleSets(fromOffsets: source, toOffset: destination, in: moduleId)
                        })
                    } header: {
                        Text("MITM Rule Sets")
                    } footer: {
                        if !mitmStore.enabled {
                            Text("MITM rule sets won't take effect until MITM is enabled.")
                        }
                    }
                }
            }
        }
        .overlay {
            if module?.ruleSetCount == 0 {
                ContentUnavailableView {
                    Label("No Rule Sets", systemImage: "list.bullet.rectangle")
                }
            }
        }
        .navigationTitle("Module Content")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if showsEditButton {
                ToolbarItem {
                    EditButton()
                }
            }
            if canAddRuleSet {
                if #available(iOS 27.0, *),
                   !ProcessInfo.processInfo.isiOSAppOnMac /* Workaround */ {
                    ToolbarOverflowMenu {
                        menuItems
                    }
                } else {
                    ToolbarItem {
                        Menu("More", systemImage: "ellipsis") {
                            menuItems
                        }
                    }
                }
            }
        }
        .alert("Add Routing Rule Set", isPresented: $showAddRoutingAlert) {
            TextField("Name", text: $newRoutingName)
            Button("Add") {
                let name = newRoutingName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                operations.modules.addRoutingRuleSet(name: name, to: moduleId)
                newRoutingName = ""
            }
            Button("Cancel", role: .cancel) {
                newRoutingName = ""
            }
        }
        .alert("Add MITM Rule Set", isPresented: $showAddMITMAlert) {
            TextField("Name", text: $newMITMName)
            Button("Add") {
                let name = newMITMName.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !name.isEmpty else { return }
                operations.modules.addMITMRuleSet(name: name, to: moduleId)
                newMITMName = ""
            }
            Button("Cancel", role: .cancel) {
                newMITMName = ""
            }
        }
    }

    @ViewBuilder
    private var menuItems: some View {
        Button {
            newRoutingName = ""
            showAddRoutingAlert = true
        } label: {
            Label("Add Routing Rule Set", systemImage: "plus")
        }
        Button {
            newMITMName = ""
            showAddMITMAlert = true
        } label: {
            Label("Add MITM Rule Set", systemImage: "plus")
        }
    }

    @ViewBuilder
    private func routingRow(for ruleSet: ModuleRoutingRuleSet) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                    .foregroundStyle(.primary)
                Text("\(ruleSet.rules.count) rule(s)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            AssignmentLabel(assignedConfigurationId: moduleStore.routingAssignment(for: ruleSet.id))
        }
    }

    @ViewBuilder
    private func mitmRow(for ruleSet: ModuleMITMRuleSet) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                    .foregroundStyle(.primary)
                Text(summary(for: ruleSet))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .truncationMode(.middle)
                    .lineLimit(1)
            }
            Spacer()
            statusDot(enabled: ruleSet.enabled)
        }
    }

    @ViewBuilder
    private func statusDot(enabled: Bool) -> some View {
        if enabled {
            Image(systemName: "circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
                .accessibilityLabel("Enabled")
        } else {
            Image(systemName: "circle.fill")
                .foregroundStyle(.red)
                .font(.caption)
                .accessibilityLabel("Disabled")
        }
    }

    private func summary(for ruleSet: ModuleMITMRuleSet) -> String {
        var parts = [String(localized: "\(ruleSet.rules.count) rule(s)")]
        if !ruleSet.parameters.isEmpty {
            parts.append(String(localized: "\(ruleSet.parameters.count) parameter(s)"))
        }
        return parts.joined(separator: " · ")
    }
}
