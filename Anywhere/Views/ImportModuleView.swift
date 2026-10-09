//
//  ImportModuleView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/9/26.
//

import Foundation
import Observation
import SwiftUI

struct ImportModuleView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(Operations.self) private var operations
    @Environment(MITMRuleSetStore.self) private var mitmStore

    @State private var model: ImportModuleModel

    init(link: URL) {
        _model = State(initialValue: ImportModuleModel(link: link))
    }

    var body: some View {
        NavigationStack {
            List {
                switch model.status {
                case .loading:
                    Section {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text("Loading…")
                                .foregroundStyle(.secondary)
                        }
                    }
                case .failed(let message):
                    Section {
                        Label {
                            Text(message)
                                .foregroundStyle(.secondary)
                        } icon: {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        }
                    }
                case .ready(let module, let routingSeeds):
                    header(for: module)
                    if !module.mitmRuleSets.isEmpty && !mitmStore.enabled {
                        mitmDisabledWarning
                    }
                    if !module.routingRuleSets.isEmpty {
                        Section("Routing Rule Sets") {
                            ForEach(module.routingRuleSets) { ruleSet in
                                routingRow(for: ruleSet, seed: routingSeeds[ruleSet.id])
                            }
                        }
                    }
                    if !module.mitmRuleSets.isEmpty {
                        Section("MITM Rule Sets") {
                            ForEach(module.mitmRuleSets) { ruleSet in
                                mitmRow(for: ruleSet)
                            }
                        }
                    }
                }
            }
            .navigationTitle("Import Module")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    CancelButton("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    ConfirmButton("Done") { performImport() }
                        .disabled(!model.isReady)
                }
            }
            .task { await model.load() }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private func header(for module: Module) -> some View {
        Section {
            HStack(spacing: 12) {
                ModuleIconView(iconLight: module.iconLight, iconDark: module.iconDark)
                VStack(alignment: .leading, spacing: 2) {
                    Text(module.name)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(model.link.host ?? model.link.absoluteString)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
    }

    @ViewBuilder
    private var mitmDisabledWarning: some View {
        Section {
            Label {
                Text("MITM rule sets won't take effect until MITM is enabled.")
                    .foregroundStyle(.secondary)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
    }

    @ViewBuilder
    private func routingRow(for ruleSet: ModuleRoutingRuleSet, seed: String?) -> some View {
        HStack {
            Image(systemName: "arrow.triangle.branch")
                .foregroundStyle(.secondary)
                .frame(width: 30, height: 30)
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                Text("\(ruleSet.rules.count) rule(s)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            AssignmentLabel(assignedConfigurationId: seed)
        }
    }

    @ViewBuilder
    private func mitmRow(for ruleSet: ModuleMITMRuleSet) -> some View {
        HStack {
            Image(systemName: "key.horizontal.fill")
                .foregroundStyle(.secondary)
                .frame(width: 30, height: 30)
            VStack(alignment: .leading) {
                Text(ruleSet.name)
                Text(summary(for: ruleSet))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .truncationMode(.middle)
                    .lineLimit(1)
            }
        }
    }

    private func summary(for ruleSet: ModuleMITMRuleSet) -> String {
        var parts = [String(localized: "\(ruleSet.rules.count) rule(s)")]
        if !ruleSet.parameters.isEmpty {
            parts.append(String(localized: "\(ruleSet.parameters.count) parameter(s)"))
        }
        return parts.joined(separator: " · ")
    }

    // MARK: - Import

    private func performImport() {
        guard case .ready(let module, let routingSeeds) = model.status else { return }
        operations.modules.add(module, routingSeeds: routingSeeds)
        dismiss()
    }
}

@MainActor
@Observable
final class ImportModuleModel {
    enum Status {
        case loading
        case ready(module: Module, routingSeeds: [UUID: String])
        case failed(String)
    }

    let link: URL
    private(set) var status: Status = .loading

    init(link: URL) {
        self.link = link
    }

    var isReady: Bool {
        if case .ready = status { return true }
        return false
    }

    func load() async {
        guard let url = Module.validSubscriptionURL(from: link.absoluteString) else {
            status = .failed(String(localized: "Unsupported link."))
            return
        }
        do {
            let body = try await ModuleOperations.fetchBody(from: url)
            let made = try ModuleOperations.makeModule(
                from: body,
                fallbackName: ModuleOperations.fallbackName(for: url),
                subscriptionURL: url
            )
            status = .ready(module: made.module, routingSeeds: made.routingSeeds)
        } catch {
            status = .failed(error.localizedDescription)
        }
    }
}
