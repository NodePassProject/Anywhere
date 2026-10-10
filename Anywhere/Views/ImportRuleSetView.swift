//
//  ImportRuleSetView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/10/26.
//

import Foundation
import Observation
import SwiftUI

struct ImportRuleSetView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(Operations.self) private var operations
    @Environment(MITMRuleSetStore.self) private var mitmStore

    @State private var model: ImportRuleSetModel

    init(link: URL) {
        _model = State(initialValue: ImportRuleSetModel(link: link))
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
                case .routing(let ruleSet, let route):
                    row(name: ruleSet.name, iconLight: ruleSet.iconLight, iconDark: ruleSet.iconDark) {
                        AssignmentLabel(assignedConfigurationId: route.assignmentId)
                    }
                case .mitm(let ruleSet):
                    row(name: ruleSet.name, iconLight: ruleSet.iconLight, iconDark: ruleSet.iconDark) {
                        EmptyView()
                    }
                    if !mitmStore.enabled {
                        mitmDisabledWarning
                    }
                }
            }
            .navigationTitle("Import Rule Set")
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
    private func row<Trailing: View>(
        name: String,
        iconLight: Data?,
        iconDark: Data?,
        @ViewBuilder trailing: () -> Trailing
    ) -> some View {
        Section {
            HStack(spacing: 12) {
                RuleSetIconView(iconLight: iconLight, iconDark: iconDark)
                VStack(alignment: .leading, spacing: 2) {
                    Text(name)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(model.summary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(model.link.host ?? model.link.absoluteString)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer(minLength: 0)
                trailing()
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

    // MARK: - Import

    private func performImport() {
        switch model.status {
        case .routing(let ruleSet, let route):
            operations.routingRuleSets.addCustomRuleSet(ruleSet, initialAssignment: route.assignmentId)
        case .mitm(let ruleSet):
            operations.mitmRuleSets.addRuleSet(ruleSet)
        case .loading, .failed:
            return
        }
        dismiss()
    }
}

@MainActor
@Observable
final class ImportRuleSetModel {
    enum Status {
        case loading
        case routing(CustomRoutingRuleSet, route: RuleSetImportRoute)
        case mitm(MITMRuleSet)
        case failed(String)
    }

    private enum Kind {
        case routing
        case mitm
    }

    let link: URL
    private(set) var status: Status = .loading

    init(link: URL) {
        self.link = link
    }

    var isReady: Bool {
        switch status {
        case .routing, .mitm: return true
        case .loading, .failed: return false
        }
    }

    var summary: String {
        switch status {
        case .routing(let ruleSet, _):
            return [String(localized: "Routing"), String(localized: "\(ruleSet.rules.count) rule(s)")]
                .joined(separator: " · ")
        case .mitm(let ruleSet):
            var parts = [String(localized: "MITM"), String(localized: "\(ruleSet.rules.count) rule(s)")]
            if !ruleSet.parameters.isEmpty {
                parts.append(String(localized: "\(ruleSet.parameters.count) parameter(s)"))
            }
            return parts.joined(separator: " · ")
        case .loading, .failed:
            return ""
        }
    }

    func load() async {
        let raw = link.absoluteString
        let kind: Kind
        let url: URL
        if let routingURL = CustomRoutingRuleSet.validSubscriptionURL(from: raw) {
            kind = .routing
            url = routingURL
        } else if let mitmURL = MITMRuleSet.validSubscriptionURL(from: raw) {
            kind = .mitm
            url = mitmURL
        } else {
            status = .failed(String(localized: "Unsupported link."))
            return
        }

        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                status = .failed("HTTP \(http.statusCode)")
                return
            }
            guard let body = String(data: data, encoding: .utf8) else {
                status = .failed(String(localized: "Unknown content."))
                return
            }
            switch kind {
            case .routing: status = Self.routingStatus(body, url: url)
            case .mitm: status = Self.mitmStatus(body, url: url)
            }
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    private static func routingStatus(_ body: String, url: URL) -> Status {
        let parsed = RoutingRuleSetParser.parse(body)
        guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
            return .failed(String(localized: "Rule set is too large."))
        }
        let name = parsed.name.isEmpty ? fallbackName(for: url) : parsed.name
        let ruleSet = CustomRoutingRuleSet(
            name: name,
            rules: parsed.rules,
            subscriptionURL: url,
            iconLight: parsed.iconLight,
            iconDark: parsed.iconDark
        )
        return .routing(ruleSet, route: parsed.routing)
    }

    private static func mitmStatus(_ body: String, url: URL) -> Status {
        let parsed = MITMRuleSetParser.parse(body)
        guard parsed.rules.count <= MITMRuleSet.maxRuleCount else {
            return .failed(String(localized: "Rule set is too large."))
        }
        let name = parsed.name.isEmpty ? fallbackName(for: url) : parsed.name
        let ruleSet = MITMRuleSet(
            name: name,
            domainSuffixes: parsed.domainSuffixes,
            rules: parsed.rules,
            parameters: parsed.parameters,
            subscriptionURL: url,
            iconLight: parsed.iconLight,
            iconDark: parsed.iconDark
        )
        return .mitm(ruleSet)
    }

    private static func fallbackName(for url: URL) -> String {
        let base = url.deletingPathExtension().lastPathComponent
        return base.isEmpty ? "Subscription" : base
    }
}
