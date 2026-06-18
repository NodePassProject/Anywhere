//
//  ImportRuleSetsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/17/26.
//

import Foundation
import Observation
import SwiftUI

struct ImportRuleSetsView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(RoutingRuleSetStore.self) private var routingStore
    @Environment(MITMRuleSetStore.self) private var mitmStore

    @State private var model: ImportRuleSetsModel

    init(links: [URL]) {
        _model = State(initialValue: ImportRuleSetsModel(links: links))
    }

    var body: some View {
        NavigationStack {
            List {
                if model.willImportMITM && !mitmStore.enabled {
                    mitmDisabledWarning
                }
                Section {
                    ForEach(model.items) { item in
                        row(for: item)
                    }
                }
            }
            .navigationTitle("Import Rule Sets")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    CancelButton("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    ConfirmButton("Done") { performImport() }
                        .disabled(model.isLoading || !model.hasSelection)
                }
            }
            .task { await model.loadAll() }
        }
    }

    // MARK: - MITM warning

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

    // MARK: - Row

    @ViewBuilder
    private func row(for item: ImportRuleSetsModel.Item) -> some View {
        HStack(spacing: 12) {
            Image(systemName: item.kind.iconName)
                .foregroundStyle(.secondary)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(item.displayName)
                    .lineLimit(1)
                    .truncationMode(.middle)

                detail(for: item)

                Text(item.url.host ?? item.url.absoluteString)
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: 0)

            trailing(for: item)
        }
        .contentShape(.rect)
        .onTapGesture {
            guard item.status == .ready else { return }
            model.toggle(item.id)
        }
    }

    @ViewBuilder
    private func detail(for item: ImportRuleSetsModel.Item) -> some View {
        switch item.status {
        case .loading:
            Text("Loading…")
                .font(.caption)
                .foregroundStyle(.secondary)
        case .ready:
            Text(item.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        case .failed(let message):
            Text(message)
                .font(.caption)
                .foregroundStyle(.red)
                .lineLimit(2)
        }
    }

    @ViewBuilder
    private func trailing(for item: ImportRuleSetsModel.Item) -> some View {
        switch item.status {
        case .loading:
            ProgressView()
                .frame(width: 25)
        case .ready:
            Image(systemName: item.isSelected ? "checkmark.circle.fill" : "circle")
                .font(.title2)
                .foregroundStyle(item.isSelected ? Color.blue : Color.secondary)
                .contentTransition(.symbolEffect)
                .frame(width: 25)
        case .failed:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .frame(width: 25)
        }
    }

    // MARK: - Import

    private func performImport() {
        for item in model.items where item.isSelected && item.status == .ready {
            if let routingSet = item.routingSet {
                routingStore.addCustomRuleSet(routingSet, initialAssignment: item.routingRoute.assignmentId)
            } else if let mitmSet = item.mitmSet {
                mitmStore.addRuleSet(mitmSet)
            }
        }
        dismiss()
    }
}

@MainActor
@Observable
final class ImportRuleSetsModel {
    enum Kind {
        case routing
        case mitm

        var iconName: String {
            switch self {
            case .routing: return "arrow.triangle.branch"
            case .mitm: return "key.horizontal.fill"
            }
        }
    }

    enum Status: Equatable {
        case loading
        case ready
        case failed(String)
    }

    struct Item: Identifiable {
        let id = UUID()
        let url: URL
        let kind: Kind
        var status: Status = .loading
        var isSelected: Bool = true
        var displayName: String
        var summary: String = ""
        var routingSet: CustomRoutingRuleSet?
        var routingRoute: RuleSetImportRoute = .default
        var mitmSet: MITMRuleSet?
    }

    private(set) var items: [Item]
    
    var hasSelection: Bool {
        items.contains { $0.isSelected && $0.status == .ready }
    }
    
    var isLoading: Bool {
        items.contains { $0.status == .loading }
    }

    /// True when at least one selected, non-failed item is a MITM rule set —
    /// drives the "MITM is disabled" warning.
    var willImportMITM: Bool {
        items.contains { item in
            guard item.kind == .mitm, item.isSelected else { return false }
            if case .failed = item.status { return false }
            return true
        }
    }

    init(links: [URL]) {
        items = links.map { url in
            let path = url.path.lowercased()
            let fallback = Self.fallbackName(for: url)
            if path.hasSuffix(".arrs") {
                return Item(url: url, kind: .routing, displayName: fallback)
            } else if path.hasSuffix(".amrs") {
                return Item(url: url, kind: .mitm, displayName: fallback)
            } else {
                // Unknown extension: surface it as failed so the reason is visible
                // rather than silently omitting the link.
                var item = Item(url: url, kind: .routing, displayName: fallback)
                item.status = .failed(String(localized: "Unsupported link."))
                item.isSelected = false
                return item
            }
        }
    }

    func toggle(_ id: UUID) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        items[index].isSelected.toggle()
    }

    func loadAll() async {
        let pending = items.filter { $0.status == .loading }.map(\.id)
        await withTaskGroup(of: Void.self) { group in
            for id in pending {
                group.addTask { await self.load(id: id) }
            }
        }
    }

    private func load(id: UUID) async {
        guard let item = items.first(where: { $0.id == id }) else { return }
        let url = item.url
        let kind = item.kind
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
                fail(id: id, message: "HTTP \(http.statusCode)")
                return
            }
            guard let body = String(data: data, encoding: .utf8) else {
                fail(id: id, message: String(localized: "Unknown content."))
                return
            }

            switch kind {
            case .routing:
                let parsed = RoutingRuleSetParser.parse(body)
                guard parsed.rules.count <= CustomRoutingRuleSet.maxRuleCount else {
                    fail(id: id, message: String(localized: "Rule set is too large."))
                    return
                }
                let name = parsed.name.isEmpty ? Self.fallbackName(for: url) : parsed.name
                let set = CustomRoutingRuleSet(name: name, rules: parsed.rules, subscriptionURL: url)
                let summary = String(localized: "Routing") + " · " + String(localized: "\(parsed.rules.count) rule(s)")
                apply(id: id) {
                    $0.status = .ready
                    $0.displayName = name
                    $0.summary = summary
                    $0.routingSet = set
                    $0.routingRoute = parsed.routing
                }

            case .mitm:
                let parsed = MITMRuleSetParser.parse(body)
                guard parsed.rules.count <= MITMRuleSet.maxRuleCount else {
                    fail(id: id, message: String(localized: "Rule set is too large."))
                    return
                }
                let name = parsed.name.isEmpty ? Self.fallbackName(for: url) : parsed.name
                let set = MITMRuleSet(
                    name: name,
                    domainSuffixes: parsed.domainSuffixes,
                    rules: parsed.rules,
                    subscriptionURL: url
                )
                var summary = String(localized: "Routing") + " · " + String(localized: "\(parsed.rules.count) rule(s)")
                if !parsed.domainSuffixes.isEmpty {
                    summary += " · " + String(localized: "\(parsed.domainSuffixes.count) domain(s)")
                }
                apply(id: id) {
                    $0.status = .ready
                    $0.displayName = name
                    $0.summary = summary
                    $0.mitmSet = set
                }
            }
        } catch {
            fail(id: id, message: error.localizedDescription)
        }
    }

    private func fail(id: UUID, message: String) {
        apply(id: id) {
            $0.status = .failed(message)
            $0.isSelected = false
        }
    }

    private func apply(id: UUID, _ mutate: (inout Item) -> Void) {
        guard let index = items.firstIndex(where: { $0.id == id }) else { return }
        mutate(&items[index])
    }

    private static func fallbackName(for url: URL) -> String {
        let base = url.deletingPathExtension().lastPathComponent
        if !base.isEmpty { return base }
        return url.host ?? String(localized: "Rule Set")
    }
}
