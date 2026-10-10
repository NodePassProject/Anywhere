//
//  HostMappingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/10/26.
//

import SwiftUI

private struct HostMappingDraft: Identifiable, Equatable {
    let id = UUID()
    var host: String
    var address: String

    init(_ mapping: HostMapping) {
        host = mapping.host
        address = mapping.address
    }

    init() {
        host = ""
        address = ""
    }

    var trimmed: HostMapping {
        HostMapping(
            host: host.trimmingCharacters(in: .whitespacesAndNewlines),
            address: address.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    var isBlank: Bool {
        let mapping = trimmed
        return mapping.host.isEmpty && mapping.address.isEmpty
    }
}

struct HostMappingsView: View {
    @Environment(\.editMode) private var editMode
    @Environment(AppSettings.self) private var settings

    @State private var drafts: [HostMappingDraft] = []

    private var isEditing: Bool {
        editMode?.wrappedValue.isEditing == true
    }

    var body: some View {
        Form {
            Section {
                if drafts.isEmpty && !isEditing {
                    Text("No host mappings")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach($drafts) { $draft in
                        if isEditing {
                            VStack(alignment: .leading) {
                                TextField(String("example.com"), text: $draft.host)
                                    .keyboardType(.URL)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                TextField(String("192.0.2.1"), text: $draft.address)
                                    .keyboardType(.numbersAndPunctuation)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                            }
                        } else {
                            HStack {
                                Text(draft.host)
                                Spacer()
                                Text(draft.address)
                                    .foregroundStyle(.secondary)
                                if !draft.trimmed.isValid {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                    .onDelete { offsets in
                        drafts.remove(atOffsets: offsets)
                        if !isEditing { save() }
                    }
                    .onMove { source, destination in
                        drafts.move(fromOffsets: source, toOffset: destination)
                        if !isEditing { save() }
                    }
                }
            }
        }
        .navigationTitle("Host Mappings")
        .toolbar {
            ToolbarItem {
                EditButton()
            }
        }
        .onAppear { loadInitial() }
        .onChange(of: isEditing) { _, newValue in
            if newValue {
                ensureTrailingBlankDraft()
            } else {
                save()
            }
        }
        .onChange(of: drafts) {
            if isEditing {
                ensureTrailingBlankDraft()
            }
        }
        .onDisappear { save() }
    }

    private func loadInitial() {
        drafts = settings.hostMappings.map { HostMappingDraft($0) }
    }

    private func ensureTrailingBlankDraft() {
        if drafts.last?.isBlank != true {
            drafts.append(HostMappingDraft())
        }
    }

    private func save() {
        var seen = Set<HostMapping>()
        let reconciled = drafts.compactMap { draft -> HostMappingDraft? in
            let mapping = draft.trimmed
            guard !draft.isBlank, seen.insert(mapping).inserted else { return nil }
            var normalized = draft
            normalized.host = mapping.host
            normalized.address = mapping.address
            return normalized
        }
        if reconciled != drafts {
            drafts = reconciled
        }
        let mappings = reconciled.map(\.trimmed)
        if settings.hostMappings != mappings {
            settings.hostMappings = mappings
        }
    }
}
