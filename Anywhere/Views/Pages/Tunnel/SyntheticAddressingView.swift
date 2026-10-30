//
//  SyntheticAddressingView.swift
//  Anywhere
//
//  Created by NodePassProject on 10/30/26.
//

import SwiftUI

private struct DomainSuffixDraft: Identifiable, Equatable {
    let id = UUID()
    var value: String
}

struct SyntheticAddressingView: View {
    @Environment(AppSettings.self) private var settings
    @Environment(\.editMode) private var editMode

    @State private var suffixDrafts: [DomainSuffixDraft] = []

    private var isEditing: Bool {
        editMode?.wrappedValue.isEditing == true
    }

    var body: some View {
        Form {
            Section("Excluded Domain Suffixes") {
                if suffixDrafts.isEmpty {
                    Text("None")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach($suffixDrafts) { $draft in
                        if isEditing {
                            TextField(String("example.com"), text: $draft.value)
                                .keyboardType(.URL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        } else {
                            HStack {
                                Text(draft.value)
                                if DNSName.normalizedDomainSuffix(draft.value) == nil {
                                    Spacer()
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                    .onDelete { offsets in
                        suffixDrafts.remove(atOffsets: offsets)
                        if !isEditing { save() }
                    }
                    .onMove { source, destination in
                        suffixDrafts.move(fromOffsets: source, toOffset: destination)
                        if !isEditing { save() }
                    }
                }
            }
        }
        .navigationTitle("Synthetic Addressing")
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
        .onChange(of: suffixDrafts) {
            if isEditing {
                ensureTrailingBlankDraft()
            }
        }
        .onDisappear { save() }
    }

    private func loadInitial() {
        suffixDrafts = settings.syntheticAddressExcludedDomainSuffixes.map { DomainSuffixDraft(value: $0) }
    }

    private func ensureTrailingBlankDraft() {
        if suffixDrafts.last?.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != true {
            suffixDrafts.append(DomainSuffixDraft(value: ""))
        }
    }

    private func save() {
        var seen = Set<String>()
        let reconciled = suffixDrafts.compactMap { draft -> DomainSuffixDraft? in
            let trimmed = draft.value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, seen.insert(trimmed).inserted else { return nil }
            var normalized = draft
            normalized.value = trimmed
            return normalized
        }
        if reconciled != suffixDrafts {
            suffixDrafts = reconciled
        }
        let suffixes = reconciled.map(\.value)
        if settings.syntheticAddressExcludedDomainSuffixes != suffixes {
            settings.syntheticAddressExcludedDomainSuffixes = suffixes
        }
    }
}
