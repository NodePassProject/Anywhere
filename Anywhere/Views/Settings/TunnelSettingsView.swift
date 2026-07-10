//
//  TunnelSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import SwiftUI

private struct RouteDraft: Identifiable, Equatable {
    let id = UUID()
    var value: String
}

struct TunnelSettingsView: View {
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(\.editMode) private var editMode

    @State private var includedRouteDrafts: [RouteDraft] = []
    @State private var excludedRouteDrafts: [RouteDraft] = []

    private var isEditing: Bool {
        editMode?.wrappedValue.isEditing == true
    }

    var body: some View {
        @Bindable var settings = AppSettings.shared
        Form {
            Section {
                Toggle("Include All Networks", isOn: $settings.includeAllNetworks)
            }

            Section {
                Toggle("Include Local Networks", isOn: $settings.includeLocalNetworks)
                Toggle("Include APNs", isOn: $settings.includeAPNs)
                Toggle("Include Cellular Services", isOn: $settings.includeCellularServices)
            }
            .disabled(!settings.includeAllNetworks)

            Section {
                routeRows($includedRouteDrafts)
            } header: {
                Text("Included Routes")
            }

            Section {
                routeRows($excludedRouteDrafts)
            } header: {
                Text("Excluded Routes")
            }
        }
        .navigationTitle("Tunnel")
        .toolbar {
            ToolbarItem {
                EditButton()
            }
        }
        .onAppear { loadInitial() }
        .onChange(of: isEditing) { _, newValue in
            if newValue {
                includedRouteDrafts.append(RouteDraft(value: ""))
                excludedRouteDrafts.append(RouteDraft(value: ""))
            } else {
                save()
            }
        }
        .disabled(viewModel.pendingReconnect)
    }

    @ViewBuilder
    private func routeRows(_ drafts: Binding<[RouteDraft]>) -> some View {
        if drafts.wrappedValue.isEmpty {
            Text("None")
                .foregroundStyle(.secondary)
        } else {
            ForEach(drafts) { $draft in
                if isEditing {
                    TextField(String("198.51.100.0/24"), text: $draft.value)
                        .keyboardType(.numbersAndPunctuation)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                } else {
                    Text(draft.value)
                }
            }
            .onDelete { offsets in
                drafts.wrappedValue.remove(atOffsets: offsets)
                if !isEditing {
                    save()
                }
            }
            .onMove { source, destination in
                drafts.wrappedValue.move(fromOffsets: source, toOffset: destination)
                if !isEditing {
                    save()
                }
            }
        }
    }

    private func loadInitial() {
        includedRouteDrafts = AppSettings.shared.tunnelIncludedRoutes.map { RouteDraft(value: $0) }
        excludedRouteDrafts = AppSettings.shared.tunnelExcludedRoutes.map { RouteDraft(value: $0) }
    }

    private func save() {
        includedRouteDrafts = includedRouteDrafts
            .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        excludedRouteDrafts = excludedRouteDrafts
            .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        AppSettings.shared.tunnelIncludedRoutes = includedRouteDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }
        AppSettings.shared.tunnelExcludedRoutes = excludedRouteDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }
    }
}
