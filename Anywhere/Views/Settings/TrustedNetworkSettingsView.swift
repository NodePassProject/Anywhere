//
//  TrustedNetworkSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/23/26.
//

import SwiftUI
import NetworkExtension

private struct TrustedSSIDDraft: Identifiable, Equatable {
    let id = UUID()
    var value: String
}

struct TrustedNetworkSettingsView: View {
    @Environment(\.editMode) private var editMode
    
    @State private var ssidDrafts: [TrustedSSIDDraft] = []
    @State private var currentSSID: String?
    
    private var isEditing: Bool { editMode?.wrappedValue.isEditing == true }
    
    private var trimmedSSIDs: [String] {
        ssidDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }
    
    var body: some View {
        @Bindable var settings = AppSettings.shared
        Form {
            Section {
                Toggle("Always Untrust Cellular", isOn: $settings.alwaysUntrustCellular)
            } footer: {
                Text("When using cellular data, enable Global Mode.")
            }
            
            Section {
                if ssidDrafts.isEmpty && !isEditing {
                    Text("No trusted SSIDs")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach($ssidDrafts) { $draft in
                        if isEditing {
                            TextField("SSID", text: $draft.value)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        } else {
                            Text(draft.value)
                        }
                    }
                    .onDelete { offsets in
                        ssidDrafts.remove(atOffsets: offsets)
                        if !isEditing { save() }
                    }
                    .onMove { source, destination in
                        ssidDrafts.move(fromOffsets: source, toOffset: destination)
                        if !isEditing { save() }
                    }
                }
                
                if isEditing {
                    Button {
                        withAnimation {
                            ssidDrafts.append(TrustedSSIDDraft(value: ""))
                        }
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
                
                if !isEditing, let currentSSID, !trimmedSSIDs.contains(currentSSID) {
                    Button {
                        withAnimation {
                            ssidDrafts.append(TrustedSSIDDraft(value: currentSSID))
                        }
                        save()
                    } label: {
                        Label("Add SSID “\(currentSSID)”", systemImage: "wifi")
                    }
                }
            } header: {
                Text("Trusted SSIDs")
            } footer: {
                Text("When connected to a trusted SSID, enable Direct Mode.")
            }
        }
        .navigationTitle("Trusted Network")
        .toolbar {
            ToolbarItem {
                EditButton()
            }
        }
        .onAppear {
            loadInitial()
            refreshCurrentSSID()
        }
        .onChange(of: isEditing) { _, newValue in
            if newValue == false {
                save()
            }
        }
    }
    
    private func loadInitial() {
        ssidDrafts = AppSettings.shared.trustedSSIDs.map { TrustedSSIDDraft(value: $0) }
    }
    
    private func save() {
        // Trim and drop empties/duplicates, reusing each draft's id so SwiftUI
        // doesn't re-render the surviving rows.
        var seen = Set<String>()
        let reconciled = ssidDrafts.compactMap { draft -> TrustedSSIDDraft? in
            let trimmed = draft.value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, seen.insert(trimmed).inserted else { return nil }
            var normalized = draft
            normalized.value = trimmed
            return normalized
        }
        ssidDrafts = reconciled
        AppSettings.shared.trustedSSIDs = reconciled.map(\.value)
    }
    
    private func refreshCurrentSSID() {
        NEHotspotNetwork.fetchCurrent { network in
            Task { @MainActor in
                currentSSID = network?.ssid
            }
        }
    }
}
