//
//  ReflectionSettingsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/31/26.
//

import SwiftUI

private struct ReflectionAddressDraft: Identifiable, Equatable {
    let id = UUID()
    var value: String
}

struct ReflectionSettingsView: View {
    @Environment(\.editMode) private var editMode

    @State private var enabled = AWCore.getReflectionEnabled()
    @State private var addressDrafts: [ReflectionAddressDraft] = []

    private var isEditing: Bool {
        editMode?.wrappedValue.isEditing == true
    }

    var body: some View {
        Form {
            Section {
                Toggle("Reflection", isOn: $enabled)
            } footer: {
                Text("Packets sent to a reflection address are returned to their sender instead of being routed or proxied.")
            }

            Section {
                if addressDrafts.isEmpty {
                    Text("None")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach($addressDrafts) { $draft in
                        if isEditing {
                            TextField("Address", text: $draft.value)
                                .keyboardType(.URL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                        } else {
                            Text(draft.value)
                        }
                    }
                    .onDelete { offsets in
                        addressDrafts.remove(atOffsets: offsets)
                        if editMode?.wrappedValue.isEditing != true {
                            save()
                        }
                    }
                    .onMove { source, destination in
                        addressDrafts.move(fromOffsets: source, toOffset: destination)
                        if editMode?.wrappedValue.isEditing != true {
                            save()
                        }
                    }
                }
            } header: {
                Text("Reflection Addresses")
            }
        }
        .navigationTitle("Reflection")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem {
                EditButton()
            }
        }
        .onAppear { loadInitial() }
        .onChange(of: enabled) { _, newValue in
            AWCore.setReflectionEnabled(newValue)
            AWCore.notifyTunnelSettingsChanged()
        }
        .onChange(of: isEditing) { _, newValue in
            if newValue {
                addressDrafts.append(ReflectionAddressDraft(value: ""))
            } else {
                save()
            }
        }
    }

    private func loadInitial() {
        enabled = AWCore.getReflectionEnabled()
        addressDrafts = AWCore.getReflectionAddresses().map { ReflectionAddressDraft(value: $0) }
    }

    private func save() {
        addressDrafts = addressDrafts
            .filter { !$0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let addresses = addressDrafts
            .map { $0.value.trimmingCharacters(in: .whitespacesAndNewlines) }
        AWCore.setReflectionAddresses(addresses)
        AWCore.notifyTunnelSettingsChanged()
    }
}
