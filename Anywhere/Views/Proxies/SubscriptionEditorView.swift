//
//  SubscriptionEditorView.swift
//  Anywhere
//
//  Created by NodePassProject on 8/23/26.
//

import SwiftUI

struct SubscriptionEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(ConfigurationStore.self) private var configurationStore

    let subscription: Subscription
    var onSave: (String, [UUID]) -> Void

    @State private var name: String = ""
    @State private var configurationIds: [UUID] = []

    private var configurations: [ProxyConfiguration] {
        configurationIds.compactMap { id in
            configurationStore.configurations.first { $0.id == id }
        }
    }

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent {
                        TextField("Name", text: $name)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Name", systemName: "tag.fill", foregroundStyle: .white, backgroundStyle: .gray.gradient)
                    }
                }

                Section("Proxies") {
                    ForEach(configurations) { configuration in
                        Text(configuration.name)
                    }
                    .onMove { source, destination in
                        configurationIds.move(fromOffsets: source, toOffset: destination)
                    }
                }
            }
            .navigationTitle("Edit Subscription")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if #available(iOS 26.0, *) {
                        Button(role: .cancel) {
                            dismiss()
                        } label: {
                            Label("Cancel", systemImage: "xmark")
                        }
                    } else {
                        Button("Cancel") { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if #available(iOS 26.0, *) {
                        Button {
                            save()
                        } label: {
                            Label("Save", systemImage: "checkmark")
                        }
                        .disabled(!canSave)
                    } else {
                        Button("Save") { save() }
                            .disabled(!canSave)
                    }
                }
            }
            .environment(\.editMode, .constant(.active))
            .onAppear {
                name = subscription.name
                configurationIds = configurationStore.configurations(for: subscription).map(\.id)
            }
        }
    }

    private func save() {
        onSave(name.trimmingCharacters(in: .whitespaces), configurationIds)
        dismiss()
    }
}
