//
//  MITMRuleEditorView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import SwiftUI

struct MITMRuleEditorView: View {
    @Environment(\.dismiss) private var dismiss

    let rule: MITMRule?
    let onCommit: (MITMRule?) -> Void

    @State private var type: DomainRuleType = .domainSuffix
    @State private var value: String = ""

    var body: some View {
        Form {
            Picker("Type", selection: $type) {
                Text("Domain Suffix").tag(DomainRuleType.domainSuffix)
                Text("Domain Keyword").tag(DomainRuleType.domainKeyword)
            }
            TextField(placeholder, text: $value)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
        }
        .navigationTitle(rule == nil ? "Add Rule" : "Edit Rule")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") {
                    onCommit(nil)
                    dismiss()
                }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") {
                    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !trimmed.isEmpty else {
                        onCommit(nil)
                        dismiss()
                        return
                    }
                    let result = MITMRule(
                        id: rule?.id ?? UUID(),
                        type: type,
                        value: trimmed
                    )
                    onCommit(result)
                    dismiss()
                }
            }
        }
        .onAppear {
            if let rule {
                type = rule.type
                value = rule.value
            }
        }
    }

    private var placeholder: String {
        switch type {
        case .domainSuffix:  return "example.com"
        case .domainKeyword: return "tracking"
        default:             return ""
        }
    }
}
