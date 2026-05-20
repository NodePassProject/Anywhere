//
//  MITMRuleEditorView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import SwiftUI

struct MITMRuleEditorView: View {
    @Environment(\.dismiss) private var dismiss

    let rule: MITMRule?
    let onCommit: (MITMRule?) -> Void

    @State private var phase: MITMPhase = .httpRequest
    @State private var operationKind: OperationKind = .headerAdd

    @State private var headerName: String = ""
    @State private var headerValue: String = ""
    @State private var pattern: String = ""
    @State private var replacement: String = ""

    @State private var validationError: String?

    private enum OperationKind: String, CaseIterable, Identifiable {
        case urlReplace
        case headerAdd
        case headerDelete
        case headerReplace

        var id: String { rawValue }
        var label: String {
            switch self {
            case .urlReplace:    return String(localized: "URL Replace")
            case .headerAdd:     return String(localized: "Header Add")
            case .headerDelete:  return String(localized: "Header Delete")
            case .headerReplace: return String(localized: "Header Replace")
            }
        }

        /// URL rewrites only make sense in the request phase. The editor
        /// hides the phase picker when this is true and pins phase to
        /// httpRequest at save time.
        var requestPhaseOnly: Bool {
            switch self {
            case .urlReplace: return true
            default:          return false
            }
        }
    }

    var body: some View {
        Form {
            if !operationKind.requestPhaseOnly {
                Section {
                    LabeledContent {
                        Picker("Phase", selection: $phase) {
                            Text("Request").tag(MITMPhase.httpRequest)
                            Text("Response").tag(MITMPhase.httpResponse)
                        }
                        .pickerStyle(.segmented)
                        .fixedSize()
                    } label: {
                        TextWithColorfulIcon(title: "Phase", comment: nil, systemName: "moonphase.last.quarter", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
            }

            Section {
                Picker(selection: $operationKind) {
                    ForEach(OperationKind.allCases) { kind in
                        Text(kind.label).tag(kind)
                    }
                } label: {
                    TextWithColorfulIcon(title: "Operation", comment: nil, systemName: "wrench.fill", foregroundColor: .white, backgroundColor: .purple)
                }
            }

            Section {
                LabeledContent {
                    TextField(String("^\\/anywhere$"), text: $pattern)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Pattern", comment: nil, systemName: "asterisk", foregroundColor: .white, backgroundColor: .gray)
                }

                switch operationKind {
                case .urlReplace:
                    LabeledContent {
                        TextField(String("/everywhere"), text: $replacement)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Replacement", comment: nil, systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                    }
                case .headerAdd:
                    LabeledContent {
                        TextField(String("User-Agent"), text: $headerName)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Header Name", comment: nil, systemName: "tag.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                    LabeledContent {
                        TextField(String("Anywhere"), text: $headerValue)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Header Value", comment: nil, systemName: "abc", foregroundColor: .white, backgroundColor: .gray)
                    }
                case .headerDelete:
                    LabeledContent {
                        TextField(String("User-Agent"), text: $headerName)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Header Name", comment: nil, systemName: "tag.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                case .headerReplace:
                    LabeledContent {
                        TextField(String("User-Agent"), text: $headerName)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Header Name", comment: nil, systemName: "tag.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                    LabeledContent {
                        TextField(String("Everywhere"), text: $headerValue)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Header Value", comment: nil, systemName: "abc", foregroundColor: .white, backgroundColor: .gray)
                    }
                }
            } footer: {
                if let validationError {
                    Text(validationError)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle(rule == nil ? "Add Rule" : "Edit Rule")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                ConfirmButton("Done") {
                    save()
                }
            }
            ToolbarItem(placement: .cancellationAction) {
                CancelButton("Cancel") {
                    onCommit(nil)
                    dismiss()
                }
            }
        }
        .onAppear { loadInitial() }
    }

    // MARK: - Save

    private func save() {
        // The URL pattern gates every operation, so validate it once up
        // front.
        guard !pattern.isEmpty else {
            validationError = String(localized: "Pattern is required.")
            return
        }
        guard (try? NSRegularExpression(pattern: pattern, options: [])) != nil else {
            validationError = String(localized: "Pattern is not a valid regular expression.")
            return
        }

        let operation: MITMOperation
        switch operationKind {
        case .urlReplace:
            operation = .urlReplace(path: replacement)
        case .headerAdd:
            let headerName = self.headerName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !headerName.isEmpty else {
                validationError = String(localized: "Header name is required.")
                return
            }
            operation = .headerAdd(name: headerName, value: headerValue)
        case .headerDelete:
            let name = headerName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !name.isEmpty else {
                validationError = String(localized: "Header name is required.")
                return
            }
            operation = .headerDelete(name: name)
        case .headerReplace:
            let headerName = self.headerName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !headerName.isEmpty else {
                validationError = String(localized: "Header name is required.")
                return
            }
            operation = .headerReplace(name: headerName, value: headerValue)
        }

        let result = MITMRule(
            id: rule?.id ?? UUID(),
            phase: operationKind.requestPhaseOnly ? .httpRequest : phase,
            pattern: pattern,
            operation: operation
        )
        onCommit(result)
        dismiss()
    }

    // MARK: - Load

    private func loadInitial() {
        guard let rule else { return }
        phase = rule.phase
        pattern = rule.pattern
        switch rule.operation {
        case .urlReplace(let replacement):
            operationKind = .urlReplace
            self.replacement = replacement
        case .headerAdd(let name, let value):
            operationKind = .headerAdd
            headerName = name
            headerValue = value
        case .headerDelete(let name):
            operationKind = .headerDelete
            headerName = name
        case .headerReplace(let name, let value):
            operationKind = .headerReplace
            self.headerName = name
            self.headerValue = value
        case .script, .streamScript:
            // Scripts are import-only; the detail view should never route
            // a script rule into this editor. Guard anyway so the
            // exhaustiveness check passes.
            break
        }
    }
}
