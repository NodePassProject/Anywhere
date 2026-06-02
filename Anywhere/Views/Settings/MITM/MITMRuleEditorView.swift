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
    @State private var urlPattern: String = ""
    @State private var replacement: String = ""
    @State private var searchText: String = ""
    @State private var rewriteMode: RewriteMode = .transparent
    @State private var rewriteURL: String = ""
    @State private var rejectText: String = ""
    @State private var rejectData: String = ""

    @State private var validationError: String?

    private enum OperationKind: String, CaseIterable, Identifiable {
        case rewrite
        case headerAdd
        case headerDelete
        case headerReplace
        case bodyReplace

        var id: String { rawValue }
        var label: String {
            switch self {
            case .rewrite:       return String(localized: "Rewrite")
            case .headerAdd:     return String(localized: "Header Add")
            case .headerDelete:  return String(localized: "Header Delete")
            case .headerReplace: return String(localized: "Header Replace")
            case .bodyReplace:   return String(localized: "Body Replace")
            }
        }

        /// The Rewrite operation only makes sense in the request phase. The
        /// editor hides the phase picker when this is true and pins phase to
        /// httpRequest at save time.
        var requestPhaseOnly: Bool {
            switch self {
            case .rewrite: return true
            default:       return false
            }
        }
    }

    /// Sub-mode of the unified "Rewrite" operation (matches the import
    /// sub-mode ids `0`–`4`).
    private enum RewriteMode: String, CaseIterable, Identifiable {
        case transparent
        case redirect302
        case reject200Text
        case reject200Gif
        case reject200Data

        var id: String { rawValue }
        var label: String {
            switch self {
            case .transparent:   return String(localized: "Transparent")
            case .redirect302:   return String(localized: "302 Redirect")
            case .reject200Text: return String(localized: "Reject Text")
            case .reject200Gif:  return String(localized: "Reject GIF")
            case .reject200Data: return String(localized: "Reject Data")
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
                    TextField(String("^https://argsment\\.com/"), text: $urlPattern)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "URL Pattern", comment: nil, systemName: "asterisk", foregroundColor: .white, backgroundColor: .gray)
                }

                switch operationKind {
                case .rewrite:
                    Picker(selection: $rewriteMode) {
                        ForEach(RewriteMode.allCases) { mode in
                            Text(mode.label).tag(mode)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Mode", comment: nil, systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .purple)
                    }
                    switch rewriteMode {
                    case .transparent, .redirect302:
                        LabeledContent {
                            TextField(String("https://argsment.com/anywhere"), text: $rewriteURL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(title: "URL", comment: nil, systemName: "link", foregroundColor: .white, backgroundColor: .blue)
                        }
                    case .reject200Text:
                        LabeledContent {
                            TextField(String("Success from Anywhere"), text: $rejectText)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(title: "Body", comment: nil, systemName: "text.cursor", foregroundColor: .white, backgroundColor: .gray)
                        }
                    case .reject200Gif:
                        EmptyView()
                    case .reject200Data:
                        LabeledContent {
                            TextField(String("QW55d2hlcmU="), text: $rejectData)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(title: "Data (Base64)", comment: nil, systemName: "cylinder.split.1x2.fill", foregroundColor: .white, backgroundColor: .gray)
                        }
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
                        TextWithColorfulIcon(title: "Header Value", comment: nil, systemName: "text.cursor", foregroundColor: .white, backgroundColor: .gray)
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
                        TextWithColorfulIcon(title: "Header Value", comment: nil, systemName: "text.cursor", foregroundColor: .white, backgroundColor: .gray)
                    }
                case .bodyReplace:
                    LabeledContent {
                        TextField(String("Anywhere"), text: $searchText)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Search", comment: nil, systemName: "magnifyingglass", foregroundColor: .white, backgroundColor: .gray)
                    }
                    LabeledContent {
                        TextField(String("Everywhere"), text: $replacement)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Replacement", comment: nil, systemName: "text.cursor", foregroundColor: .white, backgroundColor: .gray)
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
        guard !urlPattern.isEmpty else {
            validationError = String(localized: "URL Pattern is required.")
            return
        }
        guard (try? NSRegularExpression(pattern: urlPattern, options: [])) != nil else {
            validationError = String(localized: "URL Pattern is not a valid regular expression.")
            return
        }

        let operation: MITMOperation
        switch operationKind {
        case .rewrite:
            switch rewriteMode {
            case .transparent, .redirect302:
                let url = rewriteURL.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !url.isEmpty else {
                    validationError = String(localized: "URL is required.")
                    return
                }
                guard let comps = URLComponents(string: url),
                      let host = comps.host, !host.isEmpty else {
                    validationError = String(localized: "URL is not valid.")
                    return
                }
                operation = .rewrite(rewriteMode == .transparent
                    ? .transparent(url: url)
                    : .redirect302(url: url))
            case .reject200Text:
                operation = .rewrite(.reject200Text(content: rejectText))
            case .reject200Gif:
                operation = .rewrite(.reject200Gif)
            case .reject200Data:
                operation = .rewrite(.reject200Data(base64: rejectData))
            }
        case .bodyReplace:
            guard !searchText.isEmpty else {
                validationError = String(localized: "Search is required.")
                return
            }
            guard (try? Regex(searchText)) != nil else {
                validationError = String(localized: "Search is not a valid regular expression.")
                return
            }
            operation = .bodyReplace(search: searchText, replacement: replacement)
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
            urlPattern: urlPattern,
            operation: operation
        )
        onCommit(result)
        dismiss()
    }

    // MARK: - Load

    private func loadInitial() {
        guard let rule else { return }
        phase = rule.phase
        urlPattern = rule.urlPattern
        switch rule.operation {
        case .rewrite(let action):
            operationKind = .rewrite
            switch action {
            case .transparent(let url):
                rewriteMode = .transparent
                rewriteURL = url
            case .redirect302(let url):
                rewriteMode = .redirect302
                rewriteURL = url
            case .reject200Text(let content):
                rewriteMode = .reject200Text
                rejectText = content
            case .reject200Gif:
                rewriteMode = .reject200Gif
            case .reject200Data(let base64):
                rewriteMode = .reject200Data
                rejectData = base64
            }
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
        case .bodyReplace(let search, let replacement):
            operationKind = .bodyReplace
            self.searchText = search
            self.replacement = replacement
        case .script, .streamScript, .bodyJSON:
            // Scripts and native JSON-body edits are import-only; the
            // detail view should never route one of these into this editor.
            // Guard anyway so the exhaustiveness check passes.
            break
        }
    }
}
