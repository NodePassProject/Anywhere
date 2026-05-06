//
//  ImportMITMRulesView.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import SwiftUI

/// Sheet that parses pasted/downloaded text via ``MITMRuleParser`` and
/// hands the resulting rules back to the caller, which is responsible for
/// appending them to the editor's working copy.
struct ImportMITMRulesView: View {
    let onImport: ([MITMRule]) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var text = ""
    @State private var url = ""
    @State private var isDownloading = false
    @State private var downloadError: String?

    private var parsedMITMRules: [MITMRule] {
        MITMRuleParser.parse(text)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Rules") {
                    TextEditor(text: $text)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .font(.system(size: 12).monospaced())
                        .frame(minHeight: 200)
                }

                Section {
                    HStack {
                        TextField("Anywhere MITM Rule List URL", text: $url)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .keyboardType(.URL)
                            .textFieldStyle(.plain)
                        if #available(iOS 26.0, *) {
                            Button {
                                Task { await download() }
                            } label: {
                                VStack {
                                    if isDownloading {
                                        ProgressView()
                                    } else {
                                        Image(systemName: "checkmark")
                                            .accessibilityLabel("Download")
                                    }
                                }
                            }
                            .buttonBorderShape(.circle)
                            .buttonStyle(.glassProminent)
                            .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isDownloading)
                        } else {
                            Button {
                                Task { await download() }
                            } label: {
                                ZStack {
                                    Text("Download")
                                    if isDownloading {
                                        ProgressView()
                                    }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(url.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isDownloading)
                        }
                    }
                } header: {
                    Text("Download From Internet")
                } footer: {
                    if let downloadError {
                        Text(downloadError)
                            .foregroundStyle(.red)
                            .font(.caption)
                    }
                }

                let count = parsedMITMRules.count
                if count > 0 {
                    Section {
                        Text("\(count) rule(s)")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Import Rules")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    CancelButton("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    ConfirmButton("Import") {
                        onImport(parsedMITMRules)
                        dismiss()
                    }
                    .disabled(parsedMITMRules.isEmpty)
                }
            }
        }
    }

    private func download() async {
        let trimmed = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let requestURL = URL(string: trimmed) else {
            downloadError = String(localized: "Invalid URL.")
            return
        }
        isDownloading = true
        downloadError = nil
        do {
            let (data, response) = try await URLSession.shared.data(from: requestURL)
            if let httpResponse = response as? HTTPURLResponse,
               !(200...299).contains(httpResponse.statusCode) {
                downloadError = "HTTP \(httpResponse.statusCode)"
            } else if let body = String(data: data, encoding: .utf8) {
                text = body
            } else {
                downloadError = String(localized: "Unknown content.")
            }
        } catch {
            downloadError = error.localizedDescription
        }
        isDownloading = false
    }
}
