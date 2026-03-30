//
//  LogListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import SwiftUI

struct LogListView: View {
    @ObservedObject private var logsModel = LogsModel.shared
    @State private var selection = Set<UUID>()
    @State private var editMode: EditMode = .inactive
    
    var body: some View {
        content
            .navigationTitle("Logs")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if editMode == .active {
                        Button(selection.isEmpty ? "Cancel" : "Copy (\(selection.count))") {
                            if selection.isEmpty {
                                editMode = .inactive
                            } else {
                                copySelected()
                                selection.removeAll()
                                editMode = .inactive
                            }
                        }
                    } else {
                        Button("Select") {
                            editMode = .active
                        }
                    }
                }
            }
            .onAppear { logsModel.startPolling() }
            .onDisappear { logsModel.stopPolling() }
    }
    
    @ViewBuilder
    private var content: some View {
        if logsModel.logs.isEmpty {
            ContentUnavailableView("No Recent Logs", systemImage: "checkmark.circle")
        } else {
            List(logsModel.logs.reversed(), selection: $selection) { entry in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: entry.level.iconName)
                        .foregroundStyle(entry.level.color)
                        .frame(width: 16)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(entry.message)
                            .font(.system(size: 10).monospaced())
                        Text(entry.timestamp, format: .dateTime.hour().minute().second())
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .contextMenu {
                    Button("Copy", systemImage: "doc.on.doc") {
                        UIPasteboard.general.string = entry.formatted
                    }
                }
            }
            .environment(\.editMode, $editMode)
            .onChange(of: editMode) {
                if editMode == .active {
                    logsModel.stopPolling(clearLogs: false)
                }
                if editMode == .inactive {
                    logsModel.startPolling()
                    selection.removeAll()
                }
            }
        }
    }

    private func copySelected() {
        let text = logsModel.logs
            .filter { selection.contains($0.id) }
            .map(\.formatted)
            .joined(separator: "\n")
        UIPasteboard.general.string = text
    }
}

extension LogsModel.LogEntry {
    var formatted: String {
        let time = timestamp.formatted(.dateTime.hour().minute().second())
        let level = switch level {
        case .info: "INFO"
        case .warning: "WARN"
        case .error: "ERROR"
        }
        return "\(time) [\(level)] \(message)"
    }
}

extension LogsModel.LogLevel {
    var iconName: String {
        switch self {
        case .info: "info.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .error: "xmark.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .info: .secondary
        case .warning: .orange
        case .error: .red
        }
    }
}
