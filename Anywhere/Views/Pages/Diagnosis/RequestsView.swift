//
//  RequestsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import SwiftUI

struct RequestsView: View {
    @State private var requestsModel = RequestsModel()
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @State private var selection = Set<UUID>()
    @State private var editMode: EditMode = .inactive

    var body: some View {
        let requests = requestsModel.requests
        List(requests.reversed(), selection: $selection) { entry in
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: icon(for: entry))
                    .foregroundStyle(.blue)
                    .frame(width: 16)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(alignment: .firstTextBaseline) {
                        Text("\(entry.host):\(String(entry.port))")
                            .font(.system(size: 12).monospaced())
                            .minimumScaleFactor(0.5)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer()
                        Text(entry.timestamp, format: .dateTime.hour().minute().second())
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                    HStack(spacing: 4) {
                        if let protocolLabel = label(for: entry.protocol) {
                            TagBadge(text: protocolLabel, color: .green)
                        }
                        TagBadge(text: label(for: entry), color: labelColor(for: entry))
                    }
                    if let detail = detailLine(for: entry) {
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
            }
            .contextMenu {
                Button("Copy", systemImage: "doc.on.doc") {
                    UIPasteboard.general.string = entry.host
                }
            }
        }
        .environment(\.editMode, $editMode)
        .animation(.default, value: requests)
        .overlay {
            if requests.isEmpty {
                ContentUnavailableView("No Recent Requests", systemImage: "network")
            }
        }
        .navigationTitle("Requests")
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
        .task(id: editMode) {
            guard editMode == .inactive else { return }
            selection.removeAll()
            while !Task.isCancelled {
                await requestsModel.poll()
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .onDisappear { requestsModel.clear() }
    }

    private func copySelected() {
        let text = requestsModel.requests
            .filter { selection.contains($0.id) }
            .map(\.host)
            .joined(separator: "\n")
        UIPasteboard.general.string = text
    }

    // MARK: - Row formatting

    private func icon(for entry: RequestsModel.Entry) -> String {
        switch entry.routeTarget {
        case .direct: "arrow.right.circle.fill"
        case .reject: "xmark.bin.circle.fill"
        case .proxy: entry.viaDefault ? "info.circle.fill" : "arrow.trianglehead.turn.up.right.circle.fill"
        }
    }
    
    private func label(for protocol: RequestsModel.Entry.`Protocol`) -> String? {
        switch `protocol` {
        case .tcp: String(localized: "TCP")
        case .udp: String(localized: "UDP")
        case .quic: String(localized: "QUIC")
        case .unknown: nil
        }
    }

    private func label(for entry: RequestsModel.Entry) -> String {
        switch entry.routeTarget {
        case .direct: String(localized: "DIRECT")
        case .reject: String(localized: "REJECT")
        case .proxy: entry.viaDefault ? String(localized: "Default") : String(localized: "Proxy")
        }
    }
    
    private func routeName(for entry: RequestsModel.Entry) -> String? {
        guard case .proxy = entry.routeTarget else { return nil }
        return entry.routeTarget.displayName(configStore: configStore, chainStore: chainStore)
    }

    private func labelColor(for entry: RequestsModel.Entry) -> Color {
        switch entry.routeTarget {
        case .direct: .green
        case .reject: .red
        case .proxy: entry.viaDefault ? .blue : .purple
        }
    }
    
    private func detailLine(for entry: RequestsModel.Entry) -> String? {
        let ruleSetName = entry.viaDefault ? nil : entry.ruleSetName
        let parts = [routeName(for: entry), ruleSetName].compactMap(\.self)
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}
