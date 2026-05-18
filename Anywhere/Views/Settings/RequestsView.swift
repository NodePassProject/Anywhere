//
//  RequestsView.swift
//  Anywhere
//
//  Created by NodePassProject on 5/18/26.
//

import SwiftUI

struct RequestsView: View {
    @ObservedObject private var requestsModel = RequestsModel.shared
    @State private var selection = Set<UUID>()
    @State private var editMode: EditMode = .inactive

    var body: some View {
        content
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
            .onAppear { requestsModel.startPolling() }
            .onDisappear { requestsModel.stopPolling() }
    }

    @ViewBuilder
    private var content: some View {
        if requestsModel.requests.isEmpty {
            ContentUnavailableView("No Recent Requests", systemImage: "network")
        } else {
            List(requestsModel.requests.reversed(), selection: $selection) { entry in
                HStack(alignment: .top, spacing: 8) {
                    Image(systemName: entry.action.iconName)
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
                            Text(entry.proto)
                            Text("·")
                            Text(entry.action.label)
                            if let name = entry.configurationName {
                                Text("·")
                                Text(name).lineLimit(1).truncationMode(.tail)
                            }
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
                .contextMenu {
                    Button("Copy", systemImage: "doc.on.doc") {
                        UIPasteboard.general.string = entry.host
                    }
                }
            }
            .environment(\.editMode, $editMode)
            .animation(.default, value: requestsModel.requests)
            .onChange(of: editMode) {
                if editMode == .active {
                    requestsModel.stopPolling(clearRequests: false)
                }
                if editMode == .inactive {
                    requestsModel.startPolling()
                    selection.removeAll()
                }
            }
        }
    }

    private func copySelected() {
        let text = requestsModel.requests
            .filter { selection.contains($0.id) }
            .map(\.host)
            .joined(separator: "\n")
        UIPasteboard.general.string = text
    }
}

extension TunnelRequestAction {
    var label: String {
        switch self {
        case .direct: String(localized: "DIRECT")
        case .reject: String(localized: "REJECT")
        case .proxy: String(localized: "Proxy")
        case .default: String(localized: "Default")
        }
    }
    
    var iconName: String {
        switch self {
        case .direct: "arrow.right.circle.fill"
        case .reject: "xmark.bin.circle.fill"
        case .proxy: "arrow.trianglehead.turn.up.right.circle.fill"
        case .default: "info.circle.fill"
        }
    }
}
