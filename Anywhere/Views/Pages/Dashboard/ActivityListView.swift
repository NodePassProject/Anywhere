//
//  ActivityListView.swift
//  Anywhere
//
//  Created by NodePassProject on 9/23/26.
//

import SwiftUI

struct ActivityListView: View {
    private let `protocol`: TunnelActivityProtocol
    private let emptyTitle: LocalizedStringKey
    private let emptySystemImage: String

    @Environment(TunnelController.self) private var tunnelController
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(ProxySelection.self) private var proxySelection: ProxySelection?
    @State private var model = ActivityModel()

    init(_ protocol: TunnelActivityProtocol, emptyTitle: LocalizedStringKey, emptySystemImage: String) {
        self.protocol = `protocol`
        self.emptyTitle = emptyTitle
        self.emptySystemImage = emptySystemImage
    }

    var body: some View {
        let active = model.active
        let closed = model.closed
        List {
            if !active.isEmpty {
                Section("Active") {
                    ForEach(active, content: row)
                }
            }
            if !closed.isEmpty {
                Section("Closed") {
                    ForEach(closed, content: row)
                }
            }
        }
        .animation(.default, value: active)
        .animation(.default, value: closed)
        .overlay {
            if !model.isLoaded {
                ProgressView()
            } else if active.isEmpty && closed.isEmpty {
                ContentUnavailableView(emptyTitle, systemImage: emptySystemImage)
            }
        }
        .task {
            while !Task.isCancelled {
                await model.poll(`protocol`, using: tunnelController)
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func row(for entry: ActivityModel.Entry) -> some View {
        ActivityRow(
            entry: entry,
            detail: detailLine(for: entry)
        )
        .contextMenu {
            Button("Copy Host", systemImage: "doc.on.doc") {
                UIPasteboard.general.string = entry.host
            }
        }
    }

    private func detailLine(for entry: ActivityModel.Entry) -> String? {
        let outboundName = entry.routeTarget.outboundName(
            defaultRouteTarget: entry.defaultRouteTarget,
            configStore: configStore,
            chainStore: chainStore,
            selection: proxySelection
        )
        let parts = [outboundName, entry.ruleSetName].compactMap(\.self)
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}

private struct ActivityRow: View {
    let entry: ActivityModel.Entry
    let detail: String?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            stateIndicator
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(verbatim: "\(entry.host):\(entry.port)")
                        .font(.system(size: 12).monospaced())
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    timeLabel
                        .font(.system(size: 12).monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                HStack(spacing: 4) {
                    TagBadge(text: entry.routeTarget.tagText, color: entry.routeTarget.tagColor)
                    if let detail {
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.tail)
                    }
                }
                HStack(spacing: 12) {
                    traffic(entry.bytesOut, systemImage: "arrow.up", imageColor: .cyan)
                    traffic(entry.bytesIn, systemImage: "arrow.down", imageColor: .blue)
                }
            }
        }
    }

    private var stateIndicator: some View {
        let (symbol, color): (String, Color) = switch entry.state {
        case .connecting: ("circle", .orange)
        case .established: ("circle.fill", .green)
        case .closed: ("circle.fill", .secondary)
        }
        return Image(systemName: symbol)
            .font(.system(size: 8))
            .foregroundStyle(color)
            .accessibilityHidden(true)
    }

    @ViewBuilder
    private var timeLabel: some View {
        if let endedAt = entry.endedAt {
            Text(endedAt, format: .dateTime.hour().minute().second())
        } else {
            Text(entry.startedAt, style: .timer)
        }
    }

    private func traffic(_ bytes: Int64, systemImage: String, imageColor: Color = .secondary) -> some View {
        HStack(spacing: 2) {
            Image(systemName: systemImage)
                .font(.system(size: 10))
                .fontWeight(.semibold)
                .foregroundStyle(imageColor)
            Text(Formatting.formatBytes(bytes))
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .contentTransition(.numericText())
        }
    }
}
