//
//  ChainListView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import SwiftUI

struct ChainListView: View {
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ChainStore.self) private var chainStore
    @Environment(ConfigurationStore.self) private var configStore
    private let coordinator = ChainRowCoordinator.shared

    @State private var showingAddSheet = false
    @State private var showingNotEnoughProxiesAlert = false
    @State private var chainToEdit: ProxyChain?

    var body: some View {
        List {
            ForEach(coordinator.models) { item in
                ChainRowView(
                    item: item,
                    onSelect: {
                        guard item.isValid, let chain = chain(item.id) else { return }
                        viewModel.selectChain(chain, configurations: configStore.configurations)
                    },
                    onTestLatency: {
                        guard let chain = chain(item.id) else { return }
                        viewModel.testChainLatency(for: chain, configurations: configStore.configurations)
                    },
                    onEdit: { chainToEdit = chain(item.id) },
                    onDelete: { if let chain = chain(item.id) { chainStore.delete(chain) } }
                )
            }
        }
        .overlay {
            if coordinator.models.isEmpty {
                ContentUnavailableView("No Chains", systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill")
            }
        }
        .navigationTitle("Chains")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    viewModel.testAllChainLatencies(chains: chainStore.chains, configurations: configStore.configurations)
                } label: {
                    Label("Test All", systemImage: "gauge.with.dots.needle.67percent")
                }
                Button {
                    if configStore.configurations.count < 2 {
                        showingNotEnoughProxiesAlert = true
                    } else {
                        showingAddSheet = true
                    }
                } label: {
                    Label("Add", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            ChainEditorView { chain in
                chainStore.add(chain)
            }
        }
        .sheet(item: $chainToEdit) { chain in
            ChainEditorView(chain: chain) { updated in
                chainStore.update(updated)
            }
        }
        .alert("Not Enough Proxies", isPresented: $showingNotEnoughProxiesAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("A proxy chain needs at least 2 proxies.")
        }
    }

    private func chain(_ id: UUID) -> ProxyChain? {
        chainStore.chains.first { $0.id == id }
    }
}

// MARK: - Chain Row

private struct ChainRowView: View {
    let item: ChainListItem
    let onSelect: () -> Void
    let onTestLatency: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(item.name)
                            .font(.body.weight(.medium))
                        if item.isSelected {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }

                    if item.isValid {
                        // Route preview
                        HStack(spacing: 4) {
                            ForEach(Array(item.proxyNames.enumerated()), id: \.offset) { index, proxyName in
                                if index > 0 {
                                    Image(systemName: "arrow.right")
                                        .font(.system(size: 8))
                                }
                                Text(proxyName)
                                    .lineLimit(1)
                            }
                        }
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    } else {
                        Text("Invalid chain — some proxies are missing")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }

                    HStack(spacing: 4) {
                        Text("\(item.proxyNames.count) proxie(s)")
                        if let entry = item.entryAddress, let exit = item.exitAddress {
                            Text("·")
                            Text("\(entry) → \(exit)")
                                .lineLimit(1)
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                }

                Spacer()

                if item.isValid {
                    LatencyLabel(latency: item.latency)
                        .onTapGesture(perform: onTestLatency)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(item.isValid ? 1 : 0.6)
        .contextMenu {
            if item.isValid {
                Button(action: onTestLatency) {
                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                }
            }
            Button(action: onEdit) {
                Label("Edit", systemImage: "pencil")
            }
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive, action: onDelete) {
                Label("Delete", systemImage: "trash")
            }
            Button(action: onEdit) {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
    }
}
