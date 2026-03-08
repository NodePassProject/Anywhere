//
//  ChainListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/8/26.
//

import SwiftUI

struct ChainListView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel

    @State private var showingAddSheet = false
    @State private var chainToEdit: ProxyChain?

    var body: some View {
        List {
            ForEach(viewModel.chains) { chain in
                chainRow(chain)
            }
        }
        .overlay {
            if viewModel.chains.isEmpty {
                ContentUnavailableView(
                    "No Chains",
                    systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill",
                    description: Text("Tap + to create a proxy chain.")
                )
            }
        }
        .navigationTitle("Chains")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                HStack(spacing: 8) {
                    Button {
                        viewModel.testAllChainLatencies()
                    } label: {
                        Label("Test All", systemImage: "gauge.with.dots.needle.67percent")
                    }

                    Button {
                        showingAddSheet = true
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                    .disabled(viewModel.configurations.count < 2)
                }
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            ChainEditorView { chain in
                viewModel.addChain(chain)
            }
        }
        .sheet(item: $chainToEdit) { chain in
            ChainEditorView(chain: chain) { updated in
                viewModel.updateChain(updated)
            }
        }
    }

    // MARK: - Chain Row

    @ViewBuilder
    private func chainRow(_ chain: ProxyChain) -> some View {
        let proxies = chain.proxyIds.compactMap { id in
            viewModel.configurations.first(where: { $0.id == id })
        }
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
        let isSelected = viewModel.selectedChainId == chain.id
        let latency = viewModel.chainLatencyResults[chain.id]

        Button {
            if isValid {
                viewModel.selectChain(chain)
            }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(chain.name)
                            .font(.body)
                        if isSelected {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }

                    if isValid {
                        // Route preview
                        HStack(spacing: 4) {
                            ForEach(Array(proxies.enumerated()), id: \.element.id) { index, proxy in
                                if index > 0 {
                                    Image(systemName: "arrow.right")
                                        .font(.system(size: 8))
                                }
                                Text(proxy.name)
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
                        Text("\(proxies.count) proxies")
                        if let entry = proxies.first, let exit = proxies.last, proxies.count >= 2 {
                            Text("·")
                            Text("\(entry.serverAddress) → \(exit.serverAddress)")
                                .lineLimit(1)
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                }

                Spacer()

                if isValid {
                    latencyView(latency)
                        .onTapGesture {
                            viewModel.testChainLatency(for: chain)
                        }
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .opacity(isValid ? 1 : 0.6)
        .contextMenu {
            if isValid {
                Button {
                    viewModel.testChainLatency(for: chain)
                } label: {
                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                }
            }

            Button {
                chainToEdit = chain
            } label: {
                Label("Edit", systemImage: "pencil")
            }

            Button(role: .destructive) {
                viewModel.deleteChain(chain)
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                viewModel.deleteChain(chain)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                chainToEdit = chain
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
    }

    // MARK: - Latency

    @ViewBuilder
    private func latencyView(_ latency: LatencyResult?) -> some View {
        switch latency {
        case .testing:
            ProgressView()
                .controlSize(.small)
                .frame(width: 50, alignment: .trailing)
        case .success(let ms):
            Text("\(ms) ms")
                .font(.caption)
                .monospacedDigit()
                .foregroundStyle(latencyColor(ms))
                .frame(minWidth: 50, alignment: .trailing)
        case .failed:
            Text("timeout")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(minWidth: 50, alignment: .trailing)
        case nil:
            EmptyView()
        }
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 300 { return .green }
        if ms < 600 { return .yellow }
        return .red
    }
}
