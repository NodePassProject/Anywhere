//
//  ProxyListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct ProxyListView: View {
    @Environment(VPNViewModel.self) private var viewModel: VPNViewModel

    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var configurationToEdit: VLESSConfiguration?
    @State private var updatingSubscription: Subscription?
    @State private var showingSubscriptionError = false
    @State private var subscriptionErrorMessage = ""

    private var standaloneConfigs: [VLESSConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [VLESSConfiguration])] {
        viewModel.subscriptions.compactMap { sub in
            let configs = viewModel.configurations(for: sub)
            return configs.isEmpty ? nil : (sub, configs)
        }
    }

    var body: some View {
        List {
            if !standaloneConfigs.isEmpty {
                Section {
                    ForEach(standaloneConfigs) { configuration in
                        configurationRow(configuration)
                    }
                }
            }
            ForEach(subscribedGroups, id: \.0.id) { subscription, configurations in
                Section {
                    ForEach(configurations) { configuration in
                        configurationRow(configuration)
                    }
                } header: {
                    subscriptionHeader(subscription)
                }
            }
        }
        .overlay {
            if viewModel.configurations.isEmpty {
                ContentUnavailableView(
                    "No Proxies",
                    systemImage: "network.slash",
                    description: Text("Tap + to add a VLESS proxy.")
                )
            }
        }
        .navigationTitle("Proxies")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                HStack(spacing: 12) {
                    Button {
                        viewModel.testAllLatencies()
                    } label: {
                        Label("Test All", systemImage: "gauge.with.dots.needle.67percent")
                    }

                    Button {
                        showingAddSheet = true
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet) { configuration in
                    viewModel.addConfiguration(configuration)
                } onSubscriptionImport: { configurations, subscription in
                    viewModel.addSubscription(configurations: configurations, subscription: subscription)
                }
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                viewModel.addConfiguration(configuration)
            }
        }
        .sheet(item: $configurationToEdit) { configuration in
            ProxyEditorView(configuration: configuration) { updated in
                viewModel.updateConfiguration(updated)
            }
        }
        .alert("Update Failed", isPresented: $showingSubscriptionError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(subscriptionErrorMessage)
        }
    }

    // MARK: - Subscription Header

    @ViewBuilder
    private func subscriptionHeader(_ subscription: Subscription) -> some View {
        HStack {
            Text(subscription.name)
            Spacer()
            HStack(spacing: 20) {
                if updatingSubscription?.id == subscription.id {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Button {
                        updateSubscription(subscription)
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                    .buttonStyle(.borderless)
                }
                Menu {
                    Button {
                        updateSubscription(subscription)
                    } label: {
                        Label("Update", systemImage: "arrow.clockwise")
                    }
                    Button(role: .destructive) {
                        viewModel.deleteSubscription(subscription)
                    } label: {
                        Label("Delete", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .buttonStyle(.borderless)
            }
        }
    }

    private func updateSubscription(_ subscription: Subscription) {
        guard updatingSubscription == nil else { return }
        updatingSubscription = subscription
        Task {
            do {
                try await viewModel.updateSubscription(subscription)
            } catch {
                subscriptionErrorMessage = error.localizedDescription
                showingSubscriptionError = true
            }
            updatingSubscription = nil
        }
    }

    // MARK: - Config Row

    @ViewBuilder
    private func configurationRow(_ configuration: VLESSConfiguration) -> some View {
        let latency = viewModel.latencyResults[configuration.id]

        Button {
            viewModel.selectedConfiguration = configuration
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(configuration.name)
                            .font(.body)
                        if viewModel.selectedConfiguration?.id == configuration.id {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }
                    Text("\(configuration.serverAddress):\(configuration.serverPort, format: .number.grouping(.never))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    HStack(spacing: 4) {
                        Text(configuration.transport.uppercased())
                        Text("·")
                        Text(configuration.security.uppercased())
                        if let flow = configuration.flow, flow.contains("vision") {
                            Text("·")
                            Text("Vision")
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                }
                
                Spacer()
                
                latencyView(latency)
                    .onTapGesture {
                        if viewModel.vpnStatus != .connected {
                            viewModel.testLatency(for: configuration)
                        }
                    }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button {
                viewModel.testLatency(for: configuration)
            } label: {
                Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
            }

            Button {
                configurationToEdit = configuration
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            
            Button(role: .destructive) {
                viewModel.deleteConfiguration(configuration)
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                viewModel.deleteConfiguration(configuration)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                configurationToEdit = configuration
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
    }

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
