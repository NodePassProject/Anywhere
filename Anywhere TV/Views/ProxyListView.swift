//
//  ProxyListView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/14/26.
//

import SwiftUI
import NetworkExtension

struct ProxyListView: View {
    @ObservedObject private var viewModel = VPNViewModel.shared

    @State private var showingAddSheet = false
    @State private var updatingSubscription: Subscription?
    @State private var showingSubscriptionError = false
    @State private var subscriptionErrorMessage = ""
    @State private var renamingConfiguration: ProxyConfiguration?
    @State private var renameText = ""

    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configurations = viewModel.configurations(for: subscription)
            return configurations.isEmpty ? nil : (subscription, configurations)
        }
    }

    var body: some View {
        List {
            if !standaloneConfigurations.isEmpty {
                Section {
                    ForEach(standaloneConfigurations) { configuration in
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
                ContentUnavailableView("No Proxies", systemImage: "network")
            }
        }
        .navigationTitle("Proxies")
        .toolbar {
            ToolbarItem {
                Button {
                    viewModel.testAllLatencies()
                } label: {
                    Image(systemName: "gauge.with.dots.needle.67percent")
                        .accessibilityLabel("Test All")
                }
            }
            ToolbarItem {
                Button {
                    showingAddSheet = true
                } label: {
                    Image(systemName: "plus")
                        .accessibilityLabel("Add")
                }
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            NavigationStack {
                AddProxyView { configuration in
                    viewModel.addConfiguration(configuration)
                } onSubscriptionImport: { configurations, subscription in
                    viewModel.addSubscription(configurations: configurations, subscription: subscription)
                }
            }
        }
        .alert("Update Failed", isPresented: $showingSubscriptionError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(subscriptionErrorMessage)
        }
        .alert("Rename", isPresented: Binding(
            get: { renamingConfiguration != nil },
            set: { if !$0 { renamingConfiguration = nil } }
        )) {
            TextField("Name", text: $renameText)
            Button("Cancel", role: .cancel) {
                renamingConfiguration = nil
            }
            Button("Done") {
                if let config = renamingConfiguration {
                    let trimmed = renameText.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty {
                        let renamed = ProxyConfiguration(
                            id: config.id, name: trimmed,
                            serverAddress: config.serverAddress, serverPort: config.serverPort,
                            uuid: config.uuid, encryption: config.encryption,
                            transport: config.transport, flow: config.flow,
                            security: config.security, tls: config.tls, reality: config.reality,
                            websocket: config.websocket, httpUpgrade: config.httpUpgrade,
                            xhttp: config.xhttp, testseed: config.testseed,
                            muxEnabled: config.muxEnabled, xudpEnabled: config.xudpEnabled,
                            subscriptionId: config.subscriptionId,
                            outboundProtocol: config.outboundProtocol,
                            ssPassword: config.ssPassword, ssMethod: config.ssMethod
                        )
                        viewModel.updateConfiguration(renamed)
                    }
                    renamingConfiguration = nil
                }
            }
        } message: {
            Text("Provide a new name.")
        }
    }

    // MARK: - Subscription Header

    @ViewBuilder
    private func subscriptionHeader(_ subscription: Subscription) -> some View {
        HStack {
            Text(subscription.name)
            Spacer()
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
    private func configurationRow(_ configuration: ProxyConfiguration) -> some View {
        let latency = viewModel.latencyResults[configuration.id]

        Button {
            viewModel.selectedConfiguration = configuration
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
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
                        .lineLimit(1)
                    HStack(spacing: 4) {
                        Text(configuration.outboundProtocol.name)
                        Text("·")
                        Text(configuration.transport.uppercased())
                        let security = configuration.security.uppercased()
                        if security != "NONE" {
                            Text("·")
                            Text(security)
                        }
                        if let flow = configuration.flow, flow.uppercased().contains("VISION") {
                            Text("·")
                            Text("Vision")
                        }
                    }
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                }

                Spacer()

                latencyView(latency)
            }
            .contentShape(Rectangle())
        }
        .contextMenu {
            Button {
                viewModel.testLatency(for: configuration)
            } label: {
                Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
            }

            Button {
                renameText = configuration.name
                renamingConfiguration = configuration
            } label: {
                Label("Rename", systemImage: "pencil")
            }

            Button(role: .destructive) {
                viewModel.deleteConfiguration(configuration)
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
    }

    @ViewBuilder
    private func latencyView(_ latency: LatencyResult?) -> some View {
        switch latency {
        case .testing:
            ProgressView()
                .controlSize(.small)
                .frame(width: 80, alignment: .trailing)
        case .success(let ms):
            Text("\(ms) ms")
                .font(.callout)
                .monospacedDigit()
                .foregroundStyle(latencyColor(ms))
                .frame(minWidth: 80, alignment: .trailing)
        case .failed:
            Text("timeout")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(minWidth: 80, alignment: .trailing)
        case .insecure:
            Text("insecure")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(minWidth: 80, alignment: .trailing)
        case nil:
            EmptyView()
        }
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 300 { return .green }
        if ms < 500 { return .yellow }
        return .red
    }
}
