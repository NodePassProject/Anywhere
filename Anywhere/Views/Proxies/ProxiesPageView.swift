//
//  ProxiesPageView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

private enum ProxyType {
    case servers, chains
}

struct ProxiesPageView: View {
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(SubscriptionStore.self) private var subscriptionStore
    @Environment(ChainStore.self) private var chainStore
    private let coordinator = ProxyRowCoordinator.shared
    private let chainCoordinator = ChainRowCoordinator.shared

    @State private var proxyType: ProxyType = .servers
    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var showingChainAddSheet = false
    @State private var showingNotEnoughProxiesAlert = false
    @State private var configurationToEdit: ProxyConfiguration?
    @State private var chainToEdit: ProxyChain?
    @State private var updatingSubscription: Subscription?
    @State private var showingSubscriptionError = false
    @State private var subscriptionErrorMessage = ""
    @State private var collapsedSubscriptions: Set<UUID> = []
    @State private var renamingSubscription: Subscription?
    @State private var renameText = ""

    private var standaloneItems: [ProxyListItem] {
        coordinator.models.filter { $0.subscriptionId == nil }
    }

    private func items(for subscription: Subscription) -> [ProxyListItem] {
        coordinator.models.filter { $0.subscriptionId == subscription.id }
    }

    var body: some View {
        List {
            if proxyType == .servers {
                Section {
                    ForEach(standaloneItems) { item in
                        proxyRow(item, editingDisabled: false)
                    }
                }
                ForEach(subscriptionStore.subscriptions) { subscription in
                    let editingDisabled = SubscriptionDomainHelper.shouldDisableProxyEditing(for: subscription.url)
                    Section {
                        DisclosureGroup(isExpanded: expansionBinding(for: subscription)) {
                            ForEach(items(for: subscription)) { item in
                                proxyRow(item, editingDisabled: editingDisabled)
                            }
                        } label: {
                            subscriptionLabel(subscription)
                        }
                    }
                }
            } else {
                ForEach(chainCoordinator.models) { item in
                    chainRow(item)
                }
            }
        }
        .overlay {
            if proxyType == .servers, configStore.configurations.isEmpty {
                ContentUnavailableView("No Proxies", systemImage: "network")
            } else if proxyType == .chains, chainCoordinator.models.isEmpty {
                ContentUnavailableView("No Chains", systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill")
            }
        }
        .navigationTitle("Proxies")
        .toolbar {
            ToolbarItem {
                Button {
                    switch proxyType {
                    case .servers:
                        showingAddSheet = true
                    case .chains:
                        if configStore.configurations.count < 2 {
                            showingNotEnoughProxiesAlert = true
                        } else {
                            showingChainAddSheet = true
                        }
                    }
                } label: {
                    Label("Add", systemImage: "plus")
                }
            }
            
            ToolbarItem {
                Menu("More", systemImage: "ellipsis") {
                    Section {
                        Picker("Proxy Type", selection: $proxyType) {
                            Label("Servers", systemImage: "server.rack")
                                .tag(ProxyType.servers)
                            Label("Chains", systemImage:  "point.bottomleft.forward.to.point.topright.scurvepath.fill")
                                .tag(ProxyType.chains)
                        }
                    }
                    Section {
                        Button {
                            switch proxyType {
                            case .servers:
                                let liveSubscriptionIds = Set(subscriptionStore.subscriptions.map(\.id))
                                let visible = configStore.configurations.filter { configuration in
                                    guard let subscriptionId = configuration.subscriptionId else { return true }
                                    return liveSubscriptionIds.contains(subscriptionId) && !collapsedSubscriptions.contains(subscriptionId)
                                }
                                viewModel.testLatencies(for: visible)
                            case .chains:
                                viewModel.testAllChainLatencies(chains: chainStore.chains, configurations: configStore.configurations)
                            }
                        } label: {
                            Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                        }
                        
                        if standaloneItems.count > 1 || subscriptionStore.subscriptions.count > 1 || chainStore.chains.count > 1 {
                            NavigationLink {
                                ReorderProxiesView()
                            } label: {
                                Label("Reorder", systemImage: "arrow.up.arrow.down")
                            }
                        }
                    }
                    if !subscriptionStore.subscriptions.isEmpty {
                        Section {
                            Button {
                                updateAllSubscriptions()
                            } label: {
                                Label("Update", systemImage: "arrow.clockwise")
                            }
                        }
                    }
                }
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet)
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                configStore.add(configuration); viewModel.selectIfNone(configuration)
            }
        }
        .sheet(isPresented: $showingChainAddSheet) {
            ChainEditorView { chain in
                chainStore.add(chain)
            }
        }
        .sheet(item: $configurationToEdit) { configuration in
            ProxyEditorView(configuration: configuration) { updated in
                configStore.update(updated)
            }
        }
        .sheet(item: $chainToEdit) { chain in
            ChainEditorView(chain: chain) { updated in
                chainStore.update(updated)
            }
        }
        .alert("Update Failed", isPresented: $showingSubscriptionError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(subscriptionErrorMessage)
        }
        .alert("Not Enough Proxies", isPresented: $showingNotEnoughProxiesAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("A proxy chain needs at least 2 proxies.")
        }
        .alert("Rename", isPresented: Binding(get: { renamingSubscription != nil }, set: { if !$0 { renamingSubscription = nil } })) {
            TextField("Name", text: $renameText)
            Button("OK") {
                if let subscription = renamingSubscription, !renameText.isEmpty {
                    subscriptionStore.rename(subscription, to: renameText)
                }
            }
            Button("Cancel", role: .cancel) { }
        }
        .onAppear {
            collapsedSubscriptions = Set(subscriptionStore.subscriptions.filter(\.collapsed).map(\.id))
        }
    }

    // MARK: - Subscription Header
    
    private func expansionBinding(for subscription: Subscription) -> Binding<Bool> {
        Binding(
            get: { !collapsedSubscriptions.contains(subscription.id) },
            set: { expanded in
                if expanded {
                    collapsedSubscriptions.remove(subscription.id)
                } else {
                    collapsedSubscriptions.insert(subscription.id)
                }
                if subscription.collapsed == expanded {
                    subscriptionStore.toggleCollapsed(subscription)
                }
            }
        )
    }

    @ViewBuilder
    private func subscriptionLabel(_ subscription: Subscription) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(subscription.name)
                    .font(.body.weight(.medium))
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
            SubscriptionUsageView(subscription: subscription)
        }
        .padding(.trailing, 10)
        .swipeActions {
            Button(role: .destructive) {
                subscriptionStore.delete(subscription)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                updateSubscription(subscription)
            } label: {
                Label("Update", systemImage: "arrow.clockwise")
            }
            .tint(.blue)
            Button {
                renameText = subscription.name
                renamingSubscription = subscription
            } label: {
                Label("Rename", systemImage: "pencil")
            }
        }
        .contextMenu {
            Section {
                Button {
                    viewModel.testLatencies(for: configStore.configurations(for: subscription))
                } label: {
                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                }
            }
            Section {
                Button {
                    renameText = subscription.name
                    renamingSubscription = subscription
                } label: {
                    Label("Rename", systemImage: "pencil")
                }
                Button {
                    updateSubscription(subscription)
                } label: {
                    Label("Update", systemImage: "arrow.clockwise")
                }
                Button(role: .destructive) {
                    subscriptionStore.delete(subscription)
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
    }

    // MARK: - Formatting

    private func updateSubscription(_ subscription: Subscription) {
        guard updatingSubscription == nil else { return }
        updatingSubscription = subscription
        Task {
            do {
                try await subscriptionStore.refresh(subscription)
            } catch {
                subscriptionErrorMessage = error.localizedDescription
                showingSubscriptionError = true
            }
            updatingSubscription = nil
        }
    }

    private func updateAllSubscriptions() {
        guard updatingSubscription == nil else { return }
        Task {
            var failures: [String] = []
            for id in subscriptionStore.subscriptions.map(\.id) {
                guard let subscription = subscriptionStore.subscriptions.first(where: { $0.id == id }) else { continue }
                updatingSubscription = subscription
                do {
                    try await subscriptionStore.refresh(subscription)
                } catch {
                    failures.append("\(subscription.name): \(error.localizedDescription)")
                }
            }
            updatingSubscription = nil
            if !failures.isEmpty {
                subscriptionErrorMessage = failures.joined(separator: "\n")
                showingSubscriptionError = true
            }
        }
    }

    // MARK: - Rows

    private func config(_ id: UUID) -> ProxyConfiguration? {
        configStore.configurations.first { $0.id == id }
    }

    @ViewBuilder
    private func proxyRow(_ item: ProxyListItem, editingDisabled: Bool) -> some View {
        ProxyRowView(
            item: item,
            editingDisabled: editingDisabled,
            onSelect: { if let configuration = config(item.id) { viewModel.selectedConfiguration = configuration } },
            onTestLatency: { if let configuration = config(item.id) { viewModel.testLatency(for: configuration) } },
            onCopyLink: { if let configuration = config(item.id) { UIPasteboard.general.string = configuration.toURL() } },
            onEdit: { configurationToEdit = config(item.id) },
            onDelete: { if let configuration = config(item.id) { configStore.delete(configuration) } }
        )
    }

    private func chain(_ id: UUID) -> ProxyChain? {
        chainStore.chains.first { $0.id == id }
    }

    @ViewBuilder
    private func chainRow(_ item: ChainListItem) -> some View {
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

private struct SubscriptionUsageView: View {
    let subscription: Subscription

    private static let byteFormatter: ByteCountFormatter = {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        formatter.allowsNonnumericFormatting = false
        return formatter
    }()
    
    private var totalBytes: Int64? {
        guard let total = subscription.total, total > 0 else { return nil }
        return total
    }

    private var usedBytes: Int64? {
        guard subscription.upload != nil || subscription.download != nil else { return nil }
        return (subscription.upload ?? 0) + (subscription.download ?? 0)
    }

    private var usedFraction: Double? {
        guard let usedBytes, let totalBytes else { return nil }
        return Double(usedBytes) / Double(totalBytes)
    }

    var body: some View {
        if usageDescription != nil || subscription.expire != nil {
            HStack(spacing: 5) {
                if let usedFraction {
                    UsageRing(fraction: usedFraction)
                }
                if let usageDescription, let expire = subscription.expire {
                    Text([usageDescription, expireDescription(expire)].joined(separator: " · "))
                } else if let usageDescription {
                    Text(usageDescription)
                } else if let expire = subscription.expire {
                    Text(expireDescription(expire))
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }
    
    private struct UsageRing: View {
        let fraction: Double

        var body: some View {
            ZStack {
                Circle()
                    .inset(by: 1)
                    .stroke(.quaternary, lineWidth: 2)
                Circle()
                    .inset(by: 1)
                    .trim(from: 0, to: max(0.03, min(fraction, 1)))
                    .stroke(usageWarningColor(for: fraction), style: StrokeStyle(lineWidth: 2, lineCap: .round))
                    .rotationEffect(.degrees(-90))
            }
            .frame(width: 12, height: 12)
            .animation(.snappy(duration: 0.3, extraBounce: 0), value: fraction)
        }
        
        private func usageWarningColor(for fraction: Double) -> Color {
            if fraction >= 0.95 {
                .red
            } else if fraction >= 0.8 {
                .orange
            } else {
                .blue
            }
        }
    }
    
    private var usageDescription: String? {
        switch (usedBytes, totalBytes) {
        case let (used?, total?):
            String(localized: "\(Self.byteFormatter.string(fromByteCount: used)) of \(Self.byteFormatter.string(fromByteCount: total)) used")
        case let (used?, nil):
            String(localized: "\(Self.byteFormatter.string(fromByteCount: used)) used")
        case let (nil, total?):
            String(localized: "\(Self.byteFormatter.string(fromByteCount: total)) total")
        case (nil, nil):
            nil
        }
    }
    
    private func expireDescription(_ expire: Date) -> String {
        let calendar = Calendar.current
        let days = calendar.dateComponents(
            [.day],
            from: calendar.startOfDay(for: .now),
            to: calendar.startOfDay(for: expire)
        ).day ?? 0
        if expire < .now {
            return String(localized: "Expired")
        } else {
            return String(localized: "Expires in \(days) day(s)")
        }
    }
}
