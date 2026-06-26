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
            ToolbarItemGroup(placement: .principal) {
                Picker("Proxy Type", selection: $proxyType) {
                    Image(systemName: "server.rack")
                        .tag(ProxyType.servers)
                    Image(systemName: "point.bottomleft.forward.to.point.topright.scurvepath.fill")
                        .tag(ProxyType.chains)
                }
                .pickerStyle(.segmented)
            }
            
            if standaloneItems.count > 1 || subscriptionStore.subscriptions.count > 1 || chainStore.chains.count > 1 {
//                if #available(iOS 27.0, *) {
//                    ToolbarItemGroup {
//                        NavigationLink {
//                            ReorderProxiesView()
//                        } label: {
//                            Label("Reorder Proxies", systemImage: "arrow.up.arrow.down")
//                        }
//                    }
//                    .visibilityPriority(.low)
//                } else {
//                    ToolbarItemGroup {
//                        NavigationLink {
//                            ReorderProxiesView()
//                        } label: {
//                            Label("Reorder Proxies", systemImage: "arrow.up.arrow.down")
//                        }
//                    }
//                }
                ToolbarItemGroup {
                    NavigationLink {
                        ReorderProxiesView()
                    } label: {
                        Label("Reorder Proxies", systemImage: "arrow.up.arrow.down")
                    }
                }
            }
            
            if #available(iOS 26.0, *) {
                ToolbarSpacer()
            }
            
            ToolbarItemGroup {
                Button {
                    switch proxyType {
                    case .servers:
                        let visible = configStore.configurations.filter { configuration in
                            guard let subscriptionId = configuration.subscriptionId else { return true }
                            return !collapsedSubscriptions.contains(subscriptionId)
                        }
                        viewModel.testLatencies(for: visible)
                    case .chains:
                        viewModel.testAllChainLatencies(chains: chainStore.chains, configurations: configStore.configurations)
                    }
                } label: {
                    Label("Test All", systemImage: "gauge.with.dots.needle.67percent")
                }
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
        VStack(alignment: .leading) {
            HStack {
                Text(subscription.name)
                    .font(.body.weight(.medium))
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
                            viewModel.testLatencies(for: configStore.configurations(for: subscription))
                        } label: {
                            Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                        }
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
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                    .buttonStyle(.borderless)
                }
            }
        }
        .padding(.trailing, 10)
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
