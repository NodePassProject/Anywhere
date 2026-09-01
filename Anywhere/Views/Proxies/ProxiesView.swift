//
//  ProxiesView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

private enum ProxyType: String {
    case servers, chains
}

struct ProxiesView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(Operations.self) private var operations
    @Environment(ProxySelection.self) private var proxySelection
    @Environment(LatencyCenter.self) private var latencyCenter
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore

    @State private var proxyRowsBox = ViewScoped<ProxyRowCoordinator>()
    @State private var chainRowsBox = ViewScoped<ChainRowCoordinator>()
    private var coordinator: ProxyRowCoordinator {
        proxyRowsBox {
            ProxyRowCoordinator(configurationStore: configurationStore, selection: proxySelection, latency: latencyCenter)
        }
    }
    private var chainCoordinator: ChainRowCoordinator {
        chainRowsBox {
            ChainRowCoordinator(chainStore: chainStore, configurationStore: configurationStore, selection: proxySelection, latency: latencyCenter)
        }
    }
    
    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var showingChainAddSheet = false
    @State private var showingNotEnoughProxiesAlert = false
    
    @State private var proxyType: ProxyType = AWCore.getProxiesPageProxyType().flatMap(ProxyType.init(rawValue:)) ?? .servers
    @State private var showingGroupAddSheet = false
    
    @State private var configurationToEdit: ProxyConfiguration?
    @State private var chainToEdit: ProxyChain?
    
    @State private var groupToEdit: ProxyGroup?
    @State private var subscriptionToEdit: Subscription?
    @State private var expandedContainerId: UUID?
    
    @State private var updatingSubscriptionIds: Set<UUID> = []
    @State private var showingSubscriptionError = false
    @State private var subscriptionErrorMessage = ""
    
    private var serverGroups: [ProxyGroup] { groupStore.groups(of: .servers) }
    private var chainGroups: [ProxyGroup] { groupStore.groups(of: .chains) }
    
    private var expandedSubscription: Subscription? {
        guard proxyType == .servers else { return nil }
        return subscriptionStore.subscriptions.first { $0.id == expandedContainerId }
    }
    
    private var expandedGroup: ProxyGroup? {
        (proxyType == .servers ? serverGroups : chainGroups).first { $0.id == expandedContainerId }
    }
    
    private var groupedServerIds: Set<UUID> {
        Set(serverGroups.flatMap(\.memberIds))
    }
    
    private var groupedChainIds: Set<UUID> {
        Set(chainGroups.flatMap(\.memberIds))
    }
    
    private var standaloneItems: [ProxyListItem] {
        let grouped = groupedServerIds
        return coordinator.models.filter { $0.subscriptionId == nil && !grouped.contains($0.id) }
    }
    
    private var ungroupedChainItems: [ChainListItem] {
        let grouped = groupedChainIds
        return chainCoordinator.models.filter { !grouped.contains($0.id) }
    }
    
    private func items(for subscription: Subscription) -> [ProxyListItem] {
        coordinator.models.filter { $0.subscriptionId == subscription.id }
    }
    
    private func serverMembers(of group: ProxyGroup) -> [ProxyListItem] {
        group.memberIds.compactMap { coordinator.model(for: $0) }
    }
    
    private func chainMembers(of group: ProxyGroup) -> [ChainListItem] {
        group.memberIds.compactMap { chainCoordinator.model(for: $0) }
    }
    
    var body: some View {
        NavigationStack {
            Group {
                if proxyType == .servers, configurationStore.configurations.isEmpty, serverGroups.isEmpty {
                    ContentUnavailableView("No Proxies", systemImage: "network")
                } else if proxyType == .chains, chainCoordinator.models.isEmpty, chainGroups.isEmpty {
                    ContentUnavailableView("No Chains", systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill")
                } else {
                    ScrollView {
                        VStack(spacing: 10) {
                            if proxyType == .servers {
                                ForEach(standaloneItems) { item in
                                    proxyRow(item)
                                        .padding(.horizontal, 12)
                                }
                                ForEach(serverGroups) { group in
                                    groupView(group) {
                                        ForEach(serverMembers(of: group)) { item in
                                            proxyRow(item, group: group)
                                        }
                                    }
                                }
                                ForEach(subscriptionStore.subscriptions) { subscription in
                                    subscriptionView(subscription) {
                                        ForEach(items(for: subscription)) { item in
                                            proxyRow(item)
                                        }
                                    }
                                }
                            } else {
                                ForEach(ungroupedChainItems) { item in
                                    chainRow(item)
                                        .padding(.horizontal, 12)
                                }
                                ForEach(chainGroups) { group in
                                    groupView(group) {
                                        ForEach(chainMembers(of: group)) { item in
                                            chainRow(item, group: group)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle(title)
            .toolbar { toolbar }
            .containerBackground(Color(.systemGroupedBackground), for: .navigation)
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet)
                    .environment(operations)
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                operations.configurations.add(configuration); operations.selection.selectIfNone(configuration)
            }
        }
        .sheet(isPresented: $showingChainAddSheet) {
            ChainEditorView { chain in
                operations.chains.add(chain)
            }
        }
        .sheet(isPresented: $showingGroupAddSheet) {
            GroupEditorView(kind: proxyType == .servers ? .servers : .chains) { group in
                operations.groups.add(group)
            }
        }
        .sheet(item: $configurationToEdit) { configuration in
            ProxyEditorView(configuration: configuration) { updated in
                operations.configurations.update(updated)
            }
        }
        .sheet(item: $chainToEdit) { chain in
            ChainEditorView(chain: chain) { updated in
                operations.chains.update(updated)
            }
        }
        .sheet(item: $groupToEdit) { group in
            GroupEditorView(kind: group.kind, group: group) { updated in
                operations.groups.update(updated)
            }
        }
        .sheet(item: $subscriptionToEdit) { subscription in
            SubscriptionEditorView(subscription: subscription) { name, configurationIds in
                if name != subscription.name {
                    operations.subscriptions.rename(subscription, to: name)
                }
                operations.configurations.reorder(for: subscription.id, to: configurationIds)
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
        .onChange(of: proxyType) { _, newValue in
            AWCore.setProxiesPageProxyType(newValue.rawValue)
        }
        .onAppear {
            unfoldSelectedProxyContainer()
        }
    }
    
    // MARK: - Title
    private var title: Text {
        switch proxyType {
        case .servers:
            Text("Servers")
        case .chains:
            Text("Chains")
        }
    }
    
    // MARK: - Toolbar
    
    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button {
                dismiss()
            } label: {
                Label("Close", systemImage: "xmark")
            }
        }
        
        ToolbarItem {
            Button {
                switch proxyType {
                case .servers:
                    let liveSubscriptionIds = Set(subscriptionStore.subscriptions.map(\.id))
                    let hiddenGroupMemberIds = Set(serverGroups.filter { $0.id != expandedContainerId }.flatMap(\.memberIds))
                    let visible = configurationStore.configurations.filter { configuration in
                        guard let subscriptionId = configuration.subscriptionId else {
                            return !hiddenGroupMemberIds.contains(configuration.id)
                        }
                        return liveSubscriptionIds.contains(subscriptionId) && subscriptionId == expandedContainerId
                    }
                    operations.latency.testAll(visible)
                case .chains:
                    let hiddenChainIds = Set(chainGroups.filter { $0.id != expandedContainerId }.flatMap(\.memberIds))
                    let visibleChains = chainStore.chains.filter { !hiddenChainIds.contains($0.id) }
                    operations.latency.testChains(visibleChains)
                }
            } label: {
                Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
            }
        }
        
        if #available(iOS 26.0, *) {
            ToolbarSpacer()
        }
        
        ToolbarItem {
            Button {
                switch proxyType {
                case .servers:
                    showingAddSheet = true
                case .chains:
                    if configurationStore.configurations.count < 2 {
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
                        showingGroupAddSheet = true
                    } label: {
                        Label("New Group", systemImage: "folder.badge.plus")
                    }
                    NavigationLink {
                        ReorderView()
                    } label: {
                        Label("Reorder", systemImage: "arrow.up.arrow.down")
                    }
                }
                if !subscriptionStore.subscriptions.isEmpty {
                    Section {
                        Button {
                            updateAllSubscriptions()
                        } label: {
                            Label("Update Subscriptions", systemImage: "arrow.clockwise")
                        }
                    }
                }
            }
        }
    }
    
    // MARK: - Expansion
    
    private func expansionBinding(for id: UUID) -> Binding<Bool> {
        Binding(
            get: { expandedContainerId == id },
            set: { expanded in
                expandedContainerId = expanded ? id : nil
            }
        )
    }
    
    private func unfoldSelectedProxyContainer() {
        if let chainId = proxySelection.selectedChainId {
            if let group = groupStore.group(containing: chainId, kind: .chains) {
                expandedContainerId = group.id
            }
        } else if let configuration = proxySelection.selectedConfiguration {
            if let subscriptionId = configuration.subscriptionId {
                expandedContainerId = subscriptionId
            } else if let group = groupStore.group(containing: configuration.id, kind: .servers) {
                expandedContainerId = group.id
            }
        }
    }
    
    // MARK: - Groups
    
    @ViewBuilder
    private func groupView(_ group: ProxyGroup, @ViewBuilder content: () -> some View) -> some View {
        GroupView(
            group: group,
            memberCount: group.kind == .servers ? serverMembers(of: group).count : chainMembers(of: group).count,
            isExpanded: expansionBinding(for: group.id),
            onEdit: { groupToEdit = group },
            onDelete: { operations.groups.delete(group) },
            content: content
        )
    }
    
    // MARK: - Subscriptions
    
    @ViewBuilder
    private func subscriptionView(_ subscription: Subscription, @ViewBuilder content: () -> some View) -> some View {
        SubscriptionView(
            subscription: subscription,
            configurationCount: configurationStore.configurations(for: subscription).count,
            isExpanded: expansionBinding(for: subscription.id),
            isUpdating: updatingSubscriptionIds.contains(subscription.id),
            onEdit: { subscriptionToEdit = subscription },
            onUpdate: { updateSubscription(subscription) },
            onDelete: { operations.subscriptions.delete(subscription) },
            content: content
        )
    }
    
    private func updateSubscription(_ subscription: Subscription) {
        guard !updatingSubscriptionIds.contains(subscription.id) else { return }
        updatingSubscriptionIds.insert(subscription.id)
        Task {
            do {
                try await operations.subscriptions.refresh(subscription)
            } catch {
                subscriptionErrorMessage = error.localizedDescription
                showingSubscriptionError = true
            }
            updatingSubscriptionIds.remove(subscription.id)
        }
    }

    private func updateAllSubscriptions() {
        guard updatingSubscriptionIds.isEmpty else { return }
        let subscriptions = subscriptionStore.subscriptions
        updatingSubscriptionIds = Set(subscriptions.map(\.id))
        Task {
            var failures: [String] = []
            await withTaskGroup(of: (id: UUID, failure: String?).self) { group in
                for subscription in subscriptions {
                    group.addTask {
                        do {
                            try await operations.subscriptions.refresh(subscription)
                            return (subscription.id, nil)
                        } catch {
                            return (subscription.id, "\(subscription.name): \(error.localizedDescription)")
                        }
                    }
                }
                for await result in group {
                    updatingSubscriptionIds.remove(result.id)
                    if let failure = result.failure {
                        failures.append(failure)
                    }
                }
            }
            if !failures.isEmpty {
                subscriptionErrorMessage = failures.joined(separator: "\n")
                showingSubscriptionError = true
            }
        }
    }
    
    // MARK: - Rows
    
    private func config(_ id: UUID) -> ProxyConfiguration? {
        configurationStore.configurations.first { $0.id == id }
    }
    
    @ViewBuilder
    private func proxyRow(_ item: ProxyListItem, group: ProxyGroup? = nil) -> some View {
        let isGroupable = item.subscriptionId == nil
        ProxyRowView(
            item: item,
            onSelect: { if let configuration = config(item.id) { operations.selection.select(configuration) } },
            onTestLatency: { if let configuration = config(item.id) { operations.latency.test(configuration) } },
            onCopyLink: { if let configuration = config(item.id) { UIPasteboard.general.string = configuration.toURL() } },
            onEdit: { configurationToEdit = config(item.id) },
            onAddToGroup: isGroupable && group == nil ? { operations.groups.addMember(item.id, to: $0) } : nil,
            groupOptions: isGroupable && group == nil ? serverGroups.map { PickerItem(id: $0.id, name: $0.name) } : [],
            onRemoveFromGroup: group.map { group in { operations.groups.removeMember(item.id, from: group.id) } },
            onDelete: { if let configuration = config(item.id) { operations.configurations.delete(configuration) } }
        )
    }
    
    private func chain(_ id: UUID) -> ProxyChain? {
        chainStore.chains.first { $0.id == id }
    }
    
    @ViewBuilder
    private func chainRow(_ item: ChainListItem, group: ProxyGroup? = nil) -> some View {
        ChainRowView(
            item: item,
            onSelect: {
                guard item.isValid, let chain = chain(item.id) else { return }
                operations.selection.selectChain(chain, configurations: configurationStore.configurations)
            },
            onTestLatency: {
                guard let chain = chain(item.id) else { return }
                operations.latency.testChain(chain)
            },
            onEdit: { chainToEdit = chain(item.id) },
            onAddToGroup: group == nil ? { operations.groups.addMember(item.id, to: $0) } : nil,
            groupOptions: group == nil ? chainGroups.map { PickerItem(id: $0.id, name: $0.name) } : [],
            onRemoveFromGroup: group.map { group in { operations.groups.removeMember(item.id, from: group.id) } },
            onDelete: { if let chain = chain(item.id) { operations.chains.delete(chain) } }
        )
    }
}
