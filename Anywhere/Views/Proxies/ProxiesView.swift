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
    @Environment(AppContainer.self) private var appContainer
    @Environment(ProxySelection.self) private var proxySelection
    @Environment(LatencyCenter.self) private var latencyCenter
    @Environment(ConfigurationStore.self) private var configurationStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore
    private var coordinator: ProxyRowCoordinator { appContainer.proxyRows }
    private var chainCoordinator: ChainRowCoordinator { appContainer.chainRows }
    
    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var showingChainAddSheet = false
    @State private var showingNotEnoughProxiesAlert = false
    
    @State private var proxyType: ProxyType = AWCore.getProxiesPageProxyType().flatMap(ProxyType.init(rawValue:)) ?? .servers
    @State private var showingGroupAddSheet = false
    @State private var reorderScope: ReorderScope?
    
    @State private var configurationToEdit: ProxyConfiguration?
    @State private var chainToEdit: ProxyChain?
    
    @State private var groupToEdit: ProxyGroup?
    @State private var expandedContainerId: UUID?
    
    @State private var updatingSubscription: Subscription?
    @State private var showingSubscriptionError = false
    @State private var subscriptionErrorMessage = ""
    @State private var renamingSubscription: Subscription?
    @State private var renameText = ""
    
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
        ZStack {
            Color(.systemGroupedBackground)
                .ignoresSafeArea()
            ScrollView {
                LazyVStack(spacing: 10) {
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
        .overlay {
            if proxyType == .servers, configurationStore.configurations.isEmpty, serverGroups.isEmpty {
                ContentUnavailableView("No Proxies", systemImage: "network")
            } else if proxyType == .chains, chainCoordinator.models.isEmpty, chainGroups.isEmpty {
                ContentUnavailableView("No Chains", systemImage: "point.bottomleft.forward.to.point.topright.scurvepath.fill")
            }
        }
        .navigationTitle("Proxies")
        .toolbar {
            if let subscription = expandedSubscription {
                ToolbarItem(placement: .bottomBar) {
                    if updatingSubscription?.id == subscription.id {
                        ProgressView()
                    } else {
                        Button {
                            updateSubscription(subscription)
                        } label: {
                            Label("Update", systemImage: "arrow.clockwise")
                        }
                    }
                }
                
                ToolbarItem(placement: .bottomBar) {
                    Menu("More", systemImage: "ellipsis") {
                        let configurationCount = configurationStore.configurations(for: subscription).count
                        if configurationCount > 1 {
                            Button {
                                reorderScope = .subscription(subscription.id)
                            } label: {
                                Label("Reorder", systemImage: "arrow.up.arrow.down")
                            }
                        }
                        if configurationCount > 0 {
                            Section {
                                Button {
                                    latencyCenter.testLatencies(for: configurationStore.configurations(for: subscription))
                                } label: {
                                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                                }
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
            } else if let group = expandedGroup {
                ToolbarItem(placement: .bottomBar) {
                    Button{
                        groupToEdit = group
                    } label: {
                        Label("Edit", systemImage: "pencil")
                    }
                }
                
                ToolbarItem(placement: .bottomBar) {
                    Menu("More", systemImage: "ellipsis") {
                        let memberCount = group.kind == .servers ? serverMembers(of: group).count : chainMembers(of: group).count
                        if memberCount > 1 {
                            Section {
                                Button {
                                    reorderScope = .group(group.id)
                                } label: {
                                    Label("Reorder", systemImage: "arrow.up.arrow.down")
                                }
                            }
                        }
                        if memberCount > 0 {
                            Section {
                                Button {
                                    testGroupLatency(group)
                                } label: {
                                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                                }
                            }
                        }
                        Section {
                            Button {
                                groupToEdit = group
                            } label: {
                                Label("Edit", systemImage: "pencil")
                            }
                            Button(role: .destructive) {
                                groupStore.delete(group)
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                    }
                }
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
                        if standaloneItems.count > 1 || subscriptionStore.subscriptions.count > 1 || chainStore.chains.count > 1 || serverGroups.count > 1 || chainGroups.count > 1 {
                            NavigationLink {
                                ReorderView()
                            } label: {
                                Label("Reorder", systemImage: "arrow.up.arrow.down")
                            }
                        }
                    }
                    Section {
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
                                latencyCenter.testLatencies(for: visible)
                            case .chains:
                                let hiddenChainIds = Set(chainGroups.filter { $0.id != expandedContainerId }.flatMap(\.memberIds))
                                let visibleChains = chainStore.chains.filter { !hiddenChainIds.contains($0.id) }
                                latencyCenter.testAllChainLatencies(chains: visibleChains, configurations: configurationStore.configurations)
                            }
                        } label: {
                            Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                        }
                    }
                    if !subscriptionStore.subscriptions.isEmpty {
                        Section {
                            Button {
                                updateAllSubscriptions()
                            } label: {
                                Label("Update All", systemImage: "arrow.clockwise")
                            }
                        }
                    }
                }
            }
        }
        .navigationDestination(item: $reorderScope) { scope in
            ReorderView(scope: scope)
        }
        .sheet(isPresented: $showingAddSheet) {
            DynamicSheet(animation: .snappy(duration: 0.3, extraBounce: 0)) {
                AddProxyView(showingManualAddSheet: $showingManualAddSheet)
                    .environment(proxySelection)
                    .environment(configurationStore)
                    .environment(subscriptionStore)
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                configurationStore.add(configuration); proxySelection.selectIfNone(configuration)
            }
        }
        .sheet(isPresented: $showingChainAddSheet) {
            ChainEditorView { chain in
                chainStore.add(chain)
            }
        }
        .sheet(isPresented: $showingGroupAddSheet) {
            GroupEditorView(kind: proxyType == .servers ? .servers : .chains) { group in
                groupStore.add(group)
            }
        }
        .sheet(item: $configurationToEdit) { configuration in
            ProxyEditorView(configuration: configuration) { updated in
                configurationStore.update(updated)
            }
        }
        .sheet(item: $chainToEdit) { chain in
            ChainEditorView(chain: chain) { updated in
                chainStore.update(updated)
            }
        }
        .sheet(item: $groupToEdit) { group in
            GroupEditorView(kind: group.kind, group: group) { updated in
                groupStore.update(updated)
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
        .onChange(of: proxyType) { _, newValue in
            AWCore.setProxiesPageProxyType(newValue.rawValue)
        }
        .onAppear {
            unfoldSelectedProxyContainer()
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
            onReorder: { reorderScope = .group(group.id) },
            onTestLatency: { testGroupLatency(group) },
            onEdit: { groupToEdit = group },
            onDelete: { groupStore.delete(group) },
            content: content
        )
    }
    
    private func testGroupLatency(_ group: ProxyGroup) {
        switch group.kind {
        case .servers:
            let members = group.memberIds.compactMap { id in
                configurationStore.configurations.first { $0.id == id }
            }
            latencyCenter.testLatencies(for: members)
        case .chains:
            let members = group.memberIds.compactMap { id in
                chainStore.chains.first { $0.id == id }
            }
            latencyCenter.testAllChainLatencies(chains: members, configurations: configurationStore.configurations)
        }
    }
    
    // MARK: - Subscriptions
    
    @ViewBuilder
    private func subscriptionView(_ subscription: Subscription, @ViewBuilder content: () -> some View) -> some View {
        SubscriptionView(
            subscription: subscription,
            configurationCount: configurationStore.configurations(for: subscription).count,
            isExpanded: expansionBinding(for: subscription.id),
            isUpdating: updatingSubscription?.id == subscription.id,
            onRename: {
                renameText = subscription.name
                renamingSubscription = subscription
            },
            onDelete: { subscriptionStore.delete(subscription) },
            content: content
        )
    }
    
    private func updateSubscription(_ subscription: Subscription) {
        guard updatingSubscription == nil else { return }
        updatingSubscription = subscription
        Task {
            do {
                try await appContainer.subscriptionRefresher.refresh(subscription)
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
                    try await appContainer.subscriptionRefresher.refresh(subscription)
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
        configurationStore.configurations.first { $0.id == id }
    }
    
    @ViewBuilder
    private func proxyRow(_ item: ProxyListItem, group: ProxyGroup? = nil) -> some View {
        let isGroupable = item.subscriptionId == nil
        ProxyRowView(
            item: item,
            onSelect: { if let configuration = config(item.id) { proxySelection.selectedConfiguration = configuration } },
            onTestLatency: { if let configuration = config(item.id) { latencyCenter.testLatency(for: configuration) } },
            onCopyLink: { if let configuration = config(item.id) { UIPasteboard.general.string = configuration.toURL() } },
            onEdit: { configurationToEdit = config(item.id) },
            onAddToGroup: isGroupable && group == nil ? { groupStore.addMember(item.id, to: $0) } : nil,
            groupOptions: isGroupable && group == nil ? serverGroups.map { PickerItem(id: $0.id, name: $0.name) } : [],
            onRemoveFromGroup: group.map { group in { groupStore.removeMember(item.id, from: group.id) } },
            onDelete: { if let configuration = config(item.id) { configurationStore.delete(configuration) } }
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
                proxySelection.selectChain(chain, configurations: configurationStore.configurations)
            },
            onTestLatency: {
                guard let chain = chain(item.id) else { return }
                latencyCenter.testChainLatency(for: chain, configurations: configurationStore.configurations)
            },
            onEdit: { chainToEdit = chain(item.id) },
            onAddToGroup: group == nil ? { groupStore.addMember(item.id, to: $0) } : nil,
            groupOptions: group == nil ? chainGroups.map { PickerItem(id: $0.id, name: $0.name) } : [],
            onRemoveFromGroup: group.map { group in { groupStore.removeMember(item.id, from: group.id) } },
            onDelete: { if let chain = chain(item.id) { chainStore.delete(chain) } }
        )
    }
}
