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
    @Environment(AppContainer.self) private var container
    @Environment(ProxySelection.self) private var selection
    @Environment(LatencyCenter.self) private var latency
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(ChainStore.self) private var chainStore
    @Environment(GroupStore.self) private var groupStore
    @Environment(SubscriptionStore.self) private var subscriptionStore
    private var coordinator: ProxyRowCoordinator { container.proxyRows }
    private var chainCoordinator: ChainRowCoordinator { container.chainRows }
    
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
    @State private var collapsedGroups: Set<UUID> = []
    
    @State private var updatingSubscription: Subscription?
    @State private var showingSubscriptionError = false
    @State private var subscriptionErrorMessage = ""
    @State private var collapsedSubscriptions: Set<UUID> = []
    @State private var renamingSubscription: Subscription?
    @State private var renameText = ""

    private var serverGroups: [ProxyGroup] { groupStore.groups(of: .servers) }
    private var chainGroups: [ProxyGroup] { groupStore.groups(of: .chains) }

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
        List {
            if proxyType == .servers {
                Section {
                    ForEach(standaloneItems) { item in
                        proxyRow(item, editingDisabled: false)
                    }
                }
                ForEach(serverGroups) { group in
                    Section {
                        DisclosureGroup(isExpanded: expansionBinding(for: group)) {
                            ForEach(serverMembers(of: group)) { item in
                                proxyRow(item, editingDisabled: false, group: group)
                            }
                        } label: {
                            groupLabel(group)
                        }
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
                Section {
                    ForEach(ungroupedChainItems) { item in
                        chainRow(item)
                    }
                }
                ForEach(chainGroups) { group in
                    Section {
                        DisclosureGroup(isExpanded: expansionBinding(for: group)) {
                            ForEach(chainMembers(of: group)) { item in
                                chainRow(item, group: group)
                            }
                        } label: {
                            groupLabel(group)
                        }
                    }
                }
            }
        }
        .overlay {
            if proxyType == .servers, configStore.configurations.isEmpty, serverGroups.isEmpty {
                ContentUnavailableView("No Proxies", systemImage: "network")
            } else if proxyType == .chains, chainCoordinator.models.isEmpty, chainGroups.isEmpty {
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
                                let hiddenGroupMemberIds = Set(serverGroups.filter { collapsedGroups.contains($0.id) }.flatMap(\.memberIds))
                                let visible = configStore.configurations.filter { configuration in
                                    guard let subscriptionId = configuration.subscriptionId else {
                                        return !hiddenGroupMemberIds.contains(configuration.id)
                                    }
                                    return liveSubscriptionIds.contains(subscriptionId) && !collapsedSubscriptions.contains(subscriptionId)
                                }
                                latency.testLatencies(for: visible)
                            case .chains:
                                let hiddenChainIds = Set(chainGroups.filter { collapsedGroups.contains($0.id) }.flatMap(\.memberIds))
                                let visibleChains = chainStore.chains.filter { !hiddenChainIds.contains($0.id) }
                                latency.testAllChainLatencies(chains: visibleChains, configurations: configStore.configurations)
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
            }
        }
        .sheet(isPresented: $showingManualAddSheet) {
            ProxyEditorView { configuration in
                configStore.add(configuration); selection.selectIfNone(configuration)
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
                configStore.update(updated)
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
            collapsedSubscriptions = Set(subscriptionStore.subscriptions.filter(\.collapsed).map(\.id))
            collapsedGroups = Set(groupStore.groups.filter(\.collapsed).map(\.id))
        }
    }
    
    // MARK: - Groups

    private func expansionBinding(for group: ProxyGroup) -> Binding<Bool> {
        Binding(
            get: { !collapsedGroups.contains(group.id) },
            set: { expanded in
                if expanded {
                    collapsedGroups.remove(group.id)
                } else {
                    collapsedGroups.insert(group.id)
                }
                if group.collapsed == expanded {
                    groupStore.toggleCollapsed(group)
                }
            }
        )
    }

    @ViewBuilder
    private func groupLabel(_ group: ProxyGroup) -> some View {
        let memberCount = group.kind == .servers ? serverMembers(of: group).count : chainMembers(of: group).count
        VStack(alignment: .leading, spacing: 5) {
            Text(group.name)
                .font(.body.weight(.medium))
        }
        .padding(.trailing, 10)
        .swipeActions {
            Button(role: .destructive) {
                groupStore.delete(group)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                groupToEdit = group
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
        .contextMenu {
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

    private func testGroupLatency(_ group: ProxyGroup) {
        switch group.kind {
        case .servers:
            let members = group.memberIds.compactMap { id in
                configStore.configurations.first { $0.id == id }
            }
            latency.testLatencies(for: members)
        case .chains:
            let members = group.memberIds.compactMap { id in
                chainStore.chains.first { $0.id == id }
            }
            latency.testAllChainLatencies(chains: members, configurations: configStore.configurations)
        }
    }

    // MARK: - Subscriptions
    
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
        let configurationCount = configStore.configurations(for: subscription).count
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
                        latency.testLatencies(for: configStore.configurations(for: subscription))
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

    // MARK: - Formatting

    private func updateSubscription(_ subscription: Subscription) {
        guard updatingSubscription == nil else { return }
        updatingSubscription = subscription
        Task {
            do {
                try await container.subscriptionRefresher.refresh(subscription)
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
                    try await container.subscriptionRefresher.refresh(subscription)
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
    private func proxyRow(_ item: ProxyListItem, editingDisabled: Bool, group: ProxyGroup? = nil) -> some View {
        let isGroupable = item.subscriptionId == nil
        ProxyRowView(
            item: item,
            editingDisabled: editingDisabled,
            onSelect: { if let configuration = config(item.id) { selection.selectedConfiguration = configuration } },
            onTestLatency: { if let configuration = config(item.id) { latency.testLatency(for: configuration) } },
            onCopyLink: { if let configuration = config(item.id) { UIPasteboard.general.string = configuration.toURL() } },
            onEdit: { configurationToEdit = config(item.id) },
            onAddToGroup: isGroupable && group == nil ? { groupStore.addMember(item.id, to: $0) } : nil,
            groupOptions: isGroupable && group == nil ? serverGroups.map { PickerItem(id: $0.id, name: $0.name) } : [],
            onRemoveFromGroup: group.map { group in { groupStore.removeMember(item.id, from: group.id) } },
            onDelete: { if let configuration = config(item.id) { configStore.delete(configuration) } }
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
                selection.selectChain(chain, configurations: configStore.configurations)
            },
            onTestLatency: {
                guard let chain = chain(item.id) else { return }
                latency.testChainLatency(for: chain, configurations: configStore.configurations)
            },
            onEdit: { chainToEdit = chain(item.id) },
            onAddToGroup: group == nil ? { groupStore.addMember(item.id, to: $0) } : nil,
            groupOptions: group == nil ? chainGroups.map { PickerItem(id: $0.id, name: $0.name) } : [],
            onRemoveFromGroup: group.map { group in { groupStore.removeMember(item.id, from: group.id) } },
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
