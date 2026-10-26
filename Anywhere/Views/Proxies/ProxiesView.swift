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
    @Environment(\.colorScheme) private var colorScheme
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
        
        if #available(iOS 27.0, *),
           !ProcessInfo.processInfo.isiOSAppOnMac /* Workaround */ {
            ToolbarOverflowMenu {
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
        } else {
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
    }
    
    // MARK: - Expansion

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
        let isExpanded = expandedContainerId == group.id
        let iconSize: CGFloat = isExpanded ? 36 : 18
        VStack(spacing: 0) {
            Button {
                withAnimation {
                    expandedContainerId = isExpanded ? nil : group.id
                }
            } label: {
                HStack(spacing: isExpanded ? 20 : 10) {
                    Image(systemName: "folder")
                        .resizable()
                        .scaledToFit()
                        .frame(width: iconSize, height: iconSize)
                        .foregroundStyle(.secondary)
                    Text(group.name)
                        .font(.body.weight(.medium))
                    Spacer()
                    TagBadge(text: (group.kind == .servers ? serverMembers(of: group).count : chainMembers(of: group).count).description, color: .accentColor)
                }
                .padding()
                .background {
                    RoundedRectangle(cornerRadius: 24)
                        .fill(Color(isExpanded ? .systemGroupedBackground : .secondarySystemGroupedBackground))
                }
                .contentShape(RoundedRectangle(cornerRadius: 24))
                .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 24))
                .swipeActions {
                    Button(role: .destructive) {
                        operations.groups.delete(group)
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
                    Section {
                        Button {
                            groupToEdit = group
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        Button(role: .destructive) {
                            operations.groups.delete(group)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
                .padding(.horizontal, isExpanded ? 0 : 12)
            }
            .buttonStyle(.plain)

            if isExpanded {
                LazyVStack(spacing: 10) {
                    content()
                }
                .padding(.top, 12)
            }
        }
        .padding(.horizontal, isExpanded ? 7 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .background {
            RoundedRectangle(cornerRadius: 24)
                .fill(Color(isExpanded ? .systemGroupedBackground : .clear))
                .shadow(color: .primary.opacity(isExpanded ? 0.2 : 0), radius: 6)
                .padding(.horizontal, isExpanded ? 0 : 12)
        }
        .padding(.horizontal, isExpanded ? 5 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .geometryGroup()
    }
    
    // MARK: - Subscriptions
    
    @ViewBuilder
    private func subscriptionView(_ subscription: Subscription, @ViewBuilder content: () -> some View) -> some View {
        let isExpanded = expandedContainerId == subscription.id
        let iconSize: CGFloat = isExpanded ? 36 : 18
        let iconData: Data? = switch colorScheme {
        case .dark: subscription.iconDark ?? subscription.iconLight
        default: subscription.iconLight ?? subscription.iconDark
        }
        VStack(spacing: 0) {
            Button {
                withAnimation {
                    expandedContainerId = isExpanded ? nil : subscription.id
                }
            } label: {
                HStack(spacing: isExpanded ? 20 : 10) {
                    if let iconData, let image = SubscriptionIconCache.image(for: iconData) {
                        Image(uiImage: image)
                            .resizable()
                            .scaledToFit()
                            .frame(width: iconSize, height: iconSize)
                    } else {
                        Image(systemName: "globe")
                            .resizable()
                            .scaledToFit()
                            .frame(width: iconSize, height: iconSize)
                            .foregroundStyle(.secondary)
                    }
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 10) {
                            Text(subscription.name)
                                .font(.body.weight(.medium))
                                .lineLimit(1)
                            if updatingSubscriptionIds.contains(subscription.id) {
                                ProgressView()
                                    .controlSize(.small)
                            }
                            Spacer()
                            TagBadge(text: configurationStore.configurations(for: subscription).count.description, color: .accentColor)
                        }
                        if isExpanded {
                            SubscriptionUsageView(subscription: subscription)
                        }
                    }
                }
                .padding()
                .background {
                    RoundedRectangle(cornerRadius: 24)
                        .fill(Color(isExpanded ? .systemGroupedBackground : .secondarySystemGroupedBackground))
                }
                .contentShape(RoundedRectangle(cornerRadius: 24))
                .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 24))
                .swipeActions {
                    Button(role: .destructive) {
                        operations.subscriptions.delete(subscription)
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
                        subscriptionToEdit = subscription
                    } label: {
                        Label("Edit", systemImage: "pencil")
                    }
                    .tint(.orange)
                }
                .contextMenu {
                    Section {
                        Button {
                            UIPasteboard.general.string = subscription.url
                        } label: {
                            Label("Copy Link", systemImage: "doc.on.doc")
                        }
                        if let url = URL(string: subscription.url) {
                            ShareLink(item: url, preview: SharePreview(subscription.name)) {
                                Label("Share", systemImage: "square.and.arrow.up")
                            }
                        }
                    }
                    Section {
                        Button {
                            subscriptionToEdit = subscription
                        } label: {
                            Label("Edit", systemImage: "pencil")
                        }
                        Button {
                            updateSubscription(subscription)
                        } label: {
                            Label("Update", systemImage: "arrow.clockwise")
                        }
                        Button(role: .destructive) {
                            operations.subscriptions.delete(subscription)
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
                .padding(.horizontal, isExpanded ? 0 : 12)
            }
            .buttonStyle(.plain)

            if isExpanded {
                LazyVStack(spacing: 10) {
                    content()
                }
                .padding(.top, 12)
            }
        }
        .padding(.horizontal, isExpanded ? 7 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .background {
            RoundedRectangle(cornerRadius: 24)
                .fill(Color(isExpanded ? .systemGroupedBackground : .clear))
                .shadow(color: .primary.opacity(isExpanded ? 0.2 : 0), radius: 6)
                .padding(.horizontal, isExpanded ? 0 : 12)
        }
        .padding(.horizontal, isExpanded ? 5 : 0)
        .padding(.vertical, isExpanded ? 12 : 0)
        .geometryGroup()
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
        Button {
            if let configuration = config(item.id) { operations.selection.select(configuration) }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text(item.name)
                            .font(.body.weight(.medium))
                        if item.isSelected {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }
                    HStack(spacing: 5) {
                        TagBadge(text: item.protocolName, color: .blue)
                        if let networkTag = item.networkTag {
                            TagBadge(text: networkTag, color: .green)
                        }
                        if let transportLayerTag = item.transportLayerTag {
                            TagBadge(text: transportLayerTag, color: .teal)
                        }
                        if let securityLayerTag = item.securityLayerTag {
                            TagBadge(text: securityLayerTag, color: .orange)
                        }
                        if item.isVision {
                            TagBadge(text: "Vision", color: .purple)
                        }
                        if item.isMorph {
                            TagBadge(text: "Morph", color: .indigo)
                        }
                    }
                }

                Spacer()

                LatencyLabel(latency: item.latency)
                    .onTapGesture {
                        if let configuration = config(item.id) { operations.latency.test(configuration) }
                    }
            }
            .padding()
            .background {
                RoundedRectangle(cornerRadius: 24)
                    .fill(Color(.secondarySystemGroupedBackground))
            }
            .contentShape(RoundedRectangle(cornerRadius: 24))
            .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 24))
        }
        .buttonStyle(.plain)
        .contextMenu {
            Section {
                if group == nil, item.subscriptionId == nil, !serverGroups.isEmpty {
                    Menu {
                        ForEach(serverGroups) { candidate in
                            Button(candidate.name) { operations.groups.addMember(item.id, to: candidate.id) }
                        }
                    } label: {
                        Label("Add to Group", systemImage: "folder.badge.plus")
                    }
                }
                if let group {
                    Button {
                        operations.groups.removeMember(item.id, from: group.id)
                    } label: {
                        Label("Remove from Group", systemImage: "folder.badge.minus")
                    }
                }
            }
            Section {
                Button {
                    if let configuration = config(item.id) { operations.latency.test(configuration) }
                } label: {
                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                }
            }
            Section {
                Button {
                    if let configuration = config(item.id) { UIPasteboard.general.string = configuration.toURLString() }
                } label: {
                    Label("Copy Link", systemImage: "doc.on.doc")
                }
                if let urlString = config(item.id)?.toURLString(), let url = URL(string: urlString) {
                    ShareLink(item: url, preview: SharePreview(item.name)) {
                        Label("Share", systemImage: "square.and.arrow.up")
                    }
                }
            }
            Section {
                Button {
                    configurationToEdit = config(item.id)
                } label: {
                    Label("Edit", systemImage: "pencil")
                }
                Button(role: .destructive) {
                    if let configuration = config(item.id) { operations.configurations.delete(configuration) }
                } label: {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                if let configuration = config(item.id) { operations.configurations.delete(configuration) }
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                configurationToEdit = config(item.id)
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
    }
    
    private func chain(_ id: UUID) -> ProxyChain? {
        chainStore.chains.first { $0.id == id }
    }
    
    @ViewBuilder
    private func chainRow(_ item: ChainListItem, group: ProxyGroup? = nil) -> some View {
        Button {
            guard item.isValid, let chain = chain(item.id) else { return }
            operations.selection.selectChain(chain, configurations: configurationStore.configurations)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
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
                        .onTapGesture {
                            if let chain = chain(item.id) { operations.latency.testChain(chain) }
                        }
                }
            }
            .padding()
            .background {
                RoundedRectangle(cornerRadius: 24)
                    .fill(Color(.secondarySystemGroupedBackground))
            }
            .contentShape(RoundedRectangle(cornerRadius: 24))
            .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 24))
        }
        .buttonStyle(.plain)
        .opacity(item.isValid ? 1 : 0.6)
        .contextMenu {
            if item.isValid {
                Button {
                    if let chain = chain(item.id) { operations.latency.testChain(chain) }
                } label: {
                    Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
                }
            }
            Button {
                chainToEdit = chain(item.id)
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            if group == nil, !chainGroups.isEmpty {
                Menu {
                    ForEach(chainGroups) { candidate in
                        Button(candidate.name) { operations.groups.addMember(item.id, to: candidate.id) }
                    }
                } label: {
                    Label("Add to Group", systemImage: "folder.badge.plus")
                }
            }
            if let group {
                Button {
                    operations.groups.removeMember(item.id, from: group.id)
                } label: {
                    Label("Remove from Group", systemImage: "folder.badge.minus")
                }
            }
            Button(role: .destructive) {
                if let chain = chain(item.id) { operations.chains.delete(chain) }
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                if let chain = chain(item.id) { operations.chains.delete(chain) }
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                chainToEdit = chain(item.id)
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(.orange)
        }
    }
}

private enum SubscriptionIconCache {
    static let cache = NSCache<NSData, UIImage>()

    static func image(for data: Data) -> UIImage? {
        let key = data as NSData
        if let cached = cache.object(forKey: key) {
            return cached
        }
        guard let image = UIImage(data: data) else { return nil }
        cache.setObject(image, forKey: key)
        return image
    }
}

private struct SubscriptionUsageView: View {
    let subscription: Subscription

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
            VStack(alignment: .leading, spacing: 5) {
                if let usedFraction, let usageDescription {
                    HStack(spacing: 5) {
                        UsageRing(fraction: usedFraction)
                        Text(usageDescription)
                    }
                }
                if let expire = subscription.expire {
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
            String(localized: "\(Formatting.formatBytes(used)) of \(Formatting.formatBytes(total)) used")
        case let (used?, nil):
            String(localized: "\(Formatting.formatBytes(used)) used")
        case let (nil, total?):
            String(localized: "\(Formatting.formatBytes(total)) total")
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
