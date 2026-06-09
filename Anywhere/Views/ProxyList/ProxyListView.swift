//
//  ProxyListView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import SwiftUI
import NetworkExtension

struct ProxyListView: View {
    @Environment(VPNViewModel.self) private var viewModel
    @Environment(ConfigurationStore.self) private var configStore
    @Environment(SubscriptionStore.self) private var subscriptionStore
    private let coordinator = ProxyRowCoordinator.shared

    @State private var showingAddSheet = false
    @State private var showingManualAddSheet = false
    @State private var configurationToEdit: ProxyConfiguration?
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
            Section {
                ForEach(standaloneItems) { item in
                    proxyRow(item, editingDisabled: false)
                }
            }
            ForEach(subscriptionStore.subscriptions) { subscription in
                let editingDisabled = SubscriptionDomainHelper.shouldDisableProxyEditing(for: subscription.url)
                Section {
                    if !collapsedSubscriptions.contains(subscription.id) {
                        ForEach(items(for: subscription)) { item in
                            proxyRow(item, editingDisabled: editingDisabled)
                        }
                    }
                } header: {
                    subscriptionHeader(subscription)
                }
            }
        }
        .overlay {
            if configStore.configurations.isEmpty {
                ContentUnavailableView("No Proxies", systemImage: "network")
            }
        }
        .navigationTitle("Proxies")
        .toolbar {
            if standaloneItems.count > 1 || subscriptionStore.subscriptions.count > 1 {
                if #available(iOS 27.0, *) {
                    ToolbarItemGroup {
                        NavigationLink {
                            ReorderProxiesView()
                        } label: {
                            Label("Reorder Proxies", systemImage: "arrow.up.arrow.down")
                        }
                    }
                    .visibilityPriority(.low)
                } else {
                    ToolbarItemGroup {
                        NavigationLink {
                            ReorderProxiesView()
                        } label: {
                            Label("Reorder Proxies", systemImage: "arrow.up.arrow.down")
                        }
                    }
                }
            }
            
            if #available(iOS 26.0, *) {
                ToolbarSpacer()
            }
            
            ToolbarItemGroup {
                Button {
                    let visible = configStore.configurations.filter { configuration in
                        guard let subId = configuration.subscriptionId else { return true }
                        return !collapsedSubscriptions.contains(subId)
                    }
                    viewModel.testLatencies(for: visible)
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
        .sheet(item: $configurationToEdit) { configuration in
            ProxyEditorView(configuration: configuration) { updated in
                configStore.update(updated)
            }
        }
        .alert("Update Failed", isPresented: $showingSubscriptionError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text(subscriptionErrorMessage)
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

    @ViewBuilder
    private func subscriptionHeader(_ subscription: Subscription) -> some View {
        HStack {
            Button {
                let id = subscription.id
                withAnimation(.easeInOut(duration: 0.2)) {
                    if collapsedSubscriptions.contains(id) {
                        collapsedSubscriptions.remove(id)
                    } else {
                        collapsedSubscriptions.insert(id)
                    }
                }
                subscriptionStore.toggleCollapsed(subscription)
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.caption.bold())
                        .frame(width: 10)
                        .rotationEffect(.degrees(collapsedSubscriptions.contains(subscription.id) ? 0 : 90))
                    Text(subscription.name)
                }
            }
            .buttonStyle(.plain)
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
}

// MARK: - Proxy Row

private struct ProxyRowView: View {
    let item: ProxyListItem
    let editingDisabled: Bool
    let onSelect: () -> Void
    let onTestLatency: () -> Void
    let onCopyLink: () -> Void
    let onEdit: () -> Void
    let onDelete: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack {
                VStack(alignment: .leading) {
                    HStack {
                        Text(item.name)
                            .font(.body.weight(.medium))
                        if item.isSelected {
                            Image(systemName: "checkmark")
                                .font(.caption.bold())
                                .foregroundStyle(.tint)
                        }
                    }
                    HStack(spacing: 4) {
                        ForEach(Array(item.tags.enumerated()), id: \.offset) { index, tag in
                            if index > 0 { Text("·") }
                            Text(tag)
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Spacer()

                LatencyLabel(latency: item.latency)
                    .onTapGesture(perform: onTestLatency)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button(action: onTestLatency) {
                Label("Test Latency", systemImage: "gauge.with.dots.needle.67percent")
            }
            if !editingDisabled {
                Button(action: onCopyLink) {
                    Label("Copy Link", systemImage: "doc.on.doc")
                }
                Button(action: onEdit) {
                    Label("Edit", systemImage: "pencil")
                }
                Button(role: .destructive, action: onDelete) {
                    Label("Delete", systemImage: "trash")
                }
            }
        }
        .swipeActions(edge: .trailing) {
            if !editingDisabled {
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
}
