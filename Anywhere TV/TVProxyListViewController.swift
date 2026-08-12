//
//  TVProxyListViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

private nonisolated enum ProxySectionID: Hashable {
    case standalone
    case subscription(UUID)
}

class TVProxyListViewController: UITableViewController {

    private let container: AppContainer
    private var selection: ProxySelection { container.selection }
    private var latency: LatencyCenter { container.latency }
    private var coordinator: ProxyRowCoordinator { container.proxyRows }
    private var dataSource: UITableViewDiffableDataSource<ProxySectionID, UUID>!
    private var hasApplied = false

    private var collapsedSubscriptions = Set<UUID>()
    private var updatingSubscription: Subscription?

    init(container: AppContainer) {
        self.container = container
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Proxies")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(TVProxyCell.self, forCellReuseIdentifier: TVProxyCell.reuseIdentifier)
        tableView.register(TVSubscriptionHeaderView.self, forHeaderFooterViewReuseIdentifier: TVSubscriptionHeaderView.reuseIdentifier)
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

        let addButton = UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(addTapped))
        addButton.tintColor = .label

        let testAllButton = UIBarButtonItem(title: String(localized: "Test All"), style: .plain, target: self, action: #selector(testAllTapped))
        testAllButton.tintColor = .label

        navigationItem.rightBarButtonItems = [addButton, testAllButton]

        configureDataSource()
    }
    
    override func updateProperties() {
        super.updateProperties()
        applySnapshot()
    }

    private func configureDataSource() {
        dataSource = UITableViewDiffableDataSource<ProxySectionID, UUID>(tableView: tableView) { [container] tableView, indexPath, id in
            let cell = tableView.dequeueReusableCell(withIdentifier: TVProxyCell.reuseIdentifier, for: indexPath) as! TVProxyCell
            guard let model = container.proxyRows.model(for: id) else { return cell }
            cell.configurationUpdateHandler = { cell, _ in
                (cell as? TVProxyCell)?.configure(model)
            }
            return cell
        }
        dataSource.defaultRowAnimation = .fade
    }

    private func applySnapshot() {
        let models = coordinator.models
        var snapshot = NSDiffableDataSourceSnapshot<ProxySectionID, UUID>()

        let standalone = models.filter { $0.subscriptionId == nil }
        if !standalone.isEmpty {
            snapshot.appendSections([.standalone])
            snapshot.appendItems(standalone.map(\.id), toSection: .standalone)
        }
        for subscription in container.subscriptionStore.subscriptions {
            let items = models.filter { $0.subscriptionId == subscription.id }
            guard !items.isEmpty else { continue }
            snapshot.appendSections([.subscription(subscription.id)])
            let ids = collapsedSubscriptions.contains(subscription.id) ? [] : items.map(\.id)
            snapshot.appendItems(ids, toSection: .subscription(subscription.id))
        }

        let animate = hasApplied
        hasApplied = true
        dataSource.apply(snapshot, animatingDifferences: animate) { [weak self] in
            self?.refreshVisibleHeaders()
        }
        updateEmptyState(isEmpty: models.isEmpty)
    }

    // MARK: - Section Headers

    override func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        guard case .subscription(let subscriptionID)? = dataSource.sectionIdentifier(for: section),
              let subscription = subscription(subscriptionID) else { return nil }
        let header = tableView.dequeueReusableHeaderFooterView(withIdentifier: TVSubscriptionHeaderView.reuseIdentifier) as! TVSubscriptionHeaderView
        configureHeader(header, subscription: subscription)
        return header
    }

    override func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        if case .subscription? = dataSource.sectionIdentifier(for: section) { return 100 }
        return UITableView.automaticDimension
    }

    private func configureHeader(_ header: TVSubscriptionHeaderView, subscription: Subscription) {
        header.onCollapse = { [weak self] in self?.toggleCollapse(subscription) }
        header.onUpdate = { [weak self] in self?.updateSubscription(subscription) }
        header.configure(
            name: subscription.name,
            isCollapsed: collapsedSubscriptions.contains(subscription.id),
            isUpdating: updatingSubscription?.id == subscription.id,
            menu: subscriptionMenu(for: subscription)
        )
    }
    
    private func refreshVisibleHeaders() {
        for section in 0..<tableView.numberOfSections {
            guard case .subscription(let subID)? = dataSource.sectionIdentifier(for: section),
                  let header = tableView.headerView(forSection: section) as? TVSubscriptionHeaderView,
                  let subscription = subscription(subID) else { continue }
            configureHeader(header, subscription: subscription)
        }
    }

    private func subscription(_ id: UUID) -> Subscription? {
        container.subscriptionStore.subscriptions.first { $0.id == id }
    }

    // MARK: - Focus

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)
        coordinator.addCoordinatedAnimations {
            if let cell = context.nextFocusedView as? UITableViewCell {
                cell.overrideUserInterfaceStyle = .light
            }
            if let cell = context.previouslyFocusedView as? UITableViewCell {
                cell.overrideUserInterfaceStyle = .unspecified
            }
        }
    }

    // MARK: - Selection

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        defer { tableView.deselectRow(at: indexPath, animated: true) }
        guard let id = dataSource.itemIdentifier(for: indexPath),
              let configuration = container.configurationStore.configurations.first(where: { $0.id == id }) else { return }
        selection.selectedConfiguration = configuration
    }

    // MARK: - Context Menu

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        guard let id = dataSource.itemIdentifier(for: indexPath),
              let configuration = container.configurationStore.configurations.first(where: { $0.id == id }) else { return nil }

        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            guard let self else { return nil }

            var actions: [UIAction] = []

            actions.append(UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { _ in
                self.latency.testLatency(for: configuration)
            })

            actions.append(UIAction(title: String(localized: "Edit"), image: UIImage(systemName: "pencil")) { _ in
                self.presentEditor(for: configuration)
            })

            actions.append(UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                self.container.configurationStore.delete(configuration)
            })

            return UIMenu(children: actions)
        }
    }

    private func subscriptionMenu(for subscription: Subscription) -> UIMenu {
        UIMenu(children: [
            UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { [weak self] _ in
                guard let self else { return }
                self.latency.testLatencies(for: self.container.configurationStore.configurations(for: subscription))
            },
            UIAction(title: String(localized: "Rename"), image: UIImage(systemName: "pencil")) { [weak self] _ in
                self?.presentRenameAlert(for: subscription)
            },
            UIAction(title: String(localized: "Update"), image: UIImage(systemName: "arrow.clockwise")) { [weak self] _ in
                self?.updateSubscription(subscription)
            },
            UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { [container] _ in
                container.subscriptionStore.delete(subscription)
            },
        ])
    }

    // MARK: - Actions

    @objc private func addTapped() {
        let addVC = TVAddProxyViewController(container: container)
        let nav = UINavigationController(rootViewController: addVC)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    @objc private func testAllTapped() {
        let liveSubscriptionIds = Set(container.subscriptionStore.subscriptions.map(\.id))
        let visible = container.configurationStore.configurations.filter { configuration in
            guard let subId = configuration.subscriptionId else { return true }
            return liveSubscriptionIds.contains(subId) && !collapsedSubscriptions.contains(subId)
        }
        latency.testLatencies(for: visible)
    }

    private func toggleCollapse(_ subscription: Subscription) {
        let id = subscription.id
        if collapsedSubscriptions.contains(id) {
            collapsedSubscriptions.remove(id)
        } else {
            collapsedSubscriptions.insert(id)
        }
        applySnapshot()
        refreshVisibleHeaders()
    }

    private func presentEditor(for configuration: ProxyConfiguration) {
        let editor = TVProxyEditorViewController(configuration: configuration) { [container] updated in
            container.configurationStore.update(updated)
        }
        let nav = UINavigationController(rootViewController: editor)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    private func updateSubscription(_ subscription: Subscription) {
        guard updatingSubscription == nil else { return }
        updatingSubscription = subscription
        refreshVisibleHeaders()
        Task {
            do {
                try await container.subscriptionRefresher.refresh(subscription)
            } catch {
                let alert = UIAlertController(title: String(localized: "Update Failed"), message: error.localizedDescription, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .cancel))
                present(alert, animated: true)
            }
            updatingSubscription = nil
            refreshVisibleHeaders()
        }
    }

    private func presentRenameAlert(for subscription: Subscription) {
        let alert = UIAlertController(title: String(localized: "Rename"), message: nil, preferredStyle: .alert)
        alert.addTextField { $0.text = subscription.name }
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default) { [container] _ in
            if let name = alert.textFields?.first?.text, !name.isEmpty {
                container.subscriptionStore.rename(subscription, to: name)
            }
        })
        present(alert, animated: true)
    }

    // MARK: - Empty State

    private func updateEmptyState(isEmpty: Bool) {
        guard isEmpty else {
            tableView.backgroundView = nil
            return
        }
        let emptyLabel = UILabel()
        emptyLabel.text = String(localized: "No Proxies")
        emptyLabel.textColor = .secondaryLabel
        emptyLabel.font = .systemFont(ofSize: 32, weight: .medium)
        emptyLabel.textAlignment = .center
        tableView.backgroundView = emptyLabel
    }
}
