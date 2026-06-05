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

    private let viewModel = VPNViewModel.shared
    private let coordinator = ProxyRowCoordinator.shared
    private var dataSource: UITableViewDiffableDataSource<ProxySectionID, UUID>!
    private var hasApplied = false

    private var collapsedSubscriptions = Set<UUID>()
    private var updatingSubscription: Subscription?

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

        collapsedSubscriptions = Set(SubscriptionStore.shared.subscriptions.filter(\.collapsed).map(\.id))
        configureDataSource()
    }
    
    override func updateProperties() {
        super.updateProperties()
        applySnapshot()
    }

    private func configureDataSource() {
        dataSource = UITableViewDiffableDataSource<ProxySectionID, UUID>(tableView: tableView) { tableView, indexPath, id in
            let cell = tableView.dequeueReusableCell(withIdentifier: TVProxyCell.reuseIdentifier, for: indexPath) as! TVProxyCell
            guard let model = ProxyRowCoordinator.shared.model(for: id) else { return cell }
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
        for subscription in SubscriptionStore.shared.subscriptions {
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
        guard case .subscription(let subID)? = dataSource.sectionIdentifier(for: section),
              let subscription = subscription(subID) else { return nil }
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
        SubscriptionStore.shared.subscriptions.first { $0.id == id }
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
              let configuration = ConfigurationStore.shared.configurations.first(where: { $0.id == id }) else { return }
        viewModel.selectedConfiguration = configuration
    }

    // MARK: - Context Menu

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        guard let id = dataSource.itemIdentifier(for: indexPath),
              let configuration = ConfigurationStore.shared.configurations.first(where: { $0.id == id }) else { return nil }

        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            guard let self else { return nil }

            var actions: [UIAction] = []

            actions.append(UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { _ in
                self.viewModel.testLatency(for: configuration)
            })

            actions.append(UIAction(title: String(localized: "Edit"), image: UIImage(systemName: "pencil")) { _ in
                self.presentEditor(for: configuration)
            })

            actions.append(UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                ConfigurationStore.shared.delete(configuration)
            })

            return UIMenu(children: actions)
        }
    }

    private func subscriptionMenu(for subscription: Subscription) -> UIMenu {
        UIMenu(children: [
            UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { [weak self] _ in
                self?.viewModel.testLatencies(for: ConfigurationStore.shared.configurations(for: subscription))
            },
            UIAction(title: String(localized: "Rename"), image: UIImage(systemName: "pencil")) { [weak self] _ in
                self?.presentRenameAlert(for: subscription)
            },
            UIAction(title: String(localized: "Update"), image: UIImage(systemName: "arrow.clockwise")) { [weak self] _ in
                self?.updateSubscription(subscription)
            },
            UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                SubscriptionStore.shared.delete(subscription)
            },
        ])
    }

    // MARK: - Actions

    @objc private func addTapped() {
        let addVC = TVAddProxyViewController()
        let nav = UINavigationController(rootViewController: addVC)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    @objc private func testAllTapped() {
        let visible = ConfigurationStore.shared.configurations.filter { configuration in
            guard let subId = configuration.subscriptionId else { return true }
            return !collapsedSubscriptions.contains(subId)
        }
        viewModel.testLatencies(for: visible)
    }

    private func toggleCollapse(_ subscription: Subscription) {
        let id = subscription.id
        if collapsedSubscriptions.contains(id) {
            collapsedSubscriptions.remove(id)
        } else {
            collapsedSubscriptions.insert(id)
        }
        SubscriptionStore.shared.toggleCollapsed(subscription)
        applySnapshot()
        refreshVisibleHeaders()
    }

    private func presentEditor(for configuration: ProxyConfiguration) {
        let editor = TVProxyEditorViewController(configuration: configuration) { updated in
            ConfigurationStore.shared.update(updated)
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
                try await SubscriptionStore.shared.refresh(subscription)
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
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default) { _ in
            if let name = alert.textFields?.first?.text, !name.isEmpty {
                SubscriptionStore.shared.rename(subscription, to: name)
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
