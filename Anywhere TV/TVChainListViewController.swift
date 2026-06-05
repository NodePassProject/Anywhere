//
//  TVChainListViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

class TVChainListViewController: UITableViewController {

    private let viewModel = VPNViewModel.shared
    private let coordinator = ChainRowCoordinator.shared
    private var dataSource: UITableViewDiffableDataSource<Int, UUID>!

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Chains")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(TVChainCell.self, forCellReuseIdentifier: TVChainCell.reuseIdentifier)
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
        applySnapshot(coordinator.models)
    }

    private func configureDataSource() {
        dataSource = UITableViewDiffableDataSource<Int, UUID>(tableView: tableView) { tableView, indexPath, id in
            let cell = tableView.dequeueReusableCell(withIdentifier: TVChainCell.reuseIdentifier, for: indexPath) as! TVChainCell
            guard let model = ChainRowCoordinator.shared.model(for: id) else { return cell }
            cell.configurationUpdateHandler = { cell, _ in
                (cell as? TVChainCell)?.configure(model)
            }
            return cell
        }
        dataSource.defaultRowAnimation = .fade
    }

    private func applySnapshot(_ models: [ChainListItem]) {
        var snapshot = NSDiffableDataSourceSnapshot<Int, UUID>()
        snapshot.appendSections([0])
        snapshot.appendItems(models.map(\.id), toSection: 0)
        let animate = !dataSource.snapshot().itemIdentifiers.isEmpty
        dataSource.apply(snapshot, animatingDifferences: animate)
        updateEmptyState(isEmpty: models.isEmpty)
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
        guard let id = dataSource.itemIdentifier(for: indexPath), let chain = chain(id) else { return }
        let configurations = ConfigurationStore.shared.configurations
        let proxies = chain.resolveProxies(from: configurations)
        if proxies.count == chain.proxyIds.count && proxies.count >= 2 {
            viewModel.selectChain(chain, configurations: configurations)
        }
    }

    // MARK: - Context Menu

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        guard let id = dataSource.itemIdentifier(for: indexPath), let chain = chain(id) else { return nil }
        let configurations = ConfigurationStore.shared.configurations
        let proxies = chain.resolveProxies(from: configurations)
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2

        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            guard let self else { return nil }
            var actions: [UIAction] = []

            if isValid {
                actions.append(UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { _ in
                    self.viewModel.testChainLatency(for: chain, configurations: configurations)
                })
            }

            actions.append(UIAction(title: String(localized: "Edit"), image: UIImage(systemName: "pencil")) { _ in
                self.presentEditor(for: chain)
            })

            actions.append(UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                ChainStore.shared.delete(chain)
            })

            return UIMenu(children: actions)
        }
    }

    // MARK: - Actions

    @objc private func addTapped() {
        if ConfigurationStore.shared.configurations.count < 2 {
            let alert = UIAlertController(
                title: String(localized: "Not Enough Proxies"),
                message: String(localized: "A proxy chain needs at least 2 proxies."),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .cancel))
            present(alert, animated: true)
            return
        }
        presentEditor(for: nil)
    }

    @objc private func testAllTapped() {
        viewModel.testAllChainLatencies(chains: ChainStore.shared.chains, configurations: ConfigurationStore.shared.configurations)
    }

    private func presentEditor(for chain: ProxyChain?) {
        let editor = TVChainEditorViewController(chain: chain) { newChain in
            if chain != nil {
                ChainStore.shared.update(newChain)
            } else {
                ChainStore.shared.add(newChain)
            }
        }
        let nav = UINavigationController(rootViewController: editor)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    private func chain(_ id: UUID) -> ProxyChain? {
        ChainStore.shared.chains.first { $0.id == id }
    }

    // MARK: - Empty State

    private func updateEmptyState(isEmpty: Bool) {
        guard isEmpty else {
            tableView.backgroundView = nil
            return
        }
        let emptyLabel = UILabel()
        emptyLabel.text = String(localized: "No Chains")
        emptyLabel.textColor = .secondaryLabel
        emptyLabel.font = .systemFont(ofSize: 32, weight: .medium)
        emptyLabel.textAlignment = .center
        tableView.backgroundView = emptyLabel
    }
}
