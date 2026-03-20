//
//  TVProxyListViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit
import NetworkExtension
import Combine

class TVProxyListViewController: UITableViewController {

    private let viewModel = VPNViewModel.shared
    private var cancellables = Set<AnyCancellable>()

    private var collapsedSubscriptions = Set<UUID>()
    private var updatingSubscription: Subscription?

    // MARK: - Computed Data

    private var standaloneConfigurations: [ProxyConfiguration] {
        viewModel.configurations.filter { $0.subscriptionId == nil }
    }

    private var subscribedGroups: [(Subscription, [ProxyConfiguration])] {
        viewModel.subscriptions.compactMap { subscription in
            let configs = viewModel.configurations(for: subscription)
            return configs.isEmpty ? nil : (subscription, configs)
        }
    }

    private var sectionCount: Int {
        (standaloneConfigurations.isEmpty ? 0 : 1) + subscribedGroups.count
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Proxies")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")

        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(addTapped)),
            UIBarButtonItem(title: String(localized: "Test All"), style: .plain, target: self, action: #selector(testAllTapped)),
        ]

        collapsedSubscriptions = Set(viewModel.subscriptions.filter(\.collapsed).map(\.id))
        bindViewModel()
    }

    private func bindViewModel() {
        viewModel.$configurations
            .combineLatest(viewModel.$subscriptions, viewModel.$selectedConfiguration, viewModel.$latencyResults)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.tableView.reloadData() }
            .store(in: &cancellables)
    }

    // MARK: - Section Helpers

    private enum SectionType {
        case standalone
        case subscription(Subscription, [ProxyConfiguration])
    }

    private func sectionType(for section: Int) -> SectionType {
        let hasStandalone = !standaloneConfigurations.isEmpty
        if hasStandalone && section == 0 { return .standalone }
        let groupIndex = hasStandalone ? section - 1 : section
        let group = subscribedGroups[groupIndex]
        return .subscription(group.0, group.1)
    }

    private func configurations(for section: Int) -> [ProxyConfiguration] {
        switch sectionType(for: section) {
        case .standalone:
            return standaloneConfigurations
        case .subscription(let sub, let configs):
            return collapsedSubscriptions.contains(sub.id) ? [] : configs
        }
    }

    // MARK: - Table View Data Source

    override func numberOfSections(in tableView: UITableView) -> Int {
        sectionCount
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        configurations(for: section).count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch sectionType(for: section) {
        case .standalone: return nil
        case .subscription(let sub, _): return sub.name
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let configs = configurations(for: indexPath.section)
        let config = configs[indexPath.row]
        let isSelected = viewModel.selectedConfiguration?.id == config.id && viewModel.selectedChainId == nil

        var content = cell.defaultContentConfiguration()
        content.text = config.name

        var details = "\(config.serverAddress):\(config.serverPort)"
        details += " · \(config.outboundProtocol.name)"
        details += " · \(config.transport.uppercased())"
        let security = config.security.uppercased()
        if security != "NONE" { details += " · \(security)" }
        if let flow = config.flow, flow.uppercased().contains("VISION") { details += " · Vision" }
        content.secondaryText = details
        content.secondaryTextProperties.color = .secondaryLabel
        content.secondaryTextProperties.font = .systemFont(ofSize: 22)

        if isSelected {
            content.image = UIImage(systemName: "checkmark.circle.fill")
            content.imageProperties.tintColor = .systemBlue
        }

        cell.contentConfiguration = content

        // Latency accessory
        if let result = viewModel.latencyResults[config.id] {
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            switch result {
            case .testing:
                let spinner = UIActivityIndicatorView(style: .medium)
                spinner.startAnimating()
                cell.accessoryView = spinner
                return cell
            case .success(let ms):
                label.text = "\(ms) ms"
                label.textColor = ms < 300 ? .systemGreen : ms < 500 ? .systemYellow : .systemRed
            case .failed:
                label.text = String(localized: "timeout")
                label.textColor = .secondaryLabel
            case .insecure:
                label.text = String(localized: "insecure")
                label.textColor = .secondaryLabel
            }
            label.sizeToFit()
            cell.accessoryView = label
        } else {
            cell.accessoryView = nil
        }

        return cell
    }

    // MARK: - Selection

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let config = configurations(for: indexPath.section)[indexPath.row]
        viewModel.selectedConfiguration = config
        tableView.deselectRow(at: indexPath, animated: true)
    }

    // MARK: - Context Menu

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        let configs = configurations(for: indexPath.section)
        let config = configs[indexPath.row]

        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            guard let self else { return nil }

            var actions: [UIAction] = []

            actions.append(UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { _ in
                self.viewModel.testLatency(for: config)
            })

            actions.append(UIAction(title: String(localized: "Edit"), image: UIImage(systemName: "pencil")) { _ in
                self.presentEditor(for: config)
            })

            actions.append(UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                self.viewModel.deleteConfiguration(config)
            })

            // Subscription actions
            if let sub = self.viewModel.subscription(for: config) {
                let subMenu = UIMenu(title: sub.name, children: [
                    UIAction(title: String(localized: "Update"), image: UIImage(systemName: "arrow.clockwise")) { _ in
                        self.updateSubscription(sub)
                    },
                    UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                        self.viewModel.deleteSubscription(sub)
                    },
                ])
                actions.append(contentsOf: [UIAction]())
                return UIMenu(children: actions + [subMenu])
            }

            return UIMenu(children: actions)
        }
    }

    // MARK: - Section Header (Subscription Collapse)

    override func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        guard case .subscription(let sub, _) = sectionType(for: section) else { return nil }

        let header = UIView()
        let isCollapsed = collapsedSubscriptions.contains(sub.id)

        let button = UIButton(type: .system)
        let chevron = isCollapsed ? "chevron.right" : "chevron.down"
        button.setImage(UIImage(systemName: chevron), for: .normal)
        button.setTitle("  " + sub.name, for: .normal)
        button.titleLabel?.font = .systemFont(ofSize: 24, weight: .semibold)
        button.contentHorizontalAlignment = .leading
        button.tag = section
        button.addTarget(self, action: #selector(toggleSection(_:)), for: .primaryActionTriggered)
        button.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(button)

        let updateBtn = UIButton(type: .system)
        if updatingSubscription?.id == sub.id {
            let spinner = UIActivityIndicatorView(style: .medium)
            spinner.startAnimating()
            spinner.translatesAutoresizingMaskIntoConstraints = false
            header.addSubview(spinner)
            NSLayoutConstraint.activate([
                spinner.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -40),
                spinner.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            ])
        } else {
            updateBtn.setImage(UIImage(systemName: "arrow.clockwise"), for: .normal)
            updateBtn.tag = section
            updateBtn.addTarget(self, action: #selector(updateSubscriptionFromHeader(_:)), for: .primaryActionTriggered)
            updateBtn.translatesAutoresizingMaskIntoConstraints = false
            header.addSubview(updateBtn)
            NSLayoutConstraint.activate([
                updateBtn.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -40),
                updateBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
                updateBtn.widthAnchor.constraint(equalToConstant: 60),
            ])
        }

        NSLayoutConstraint.activate([
            button.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 40),
            button.centerYAnchor.constraint(equalTo: header.centerYAnchor),
        ])

        return header
    }

    override func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        switch sectionType(for: section) {
        case .standalone: return UITableView.automaticDimension
        case .subscription: return 66
        }
    }

    // MARK: - Actions

    @objc private func addTapped() {
        let addVC = TVAddProxyViewController()
        let nav = UINavigationController(rootViewController: addVC)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    @objc private func testAllTapped() {
        let visibleConfigurations = standaloneConfigurations + subscribedGroups
            .filter { !collapsedSubscriptions.contains($0.0.id) }
            .flatMap(\.1)
        viewModel.testAllLatencies(for: visibleConfigurations)
    }

    @objc private func toggleSection(_ sender: UIButton) {
        let section = sender.tag
        guard case .subscription(let sub, _) = sectionType(for: section) else { return }
        let id = sub.id
        if collapsedSubscriptions.contains(id) {
            collapsedSubscriptions.remove(id)
        } else {
            collapsedSubscriptions.insert(id)
        }
        viewModel.toggleSubscriptionCollapsed(sub)
        tableView.reloadSections(IndexSet(integer: section), with: .automatic)
    }

    @objc private func updateSubscriptionFromHeader(_ sender: UIButton) {
        let section = sender.tag
        guard case .subscription(let sub, _) = sectionType(for: section) else { return }
        updateSubscription(sub)
    }

    private func presentEditor(for config: ProxyConfiguration) {
        let editor = TVProxyEditorViewController(configuration: config) { [weak self] updated in
            self?.viewModel.updateConfiguration(updated)
        }
        let nav = UINavigationController(rootViewController: editor)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    private func updateSubscription(_ subscription: Subscription) {
        guard updatingSubscription == nil else { return }
        updatingSubscription = subscription
        tableView.reloadData()
        Task {
            do {
                try await viewModel.updateSubscription(subscription)
            } catch {
                let alert = UIAlertController(title: String(localized: "Update Failed"), message: error.localizedDescription, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .cancel))
                present(alert, animated: true)
            }
            updatingSubscription = nil
            tableView.reloadData()
        }
    }

    // MARK: - Empty State

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if viewModel.configurations.isEmpty {
            let emptyLabel = UILabel()
            emptyLabel.text = String(localized: "No Proxies")
            emptyLabel.textColor = .secondaryLabel
            emptyLabel.font = .systemFont(ofSize: 32, weight: .medium)
            emptyLabel.textAlignment = .center
            tableView.backgroundView = emptyLabel
        } else {
            tableView.backgroundView = nil
        }
    }
}
