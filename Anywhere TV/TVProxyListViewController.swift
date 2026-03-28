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
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

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
            .sink { [weak self] _ in
                guard let self, self.tableView.numberOfSections > 0 else { return }
                self.tableView.reloadSections(IndexSet(0..<self.tableView.numberOfSections), with: .none)
            }
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
        let configurations = configurations(for: indexPath.section)
        let configuration = configurations[indexPath.row]
        let isSelected = viewModel.selectedConfiguration?.id == configuration.id && viewModel.selectedChainId == nil

        cell.contentConfiguration = nil

        let vStackTag = 1001
        let vStack: UIStackView
        if let existing = cell.contentView.viewWithTag(vStackTag) as? UIStackView {
            vStack = existing
            vStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        } else {
            vStack = UIStackView()
            vStack.tag = vStackTag
            vStack.axis = .vertical
            vStack.alignment = .leading
            vStack.spacing = 8
            vStack.translatesAutoresizingMaskIntoConstraints = false
            cell.contentView.addSubview(vStack)
            NSLayoutConstraint.activate([
                vStack.leadingAnchor.constraint(equalTo: cell.contentView.leadingAnchor, constant: 40),
                vStack.trailingAnchor.constraint(lessThanOrEqualTo: cell.contentView.trailingAnchor, constant: -40),
                vStack.topAnchor.constraint(equalTo: cell.contentView.topAnchor, constant: 16),
                vStack.bottomAnchor.constraint(equalTo: cell.contentView.bottomAnchor, constant: -16),
            ])
        }

        // Name row
        let nameRow = UIStackView()
        nameRow.axis = .horizontal
        nameRow.spacing = 12
        nameRow.alignment = .center

        let nameLabel = UILabel()
        nameLabel.text = configuration.name
        nameLabel.font = .systemFont(ofSize: 32, weight: .medium)
        nameLabel.textColor = .label
        nameLabel.setContentHuggingPriority(.required, for: .horizontal)
        nameRow.addArrangedSubview(nameLabel)

        if isSelected {
            let checkmarkConfig = UIImage.SymbolConfiguration(pointSize: 32, weight: .medium)
            let checkmark = UIImageView(image: UIImage(systemName: "checkmark", withConfiguration: checkmarkConfig))
            checkmark.tintColor = .systemBlue
            checkmark.setContentHuggingPriority(.required, for: .horizontal)
            nameRow.addArrangedSubview(checkmark)
        }

        vStack.addArrangedSubview(nameRow)

        // Detail tags row
        let tagsRow = UIStackView()
        tagsRow.axis = .horizontal
        tagsRow.spacing = 8
        tagsRow.alignment = .center

        tagsRow.addArrangedSubview(makeDetailTag(configuration.outboundProtocol.name))
        tagsRow.addArrangedSubview(makeDetailTag(configuration.transport.uppercased()))
        let security = configuration.security.uppercased()
        if security != "NONE" {
            tagsRow.addArrangedSubview(makeDetailTag(security))
        }
        if let flow = configuration.flow, flow.uppercased().contains("VISION") {
            tagsRow.addArrangedSubview(makeDetailTag("Vision"))
        }

        vStack.addArrangedSubview(tagsRow)

        // Latency accessory
        if let result = viewModel.latencyResults[configuration.id] {
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

    private func makeDetailTag(_ text: String) -> UIView {
        let label = UILabel()
        label.text = text
        label.font = .systemFont(ofSize: 20, weight: .medium)
        label.textColor = .secondaryLabel

        let container = UIView()
        container.backgroundColor = UIColor { $0.userInterfaceStyle == .light ? UIColor.black.withAlphaComponent(0.1) : UIColor.white.withAlphaComponent(0.1) }
        container.layer.cornerRadius = 8
        label.translatesAutoresizingMaskIntoConstraints = false
        container.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
            label.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
            label.topAnchor.constraint(equalTo: container.topAnchor, constant: 4),
            label.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -4),
        ])
        return container
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
        let configuration = configurations(for: indexPath.section)[indexPath.row]
        viewModel.selectedConfiguration = configuration
        tableView.deselectRow(at: indexPath, animated: true)
    }

    // MARK: - Context Menu

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        let configurations = configurations(for: indexPath.section)
        let configuration = configurations[indexPath.row]

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
                self.viewModel.deleteConfiguration(configuration)
            })

            // Subscription actions
            if let subscription = self.viewModel.subscription(for: configuration) {
                let subMenu = UIMenu(title: subscription.name, children: [
                    UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { _ in
                        self.viewModel.testLatencies(for: self.viewModel.configurations(for: subscription))
                    },
                    UIAction(title: String(localized: "Rename"), image: UIImage(systemName: "pencil")) { _ in
                        self.presentRenameAlert(for: subscription)
                    },
                    UIAction(title: String(localized: "Update"), image: UIImage(systemName: "arrow.clockwise")) { _ in
                        self.updateSubscription(subscription)
                    },
                    UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                        self.viewModel.deleteSubscription(subscription)
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
        viewModel.testLatencies(for: visibleConfigurations)
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

    private func presentEditor(for configuration: ProxyConfiguration) {
        let editor = TVProxyEditorViewController(configuration: configuration) { [weak self] updated in
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

    private func presentRenameAlert(for subscription: Subscription) {
        let alert = UIAlertController(title: String(localized: "Rename"), message: nil, preferredStyle: .alert)
        alert.addTextField { $0.text = subscription.name }
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .default) { [weak self] _ in
            if let name = alert.textFields?.first?.text, !name.isEmpty {
                self?.viewModel.renameSubscription(subscription, to: name)
            }
        })
        present(alert, animated: true)
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
