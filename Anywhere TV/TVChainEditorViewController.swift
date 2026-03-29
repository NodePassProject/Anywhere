//
//  TVChainEditorViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit

class TVChainEditorViewController: UITableViewController {

    private let viewModel = VPNViewModel.shared
    private let existingChain: ProxyChain?
    private let onSave: (ProxyChain) -> Void

    private var name = ""
    private var selectedProxyIds: [UUID] = []

    private var selectedProxies: [ProxyConfiguration] {
        selectedProxyIds.compactMap { id in
            viewModel.configurations.first(where: { $0.id == id })
        }
    }

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && selectedProxies.count >= 2
    }

    // MARK: - Init

    init(chain: ProxyChain? = nil, onSave: @escaping (ProxyChain) -> Void) {
        self.existingChain = chain
        self.onSave = onSave
        super.init(style: .grouped)
    }

    required init?(coder: NSCoder) { fatalError() }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = existingChain != nil ? String(localized: "Edit Chain") : String(localized: "New Chain")
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80
        tableView.remembersLastFocusedIndexPath = true

        navigationItem.leftBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped))
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .save, target: self, action: #selector(saveTapped))

        if let chain = existingChain {
            name = chain.name
            selectedProxyIds = chain.proxyIds
        }
        updateSaveButton()
    }

    // MARK: - Table View

    private enum Section: Int, CaseIterable {
        case name = 0
        case proxies = 1
        case routePreview = 2
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        selectedProxies.count >= 2 ? 3 : 2
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        guard let section = Section(rawValue: section) else { return 0 }
        switch section {
        case .name: return 1
        case .proxies: return selectedProxies.count + 1 // proxies + "Add Proxy" button
        case .routePreview: return 1
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        guard let section = Section(rawValue: section) else { return nil }
        switch section {
        case .name: return nil
        case .proxies: return String(localized: "Proxies")
        case .routePreview: return String(localized: "Route Preview")
        }
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        if Section(rawValue: section) == .proxies && selectedProxies.count < 2 {
            return String(localized: "Add at least 2 proxies to form a chain.")
        }
        return nil
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.accessoryType = .none
        cell.accessoryView = nil

        guard let sectionType = Section(rawValue: indexPath.section) else { return cell }
        switch sectionType {
        case .name:
            var content = cell.defaultContentConfiguration()
            content.text = String(localized: "Name")
            if name.isEmpty {
                content.secondaryText = String(localized: "Name")
                content.secondaryTextProperties.color = .tertiaryLabel
            } else {
                content.secondaryText = name
                content.secondaryTextProperties.color = .label
            }
            cell.contentConfiguration = content
            cell.accessoryType = .disclosureIndicator

        case .proxies:
            let proxies = selectedProxies
            if indexPath.row < proxies.count {
                let proxy = proxies[indexPath.row]
                let index = indexPath.row

                var content = cell.defaultContentConfiguration()
                content.text = "\(index + 1). \(proxy.name)"
                content.secondaryText = "\(proxy.serverAddress):\(proxy.serverPort)"
                content.secondaryTextProperties.color = .secondaryLabel

                // Entry/Exit indicator
                if index == 0 {
                    content.image = UIImage(systemName: "circle.fill")
                    content.imageProperties.tintColor = .systemBlue
                } else if index == proxies.count - 1 {
                    content.image = UIImage(systemName: "circle.fill")
                    content.imageProperties.tintColor = .systemGreen
                } else {
                    content.image = UIImage(systemName: "circle.fill")
                    content.imageProperties.tintColor = .secondaryLabel
                }

                cell.contentConfiguration = content

                // Role label
                let roleLabel = UILabel()
                if index == 0 {
                    roleLabel.text = String(localized: "Entry")
                } else if index == proxies.count - 1 {
                    roleLabel.text = String(localized: "Exit")
                }
                roleLabel.font = .systemFont(ofSize: 20)
                roleLabel.textColor = .secondaryLabel
                roleLabel.sizeToFit()
                cell.accessoryView = roleLabel
            } else {
                // Add proxy button
                var content = cell.defaultContentConfiguration()
                content.text = String(localized: "Add Proxy")
                content.image = UIImage(systemName: "plus")
                content.imageProperties.tintColor = .systemBlue
                content.textProperties.color = .systemBlue
                cell.contentConfiguration = content
            }

        case .routePreview:
            var content = cell.defaultContentConfiguration()
            let proxies = selectedProxies
            let routeParts = [String(localized: "You")] + proxies.map(\.name) + [String(localized: "Target")]
            content.text = routeParts.joined(separator: " → ")
            content.textProperties.font = .systemFont(ofSize: 22)
            content.textProperties.color = .secondaryLabel
            cell.contentConfiguration = content
            cell.isUserInteractionEnabled = false
        }

        return cell
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
        tableView.deselectRow(at: indexPath, animated: true)

        guard let sectionType = Section(rawValue: indexPath.section) else { return }
        switch sectionType {
        case .name:
            let inputVC = TVTextInputViewController(
                title: String(localized: "Name"),
                currentValue: name,
                placeholder: String(localized: "Name")
            ) { [weak self] value in
                self?.name = value
                self?.tableView.reloadData()
                self?.updateSaveButton()
            }
            let nav = UINavigationController(rootViewController: inputVC)
            nav.modalPresentationStyle = .fullScreen
            present(nav, animated: true)

        case .proxies:
            if indexPath.row >= selectedProxies.count {
                // Add proxy
                presentProxyPicker()
            }

        case .routePreview:
            break
        }
    }

    // MARK: - Context Menu (Move/Remove)

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        guard Section(rawValue: indexPath.section) == .proxies,
              indexPath.row < selectedProxies.count else { return nil }

        let index = indexPath.row
        let proxyCount = selectedProxies.count

        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            var actions: [UIAction] = []

            if index > 0 {
                actions.append(UIAction(title: String(localized: "Move Up"), image: UIImage(systemName: "arrow.up")) { _ in
                    self?.moveProxy(from: index, to: index - 1)
                })
            }
            if index < proxyCount - 1 {
                actions.append(UIAction(title: String(localized: "Move Down"), image: UIImage(systemName: "arrow.down")) { _ in
                    self?.moveProxy(from: index, to: index + 1)
                })
            }
            actions.append(UIAction(title: String(localized: "Remove"), image: UIImage(systemName: "minus.circle"), attributes: .destructive) { _ in
                self?.removeProxy(at: index)
            })

            return UIMenu(children: actions)
        }
    }

    // MARK: - Actions

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    @objc private func saveTapped() {
        var chain = existingChain ?? ProxyChain(name: name)
        chain.name = name.trimmingCharacters(in: .whitespaces)
        chain.proxyIds = selectedProxyIds
        onSave(chain)
        dismiss(animated: true)
    }

    private func updateSaveButton() {
        navigationItem.rightBarButtonItem?.isEnabled = canSave
    }

    private func moveProxy(from: Int, to: Int) {
        let id = selectedProxyIds.remove(at: from)
        selectedProxyIds.insert(id, at: to)
        tableView.reloadData()
    }

    private func removeProxy(at index: Int) {
        selectedProxyIds.remove(at: index)
        tableView.reloadData()
        updateSaveButton()
    }

    private func presentProxyPicker() {
        let picker = TVProxyPickerViewController(
            configurations: viewModel.configurations,
            excludedIds: Set(selectedProxyIds)
        ) { [weak self] selected in
            self?.selectedProxyIds.append(selected.id)
            self?.tableView.reloadData()
            self?.updateSaveButton()
        }
        let nav = UINavigationController(rootViewController: picker)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }
}

// MARK: - Proxy Picker

class TVProxyPickerViewController: UITableViewController {

    private let configurations: [ProxyConfiguration]
    private let excludedIds: Set<UUID>
    private let onSelect: (ProxyConfiguration) -> Void

    private var available: [ProxyConfiguration] {
        configurations.filter { !excludedIds.contains($0.id) }
    }

    init(configurations: [ProxyConfiguration], excludedIds: Set<UUID>, onSelect: @escaping (ProxyConfiguration) -> Void) {
        self.configurations = configurations
        self.excludedIds = excludedIds
        self.onSelect = onSelect
        super.init(style: .grouped)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Select Proxy")
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped)
        )
    }

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        available.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let proxy = available[indexPath.row]

        var content = cell.defaultContentConfiguration()
        content.text = proxy.name
        content.secondaryText = "\(proxy.serverAddress):\(proxy.serverPort)"
        content.secondaryTextProperties.color = .secondaryLabel
        cell.contentConfiguration = content

        return cell
    }

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

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        onSelect(available[indexPath.row])
        dismiss(animated: true)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if available.isEmpty {
            let label = UILabel()
            label.text = String(localized: "No Proxies")
            label.textColor = .secondaryLabel
            label.font = .systemFont(ofSize: 28, weight: .medium)
            label.textAlignment = .center
            tableView.backgroundView = label
        } else {
            tableView.backgroundView = nil
        }
    }
}
