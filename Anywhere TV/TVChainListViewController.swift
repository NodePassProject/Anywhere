//
//  TVChainListViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit
import Combine

class TVChainListViewController: UITableViewController {

    private let viewModel = VPNViewModel.shared
    private var cancellables = Set<AnyCancellable>()

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Chains")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(TVChainCell.self, forCellReuseIdentifier: TVChainCell.reuseIdentifier)
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(addTapped)),
            UIBarButtonItem(title: String(localized: "Test All"), style: .plain, target: self, action: #selector(testAllTapped)),
        ]

        bindViewModel()
    }

    private func bindViewModel() {
        // Structural changes — full reload
        viewModel.$chains
            .combineLatest(viewModel.$configurations, viewModel.$selectedChainId)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                self?.tableView.reloadData()
            }
            .store(in: &cancellables)

        // Latency changes — update only visible cells
        viewModel.$chainLatencyResults
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in
                self?.updateVisibleLatencyAccessories()
            }
            .store(in: &cancellables)
    }

    // MARK: - Table View

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        viewModel.chains.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: TVChainCell.reuseIdentifier, for: indexPath) as! TVChainCell
        let chain = viewModel.chains[indexPath.row]
        let proxies = chain.proxyIds.compactMap { id in viewModel.configurations.first(where: { $0.id == id }) }
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
        let isSelected = viewModel.selectedChainId == chain.id

        var infoText = "\(proxies.count) proxies"
        if let entry = proxies.first, let exit = proxies.last {
            infoText += " · \(entry.serverAddress) → \(exit.serverAddress)"
        }

        cell.configure(
            name: chain.name,
            isSelected: isSelected,
            proxyNames: proxies.map(\.name),
            isValid: isValid,
            infoText: infoText
        )

        applyLatencyAccessory(to: cell, chainId: chain.id, isValid: isValid)

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
        let chain = viewModel.chains[indexPath.row]
        let proxies = chain.proxyIds.compactMap { id in viewModel.configurations.first(where: { $0.id == id }) }
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
        if isValid {
            viewModel.selectChain(chain)
        }
        tableView.deselectRow(at: indexPath, animated: true)
    }

    // MARK: - Context Menu

    override func tableView(_ tableView: UITableView, contextMenuConfigurationForRowAt indexPath: IndexPath, point: CGPoint) -> UIContextMenuConfiguration? {
        let chain = viewModel.chains[indexPath.row]
        let proxies = chain.proxyIds.compactMap { id in viewModel.configurations.first(where: { $0.id == id }) }
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2

        return UIContextMenuConfiguration(identifier: nil, previewProvider: nil) { [weak self] _ in
            guard let self else { return nil }
            var actions: [UIAction] = []

            if isValid {
                actions.append(UIAction(title: String(localized: "Test Latency"), image: UIImage(systemName: "gauge.with.dots.needle.67percent")) { _ in
                    self.viewModel.testChainLatency(for: chain)
                })
            }

            actions.append(UIAction(title: String(localized: "Edit"), image: UIImage(systemName: "pencil")) { _ in
                self.presentEditor(for: chain)
            })

            actions.append(UIAction(title: String(localized: "Delete"), image: UIImage(systemName: "trash"), attributes: .destructive) { _ in
                self.viewModel.deleteChain(chain)
            })

            return UIMenu(children: actions)
        }
    }

    // MARK: - Actions

    @objc private func addTapped() {
        if viewModel.configurations.count < 2 {
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
        viewModel.testAllChainLatencies()
    }

    private func presentEditor(for chain: ProxyChain?) {
        let editor = TVChainEditorViewController(chain: chain) { [weak self] newChain in
            if chain != nil {
                self?.viewModel.updateChain(newChain)
            } else {
                self?.viewModel.addChain(newChain)
            }
        }
        let nav = UINavigationController(rootViewController: editor)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    // MARK: - Latency Accessories

    private func applyLatencyAccessory(to cell: UITableViewCell, chainId: UUID, isValid: Bool) {
        guard isValid, let result = viewModel.chainLatencyResults[chainId] else {
            cell.accessoryView = nil
            return
        }
        switch result {
        case .testing:
            let spinner = UIActivityIndicatorView(style: .medium)
            spinner.startAnimating()
            cell.accessoryView = spinner
        case .success(let ms):
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            label.text = String(localized: "\(ms) ms")
            label.textColor = ms < 300 ? .systemGreen : ms < 500 ? .systemYellow : .systemRed
            label.sizeToFit()
            cell.accessoryView = label
        case .failed:
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            label.text = String(localized: "timeout")
            label.textColor = .secondaryLabel
            label.sizeToFit()
            cell.accessoryView = label
        case .insecure:
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            label.text = String(localized: "insecure")
            label.textColor = .secondaryLabel
            label.sizeToFit()
            cell.accessoryView = label
        }
    }

    private func updateVisibleLatencyAccessories() {
        for cell in tableView.visibleCells {
            guard let indexPath = tableView.indexPath(for: cell) else { continue }
            guard indexPath.row < viewModel.chains.count else { continue }
            let chain = viewModel.chains[indexPath.row]
            let proxies = chain.proxyIds.compactMap { id in viewModel.configurations.first(where: { $0.id == id }) }
            let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
            applyLatencyAccessory(to: cell, chainId: chain.id, isValid: isValid)
        }
    }

    // MARK: - Empty State

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if viewModel.chains.isEmpty {
            let emptyLabel = UILabel()
            emptyLabel.text = String(localized: "No Chains")
            emptyLabel.textColor = .secondaryLabel
            emptyLabel.font = .systemFont(ofSize: 32, weight: .medium)
            emptyLabel.textAlignment = .center
            tableView.backgroundView = emptyLabel
        } else {
            tableView.backgroundView = nil
        }
    }
}
