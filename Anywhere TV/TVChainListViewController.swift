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
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")

        navigationItem.rightBarButtonItems = [
            UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(addTapped)),
            UIBarButtonItem(title: String(localized: "Test All"), style: .plain, target: self, action: #selector(testAllTapped)),
        ]

        bindViewModel()
    }

    private func bindViewModel() {
        viewModel.$chains
            .combineLatest(viewModel.$configurations, viewModel.$selectedChainId, viewModel.$chainLatencyResults)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.tableView.reloadData() }
            .store(in: &cancellables)
    }

    // MARK: - Table View

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        viewModel.chains.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let chain = viewModel.chains[indexPath.row]
        let proxies = chain.proxyIds.compactMap { id in viewModel.configurations.first(where: { $0.id == id }) }
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
        let isSelected = viewModel.selectedChainId == chain.id

        var content = cell.defaultContentConfiguration()
        content.text = chain.name

        if isValid {
            let route = proxies.map(\.name).joined(separator: " → ")
            var detail = route
            if let entry = proxies.first, let exit = proxies.last {
                detail += "\n\(proxies.count) proxies · \(entry.serverAddress) → \(exit.serverAddress)"
            }
            content.secondaryText = detail
            content.secondaryTextProperties.color = .secondaryLabel
            content.secondaryTextProperties.font = .systemFont(ofSize: 22)
            content.secondaryTextProperties.numberOfLines = 2
        } else {
            content.secondaryText = String(localized: "Invalid chain — some proxies are missing")
            content.secondaryTextProperties.color = .systemRed
            content.secondaryTextProperties.font = .systemFont(ofSize: 22)
        }

        if isSelected {
            content.image = UIImage(systemName: "checkmark.circle.fill")
            content.imageProperties.tintColor = .systemBlue
        }

        cell.contentConfiguration = content

        // Alpha for invalid chains
        cell.contentView.alpha = isValid ? 1.0 : 0.6

        // Latency
        cell.accessoryView = nil
        if isValid, let result = viewModel.chainLatencyResults[chain.id] {
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
        }

        return cell
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
