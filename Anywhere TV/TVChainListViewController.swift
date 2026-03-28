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
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

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
            .sink { [weak self] _ in
                guard let self, self.tableView.numberOfSections > 0 else { return }
                self.tableView.reloadSections(IndexSet(0..<self.tableView.numberOfSections), with: .none)
            }
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
        nameLabel.text = chain.name
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

        if isValid {
            // Route preview row: proxy1 → proxy2 → proxy3
            let routeRow = UIStackView()
            routeRow.axis = .horizontal
            routeRow.spacing = 6
            routeRow.alignment = .center

            let arrowConfig = UIImage.SymbolConfiguration(pointSize: 12, weight: .regular)
            for (index, proxy) in proxies.enumerated() {
                if index > 0 {
                    let arrow = UIImageView(image: UIImage(systemName: "arrow.right", withConfiguration: arrowConfig))
                    arrow.tintColor = .tertiaryLabel
                    arrow.setContentHuggingPriority(.required, for: .horizontal)
                    routeRow.addArrangedSubview(arrow)
                }
                let proxyLabel = UILabel()
                proxyLabel.text = proxy.displayName
                proxyLabel.font = .systemFont(ofSize: 22, weight: .regular)
                proxyLabel.textColor = .secondaryLabel
                proxyLabel.lineBreakMode = .byTruncatingTail
                proxyLabel.setContentHuggingPriority(.required, for: .horizontal)
                routeRow.addArrangedSubview(proxyLabel)
            }

            vStack.addArrangedSubview(routeRow)

            // Info row: proxy count · entry → exit
            let infoRow = UIStackView()
            infoRow.axis = .horizontal
            infoRow.spacing = 6
            infoRow.alignment = .center

            var infoText = "\(proxies.count) proxies"
            if let entry = proxies.first, let exit = proxies.last {
                infoText += " · \(entry.serverAddress) → \(exit.serverAddress)"
            }
            let infoLabel = UILabel()
            infoLabel.text = infoText
            infoLabel.font = .systemFont(ofSize: 20, weight: .regular)
            infoLabel.textColor = .tertiaryLabel
            infoLabel.lineBreakMode = .byTruncatingTail
            infoRow.addArrangedSubview(infoLabel)

            vStack.addArrangedSubview(infoRow)
        } else {
            let errorLabel = UILabel()
            errorLabel.text = String(localized: "Invalid chain — some proxies are missing")
            errorLabel.font = .systemFont(ofSize: 22, weight: .regular)
            errorLabel.textColor = .systemRed
            vStack.addArrangedSubview(errorLabel)
        }

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
