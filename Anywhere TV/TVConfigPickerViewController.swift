//
//  TVConfigPickerViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit

class TVConfigPickerViewController: UITableViewController {

    private let viewModel = VPNViewModel.shared
    private var items: [PickerItem] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Select Proxy")
        items = viewModel.allPickerItems
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80
        tableView.remembersLastFocusedIndexPath = true
        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped)
        )
    }

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    // MARK: - Table View

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        items.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        let item = items[indexPath.row]

        var content = cell.defaultContentConfiguration()
        content.text = item.name
        content.textProperties.font = .systemFont(ofSize: 28)
        cell.contentConfiguration = content

        let isSelected: Bool
        if let chainId = viewModel.selectedChainId {
            isSelected = item.id == chainId
        } else {
            isSelected = item.id == viewModel.selectedConfiguration?.id
        }
        cell.accessoryType = isSelected ? .checkmark : .none

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
        let item = items[indexPath.row]
        if let configuration = viewModel.configurations.first(where: { $0.id == item.id }) {
            viewModel.selectedConfiguration = configuration
        } else if let chain = viewModel.chains.first(where: { $0.id == item.id }) {
            viewModel.selectChain(chain)
        }
        dismiss(animated: true)
    }
}
