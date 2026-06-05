//
//  TVSubscriptionHeaderView.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import UIKit

class TVSubscriptionHeaderView: UITableViewHeaderFooterView {
    static let reuseIdentifier = "TVSubscriptionHeaderView"

    private let collapseButton = UIButton(configuration: .plain())
    private let updateButton = UIButton(configuration: .plain())
    private let menuButton = UIButton(configuration: .plain())
    private let spinner = UIActivityIndicatorView(style: .medium)

    var onCollapse: (() -> Void)?
    var onUpdate: (() -> Void)?

    override init(reuseIdentifier: String?) {
        super.init(reuseIdentifier: reuseIdentifier)
        setupViews()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupViews() {
        collapseButton.configuration?.imagePadding = 10
        collapseButton.configuration?.titleTextAttributesTransformer = UIConfigurationTextAttributesTransformer { incoming in
            var outgoing = incoming
            outgoing.font = UIFont.systemFont(ofSize: 24, weight: .semibold)
            return outgoing
        }
        updateButton.configuration?.image = UIImage(systemName: "arrow.clockwise")
        menuButton.configuration?.image = UIImage(systemName: "ellipsis.circle")
        menuButton.showsMenuAsPrimaryAction = true

        collapseButton.addAction(UIAction { [weak self] _ in self?.onCollapse?() }, for: .primaryActionTriggered)
        updateButton.addAction(UIAction { [weak self] _ in self?.onUpdate?() }, for: .primaryActionTriggered)

        for view in [collapseButton, updateButton, menuButton, spinner] {
            view.translatesAutoresizingMaskIntoConstraints = false
            contentView.addSubview(view)
        }

        NSLayoutConstraint.activate([
            collapseButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 40),
            collapseButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            collapseButton.trailingAnchor.constraint(lessThanOrEqualTo: updateButton.leadingAnchor, constant: -20),

            menuButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -40),
            menuButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            updateButton.trailingAnchor.constraint(equalTo: menuButton.leadingAnchor, constant: -20),
            updateButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),

            spinner.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -40),
            spinner.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
        ])
    }

    func configure(name: String, isCollapsed: Bool, isUpdating: Bool, menu: UIMenu) {
        collapseButton.configuration?.title = name
        collapseButton.configuration?.image = UIImage(systemName: isCollapsed ? "chevron.right" : "chevron.down")
        menuButton.menu = menu
        menuButton.isHidden = isUpdating
        updateButton.isHidden = isUpdating
        spinner.isHidden = !isUpdating
        if isUpdating {
            spinner.startAnimating()
        } else {
            spinner.stopAnimating()
        }
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        onCollapse = nil
        onUpdate = nil
    }
}
