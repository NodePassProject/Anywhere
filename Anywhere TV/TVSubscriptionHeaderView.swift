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
    private let editButton = UIButton(configuration: .plain())
    private let updateButton = UIButton(configuration: .plain())
    private let deleteButton = UIButton(configuration: .plain())
    private let spinner = UIActivityIndicatorView(style: .medium)

    var onCollapse: (() -> Void)?
    var onEdit: (() -> Void)?
    var onUpdate: (() -> Void)?
    var onDelete: (() -> Void)?

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
        editButton.configuration?.image = UIImage(systemName: "pencil")
        editButton.accessibilityLabel = String(localized: "Edit")
        updateButton.configuration?.image = UIImage(systemName: "arrow.clockwise")
        updateButton.accessibilityLabel = String(localized: "Update")
        deleteButton.configuration?.image = UIImage(systemName: "trash")
        deleteButton.configuration?.baseForegroundColor = .systemRed
        deleteButton.accessibilityLabel = String(localized: "Delete")

        collapseButton.addAction(UIAction { [weak self] _ in self?.onCollapse?() }, for: .primaryActionTriggered)
        editButton.addAction(UIAction { [weak self] _ in self?.onEdit?() }, for: .primaryActionTriggered)
        updateButton.addAction(UIAction { [weak self] _ in self?.onUpdate?() }, for: .primaryActionTriggered)
        deleteButton.addAction(UIAction { [weak self] _ in self?.onDelete?() }, for: .primaryActionTriggered)

        for view in [collapseButton, editButton, updateButton, deleteButton, spinner] {
            view.translatesAutoresizingMaskIntoConstraints = false
            contentView.addSubview(view)
        }

        NSLayoutConstraint.activate([
            collapseButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 40),
            collapseButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            collapseButton.trailingAnchor.constraint(lessThanOrEqualTo: editButton.leadingAnchor, constant: -20),

            deleteButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -40),
            deleteButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            updateButton.trailingAnchor.constraint(equalTo: deleteButton.leadingAnchor, constant: -20),
            updateButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            editButton.trailingAnchor.constraint(equalTo: updateButton.leadingAnchor, constant: -20),
            editButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),

            spinner.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -40),
            spinner.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
        ])
    }

    func configure(name: String, isCollapsed: Bool, isUpdating: Bool) {
        collapseButton.configuration?.title = name
        collapseButton.configuration?.image = UIImage(systemName: isCollapsed ? "chevron.right" : "chevron.down")
        for button in [editButton, updateButton, deleteButton] {
            button.isHidden = isUpdating
        }
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
        onEdit = nil
        onUpdate = nil
        onDelete = nil
    }
}
