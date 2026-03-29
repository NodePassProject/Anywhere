//
//  TVProxyCell.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/29/26.
//

import UIKit

/// Reusable table view cell for displaying a proxy configuration on tvOS.
/// Pre-creates all subviews once; `configure(…)` updates text/visibility without rebuilding the hierarchy.
class TVProxyCell: UITableViewCell {

    static let reuseIdentifier = "TVProxyCell"

    // Name row
    private let nameLabel = UILabel()
    private let checkmarkView = UIImageView()

    // Tags row (up to 4 tags: protocol, transport, security, vision)
    private let tagsRow = UIStackView()

    // Pre-allocated tag containers (reused each configure call)
    private var tagContainers: [(container: UIView, label: UILabel)] = []
    private static let maxTags = 4

    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func setupViews() {
        let vStack = UIStackView()
        vStack.axis = .vertical
        vStack.alignment = .leading
        vStack.spacing = 8
        vStack.translatesAutoresizingMaskIntoConstraints = false
        contentView.addSubview(vStack)
        NSLayoutConstraint.activate([
            vStack.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 40),
            vStack.trailingAnchor.constraint(lessThanOrEqualTo: contentView.trailingAnchor, constant: -40),
            vStack.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 16),
            vStack.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -16),
        ])

        // Name row
        let nameRow = UIStackView()
        nameRow.axis = .horizontal
        nameRow.spacing = 12
        nameRow.alignment = .center

        nameLabel.font = .systemFont(ofSize: 32, weight: .medium)
        nameLabel.textColor = .label
        nameLabel.setContentHuggingPriority(.required, for: .horizontal)
        nameRow.addArrangedSubview(nameLabel)

        let checkmarkConfig = UIImage.SymbolConfiguration(pointSize: 32, weight: .medium)
        checkmarkView.image = UIImage(systemName: "checkmark", withConfiguration: checkmarkConfig)
        checkmarkView.tintColor = .systemBlue
        checkmarkView.setContentHuggingPriority(.required, for: .horizontal)
        nameRow.addArrangedSubview(checkmarkView)

        vStack.addArrangedSubview(nameRow)

        // Tags row
        tagsRow.axis = .horizontal
        tagsRow.spacing = 8
        tagsRow.alignment = .center

        for _ in 0..<Self.maxTags {
            let label = UILabel()
            label.font = .systemFont(ofSize: 20, weight: .medium)
            label.textColor = .secondaryLabel
            label.translatesAutoresizingMaskIntoConstraints = false

            let container = UIView()
            container.backgroundColor = UIColor { $0.userInterfaceStyle == .light ? UIColor.black.withAlphaComponent(0.1) : UIColor.white.withAlphaComponent(0.1) }
            container.layer.cornerRadius = 8
            container.addSubview(label)
            NSLayoutConstraint.activate([
                label.leadingAnchor.constraint(equalTo: container.leadingAnchor, constant: 12),
                label.trailingAnchor.constraint(equalTo: container.trailingAnchor, constant: -12),
                label.topAnchor.constraint(equalTo: container.topAnchor, constant: 4),
                label.bottomAnchor.constraint(equalTo: container.bottomAnchor, constant: -4),
            ])

            tagsRow.addArrangedSubview(container)
            tagContainers.append((container, label))
        }

        vStack.addArrangedSubview(tagsRow)
    }

    // MARK: - Configuration

    func configure(
        name: String,
        isSelected: Bool,
        protocolName: String,
        transport: String,
        security: String,
        flow: String?
    ) {
        nameLabel.text = name
        checkmarkView.isHidden = !isSelected

        // Build tag list
        var tags = [protocolName, transport.uppercased()]
        let sec = security.uppercased()
        if sec != "NONE" { tags.append(sec) }
        if let flow, flow.uppercased().contains("VISION") { tags.append("Vision") }

        for (index, pair) in tagContainers.enumerated() {
            if index < tags.count {
                pair.label.text = tags[index]
                pair.container.isHidden = false
            } else {
                pair.container.isHidden = true
            }
        }
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        accessoryView = nil
    }
}
