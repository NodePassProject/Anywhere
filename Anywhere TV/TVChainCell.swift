//
//  TVChainCell.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/29/26.
//

import UIKit

/// Reusable table view cell for displaying a proxy chain on tvOS.
/// Pre-creates all subviews once; `configure(…)` updates text/visibility without rebuilding the hierarchy.
class TVChainCell: UITableViewCell {

    static let reuseIdentifier = "TVChainCell"

    // Name row
    private let nameLabel = UILabel()
    private let checkmarkView = UIImageView()

    // Route preview row (proxy1 → proxy2 → proxy3) — pre-allocated for up to maxProxies
    private let routeRow = UIStackView()
    private var routeLabels: [UILabel] = []
    private var routeArrows: [UIImageView] = []
    private static let maxProxies = 8

    // Info row
    private let infoLabel = UILabel()

    // Error row
    private let errorLabel = UILabel()

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

        // Route preview row — pre-allocate labels and arrows
        routeRow.axis = .horizontal
        routeRow.spacing = 6
        routeRow.alignment = .center

        let arrowConfig = UIImage.SymbolConfiguration(pointSize: 12, weight: .regular)
        for i in 0..<Self.maxProxies {
            if i > 0 {
                let arrow = UIImageView(image: UIImage(systemName: "arrow.right", withConfiguration: arrowConfig))
                arrow.tintColor = .tertiaryLabel
                arrow.setContentHuggingPriority(.required, for: .horizontal)
                routeRow.addArrangedSubview(arrow)
                routeArrows.append(arrow)
            }

            let label = UILabel()
            label.font = .systemFont(ofSize: 22, weight: .regular)
            label.textColor = .secondaryLabel
            label.lineBreakMode = .byTruncatingTail
            label.setContentHuggingPriority(.required, for: .horizontal)
            routeRow.addArrangedSubview(label)
            routeLabels.append(label)
        }

        vStack.addArrangedSubview(routeRow)

        // Info row
        infoLabel.font = .systemFont(ofSize: 20, weight: .regular)
        infoLabel.textColor = .tertiaryLabel
        infoLabel.lineBreakMode = .byTruncatingTail
        vStack.addArrangedSubview(infoLabel)

        // Error row
        errorLabel.font = .systemFont(ofSize: 22, weight: .regular)
        errorLabel.textColor = .systemRed
        vStack.addArrangedSubview(errorLabel)
    }

    // MARK: - Configuration

    func configure(
        name: String,
        isSelected: Bool,
        proxyNames: [String],
        isValid: Bool,
        infoText: String
    ) {
        nameLabel.text = name
        checkmarkView.isHidden = !isSelected

        if isValid {
            routeRow.isHidden = false
            infoLabel.isHidden = false
            errorLabel.isHidden = true
            contentView.alpha = 1.0

            // Update route labels/arrows visibility
            for (index, label) in routeLabels.enumerated() {
                if index < proxyNames.count {
                    label.text = proxyNames[index]
                    label.isHidden = false
                } else {
                    label.isHidden = true
                }
                // Arrow before this label (arrows array is offset by 1)
                if index > 0 {
                    routeArrows[index - 1].isHidden = index >= proxyNames.count
                }
            }

            infoLabel.text = infoText
        } else {
            routeRow.isHidden = true
            infoLabel.isHidden = true
            errorLabel.isHidden = false
            errorLabel.text = String(localized: "Invalid chain — some proxies are missing")
            contentView.alpha = 0.6
        }
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        accessoryView = nil
        contentView.alpha = 1.0
    }
}
