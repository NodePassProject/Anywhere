//
//  TVChainCell.swift
//  Anywhere
//
//  Created by NodePassProject on 3/29/26.
//

import UIKit

/// Pre-creates all subviews once; `configure(…)` updates text/visibility without rebuilding the hierarchy.
class TVChainCell: UITableViewCell {

    static let reuseIdentifier = "TVChainCell"

    private let nameLabel = UILabel()
    private let checkmarkView = UIImageView()

    private let routeRow = UIStackView()
    private var routeLabels: [UILabel] = []
    private var routeArrows: [UIImageView] = []
    private static let maxProxies = 8

    private let infoLabel = UILabel()

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

        infoLabel.font = .systemFont(ofSize: 20, weight: .regular)
        infoLabel.textColor = .tertiaryLabel
        infoLabel.lineBreakMode = .byTruncatingTail
        vStack.addArrangedSubview(infoLabel)

        errorLabel.font = .systemFont(ofSize: 22, weight: .regular)
        errorLabel.textColor = .systemRed
        vStack.addArrangedSubview(errorLabel)
    }

    // MARK: - Configuration

    func configure(_ item: ChainListItem) {
        nameLabel.text = item.name
        checkmarkView.isHidden = !item.isSelected

        if item.isValid {
            routeRow.isHidden = false
            infoLabel.isHidden = false
            errorLabel.isHidden = true
            contentView.alpha = 1.0

            let proxyNames = item.proxyNames
            for (index, label) in routeLabels.enumerated() {
                if index < proxyNames.count {
                    label.text = proxyNames[index]
                    label.isHidden = false
                } else {
                    label.isHidden = true
                }
                // routeArrows is offset by 1: arrow[i-1] precedes label[i]
                if index > 0 {
                    routeArrows[index - 1].isHidden = index >= proxyNames.count
                }
            }

            infoLabel.text = item.infoText
        } else {
            routeRow.isHidden = true
            infoLabel.isHidden = true
            errorLabel.isHidden = false
            errorLabel.text = String(localized: "Invalid chain — some proxies are missing")
            contentView.alpha = 0.6
        }

        applyLatency(item.latency, isValid: item.isValid)
    }

    private func applyLatency(_ latency: LatencyResult?, isValid: Bool) {
        guard isValid, let latency else {
            accessoryView = nil
            return
        }
        switch latency {
        case .testing:
            let spinner = UIActivityIndicatorView(style: .medium)
            spinner.startAnimating()
            accessoryView = spinner
        case .success(let ms):
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            label.text = String(localized: "\(ms) ms")
            label.textColor = ms < 300 ? .systemGreen : ms < 500 ? .systemYellow : .systemRed
            label.sizeToFit()
            accessoryView = label
        case .failed:
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            label.text = String(localized: "timeout")
            label.textColor = .secondaryLabel
            label.sizeToFit()
            accessoryView = label
        case .insecure:
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            label.text = String(localized: "insecure")
            label.textColor = .secondaryLabel
            label.sizeToFit()
            accessoryView = label
        }
    }

    override func prepareForReuse() {
        super.prepareForReuse()
        accessoryView = nil
        contentView.alpha = 1.0
    }
}
