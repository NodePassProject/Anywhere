//
//  TVToggleRow.swift
//  Anywhere
//
//  Created by NodePassProject on 8/27/26.
//

import UIKit

class TVToggleRow: UIButton {
    private let titleTextLabel = UILabel()
    private let valueLabel = UILabel()
    private let onColor: UIColor

    init(title: String, onColor: UIColor = .systemGreen) {
        self.onColor = onColor
        super.init(frame: .zero)
        translatesAutoresizingMaskIntoConstraints = false
        backgroundColor = UIColor.white.withAlphaComponent(0.1)
        layer.cornerRadius = 16

        titleTextLabel.text = title
        titleTextLabel.font = .systemFont(ofSize: 32, weight: .medium)
        titleTextLabel.textColor = .label

        valueLabel.font = .systemFont(ofSize: 28)

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let content = UIStackView(arrangedSubviews: [titleTextLabel, spacer, valueLabel])
        content.spacing = 16
        content.translatesAutoresizingMaskIntoConstraints = false
        content.isUserInteractionEnabled = false
        addSubview(content)

        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 30),
            content.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -30),
            content.topAnchor.constraint(equalTo: topAnchor, constant: 20),
            content.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -20),
        ])

        setOn(false)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    func setOn(_ on: Bool) {
        valueLabel.text = on ? String(localized: "On") : String(localized: "Off")
        valueLabel.textColor = on ? onColor : .secondaryLabel
    }

    override var isEnabled: Bool {
        didSet { alpha = isEnabled ? 1.0 : 0.5 }
    }

    // MARK: - Focus

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)
        let focused = context.nextFocusedView === self
        coordinator.addCoordinatedAnimations {
            if focused {
                self.transform = CGAffineTransform(scaleX: 1.05, y: 1.05)
                self.layer.shadowColor = UIColor.white.cgColor
                self.layer.shadowRadius = 15
                self.layer.shadowOpacity = 0.2
                self.layer.shadowOffset = .zero
            } else {
                self.transform = .identity
                self.layer.shadowOpacity = 0
            }
        }
    }
}
