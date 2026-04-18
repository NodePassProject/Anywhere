//
//  TVSettingsViewController.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit
import Combine

class TVSettingsViewController: UIViewController {

    private let viewModel = VPNViewModel.shared
    private var cancellable: AnyCancellable?

    // Left side
    private let iconView = UIImageView()
    private let descriptionLabel = UILabel()

    // Right side
    private let alwaysOnButton = UIButton(type: .custom)
    private let alwaysOnLabel = UILabel()
    private let alwaysOnValueLabel = UILabel()

    private let insecureButton = UIButton(type: .custom)
    private let insecureLabel = UILabel()
    private let insecureValueLabel = UILabel()

    private var alwaysOnEnabled: Bool {
        get { AWCore.getAlwaysOnEnabled() }
        set {
            AWCore.setAlwaysOnEnabled(newValue)
            viewModel.reconnectVPN()
            updateAppearance()
        }
    }

    private var allowInsecure: Bool {
        get { AWCore.getAllowInsecure() }
        set {
            AWCore.setAllowInsecure(newValue)
            AWCore.notifyCertificatePolicyChanged()
            updateAppearance()
        }
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Settings")
        setupLeftSide()
        setupRightSide()
        setupLayout()
        updateAppearance()
    }

    // MARK: - Left Side

    private func setupLeftSide() {
        iconView.image = UIImage(named: "AnywhereSymbol")
        iconView.contentMode = .scaleAspectFit
        iconView.translatesAutoresizingMaskIntoConstraints = false

        descriptionLabel.font = .systemFont(ofSize: 30)
        descriptionLabel.textColor = .secondaryLabel
        descriptionLabel.numberOfLines = 0
        descriptionLabel.textAlignment = .center
        descriptionLabel.alpha = 0
        descriptionLabel.translatesAutoresizingMaskIntoConstraints = false
    }

    // MARK: - Right Side

    private func setupRightSide() {
        configureToggleButton(
            button: alwaysOnButton,
            label: alwaysOnLabel,
            valueLabel: alwaysOnValueLabel,
            title: String(localized: "Always On"),
            action: #selector(alwaysOnTapped)
        )

        configureToggleButton(
            button: insecureButton,
            label: insecureLabel,
            valueLabel: insecureValueLabel,
            title: String(localized: "Allow Insecure"),
            action: #selector(insecureTapped)
        )
    }

    private func configureToggleButton(button: UIButton, label: UILabel, valueLabel: UILabel, title: String, action: Selector) {
        label.text = title
        label.font = .systemFont(ofSize: 32, weight: .medium)
        label.textColor = .label
        label.translatesAutoresizingMaskIntoConstraints = false

        valueLabel.font = .systemFont(ofSize: 28)
        valueLabel.translatesAutoresizingMaskIntoConstraints = false

        button.translatesAutoresizingMaskIntoConstraints = false
        button.backgroundColor = UIColor.white.withAlphaComponent(0.1)
        button.layer.cornerRadius = 16
        button.addTarget(self, action: action, for: .primaryActionTriggered)

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let content = UIStackView(arrangedSubviews: [label, spacer, valueLabel])
        content.axis = .horizontal
        content.spacing = 16
        content.translatesAutoresizingMaskIntoConstraints = false
        content.isUserInteractionEnabled = false
        button.addSubview(content)

        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: button.leadingAnchor, constant: 30),
            content.trailingAnchor.constraint(equalTo: button.trailingAnchor, constant: -30),
            content.topAnchor.constraint(equalTo: button.topAnchor, constant: 20),
            content.bottomAnchor.constraint(equalTo: button.bottomAnchor, constant: -20),
        ])
    }

    // MARK: - Layout

    private func setupLayout() {
        // Left container: icon fixed at center, description fills below
        let leftContainer = UIView()
        leftContainer.translatesAutoresizingMaskIntoConstraints = false
        leftContainer.addSubview(iconView)
        leftContainer.addSubview(descriptionLabel)

        // Right container
        let rightStack = UIStackView(arrangedSubviews: [alwaysOnButton, insecureButton])
        rightStack.axis = .vertical
        rightStack.spacing = 20
        rightStack.translatesAutoresizingMaskIntoConstraints = false

        let rightContainer = UIView()
        rightContainer.translatesAutoresizingMaskIntoConstraints = false
        rightContainer.addSubview(rightStack)

        view.addSubview(leftContainer)
        view.addSubview(rightContainer)

        NSLayoutConstraint.activate([
            // Left half
            leftContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            leftContainer.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.5),
            leftContainer.topAnchor.constraint(equalTo: view.topAnchor),
            leftContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            // Icon: fixed at center of left half
            iconView.centerXAnchor.constraint(equalTo: leftContainer.centerXAnchor),
            iconView.centerYAnchor.constraint(equalTo: leftContainer.centerYAnchor),
            iconView.heightAnchor.constraint(equalToConstant: 300),

            // Description: below icon, fills remaining space
            descriptionLabel.topAnchor.constraint(equalTo: iconView.bottomAnchor, constant: 40),
            descriptionLabel.centerXAnchor.constraint(equalTo: leftContainer.centerXAnchor),
            descriptionLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 700),
            descriptionLabel.bottomAnchor.constraint(lessThanOrEqualTo: leftContainer.bottomAnchor, constant: -60),

            // Right half
            rightContainer.leadingAnchor.constraint(equalTo: leftContainer.trailingAnchor),
            rightContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            rightContainer.topAnchor.constraint(equalTo: view.topAnchor),
            rightContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            rightStack.leadingAnchor.constraint(equalTo: rightContainer.leadingAnchor, constant: 80),
            rightStack.trailingAnchor.constraint(equalTo: rightContainer.trailingAnchor, constant: -80),
            rightStack.centerYAnchor.constraint(equalTo: rightContainer.centerYAnchor),
        ])
    }

    // MARK: - Updates

    private func updateAppearance() {
        let isOn = alwaysOnEnabled
        alwaysOnValueLabel.text = isOn ? String(localized: "On") : String(localized: "Off")
        alwaysOnValueLabel.textColor = isOn ? .systemGreen : .secondaryLabel

        let insecureOn = allowInsecure
        insecureValueLabel.text = insecureOn ? String(localized: "On") : String(localized: "Off")
        insecureValueLabel.textColor = insecureOn ? .systemRed : .secondaryLabel
    }

    // MARK: - Actions

    @objc private func alwaysOnTapped() {
        alwaysOnEnabled.toggle()
    }

    @objc private func insecureTapped() {
        if allowInsecure {
            allowInsecure = false
        } else {
            let alert = UIAlertController(
                title: String(localized: "Allow Insecure"),
                message: String(localized: "This will skip TLS certificate validation, making your connections vulnerable to MITM attacks."),
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: String(localized: "Allow Anyway"), style: .destructive) { [weak self] _ in
                self?.allowInsecure = true
            })
            alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
            present(alert, animated: true)
        }
    }

    // MARK: - Focus

    override var preferredFocusEnvironments: [UIFocusEnvironment] {
        [alwaysOnButton]
    }

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)

        coordinator.addCoordinatedAnimations {
            for button in [self.alwaysOnButton, self.insecureButton] {
                let isFocused = context.nextFocusedView === button
                let wasUnfocused = context.previouslyFocusedView === button

                if isFocused {
                    button.transform = CGAffineTransform(scaleX: 1.05, y: 1.05)
                    button.layer.shadowColor = UIColor.white.cgColor
                    button.layer.shadowRadius = 15
                    button.layer.shadowOpacity = 0.2
                    button.layer.shadowOffset = .zero
                }
                if wasUnfocused {
                    button.transform = .identity
                    button.layer.shadowOpacity = 0
                }
            }

            // Update description based on focused button
            let newText: String?
            if context.nextFocusedView === self.alwaysOnButton {
                newText = String(localized: "Automatically reconnect VPN when it is disconnected.")
            } else if context.nextFocusedView === self.insecureButton {
                newText = String(localized: "This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
            } else {
                newText = nil
            }

            if let newText {
                self.descriptionLabel.text = newText
                self.descriptionLabel.alpha = 1
            } else {
                self.descriptionLabel.alpha = 0
            }
        }
    }
}
