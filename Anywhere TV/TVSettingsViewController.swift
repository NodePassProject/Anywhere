//
//  TVSettingsViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit
import Combine

/// Settings page with tvOS split layout:
/// - Left half: symbol + description
/// - Right half: the form (Allow Insecure toggle only)
class TVSettingsViewController: UIViewController {

    private var cancellable: AnyCancellable?

    // Left side
    private let iconView = UIImageView()
    private let titleLabel = UILabel()
    private let descriptionLabel = UILabel()

    // Right side
    private let toggleButton = UIButton(type: .custom)
    private let toggleLabel = UILabel()
    private let valueLabel = UILabel()

    private var allowInsecure: Bool {
        get { AWCore.userDefaults.bool(forKey: "allowInsecure") }
        set {
            AWCore.userDefaults.set(newValue, forKey: "allowInsecure")
            notifySettingsChanged()
            updateToggleAppearance()
        }
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Settings")
        view.backgroundColor = .black
        setupLeftSide()
        setupRightSide()
        setupLayout()
        updateToggleAppearance()
    }

    // MARK: - Left Side

    private func setupLeftSide() {
        let iconConfig = UIImage.SymbolConfiguration(pointSize: 80, weight: .medium)
        iconView.image = UIImage(systemName: "exclamationmark.shield.fill", withConfiguration: iconConfig)
        iconView.tintColor = .systemRed
        iconView.contentMode = .scaleAspectFit
        iconView.translatesAutoresizingMaskIntoConstraints = false

        titleLabel.text = String(localized: "Allow Insecure")
        titleLabel.font = .systemFont(ofSize: 38, weight: .semibold)
        titleLabel.textColor = .label
        titleLabel.translatesAutoresizingMaskIntoConstraints = false

        descriptionLabel.text = String(localized: "This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        descriptionLabel.font = .systemFont(ofSize: 24)
        descriptionLabel.textColor = .secondaryLabel
        descriptionLabel.numberOfLines = 0
        descriptionLabel.translatesAutoresizingMaskIntoConstraints = false
    }

    // MARK: - Right Side

    private func setupRightSide() {
        toggleLabel.text = String(localized: "Allow Insecure")
        toggleLabel.font = .systemFont(ofSize: 32, weight: .medium)
        toggleLabel.textColor = .label
        toggleLabel.translatesAutoresizingMaskIntoConstraints = false

        valueLabel.font = .systemFont(ofSize: 28)
        valueLabel.translatesAutoresizingMaskIntoConstraints = false

        toggleButton.translatesAutoresizingMaskIntoConstraints = false
        toggleButton.backgroundColor = UIColor.white.withAlphaComponent(0.1)
        toggleButton.layer.cornerRadius = 16
        toggleButton.addTarget(self, action: #selector(toggleTapped), for: .primaryActionTriggered)

        let content = UIStackView(arrangedSubviews: [toggleLabel, valueLabel])
        content.axis = .horizontal
        content.spacing = 16
        content.translatesAutoresizingMaskIntoConstraints = false
        content.isUserInteractionEnabled = false
        toggleButton.addSubview(content)

        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: toggleButton.leadingAnchor, constant: 30),
            content.trailingAnchor.constraint(equalTo: toggleButton.trailingAnchor, constant: -30),
            content.topAnchor.constraint(equalTo: toggleButton.topAnchor, constant: 20),
            content.bottomAnchor.constraint(equalTo: toggleButton.bottomAnchor, constant: -20),
        ])
    }

    // MARK: - Layout

    private func setupLayout() {
        // Left container
        let leftStack = UIStackView(arrangedSubviews: [iconView, titleLabel, descriptionLabel])
        leftStack.axis = .vertical
        leftStack.spacing = 20
        leftStack.alignment = .center
        leftStack.translatesAutoresizingMaskIntoConstraints = false

        // Right container
        let rightContainer = UIView()
        rightContainer.translatesAutoresizingMaskIntoConstraints = false
        rightContainer.addSubview(toggleButton)

        // Main horizontal split
        let hStack = UIStackView(arrangedSubviews: [leftStack, rightContainer])
        hStack.axis = .horizontal
        hStack.distribution = .fillEqually
        hStack.spacing = 60
        hStack.alignment = .center
        hStack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hStack)

        NSLayoutConstraint.activate([
            hStack.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor, constant: 80),
            hStack.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor, constant: -80),
            hStack.centerYAnchor.constraint(equalTo: view.centerYAnchor),

            iconView.heightAnchor.constraint(equalToConstant: 100),
            descriptionLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 500),

            toggleButton.leadingAnchor.constraint(equalTo: rightContainer.leadingAnchor),
            toggleButton.trailingAnchor.constraint(equalTo: rightContainer.trailingAnchor),
            toggleButton.centerYAnchor.constraint(equalTo: rightContainer.centerYAnchor),
        ])
    }

    // MARK: - Updates

    private func updateToggleAppearance() {
        let isOn = allowInsecure
        valueLabel.text = isOn ? String(localized: "On") : String(localized: "Off")
        valueLabel.textColor = isOn ? .systemRed : .secondaryLabel
        toggleButton.backgroundColor = UIColor.white.withAlphaComponent(isOn ? 0.15 : 0.08)
    }

    // MARK: - Actions

    @objc private func toggleTapped() {
        if allowInsecure {
            // Turn off — no confirmation needed
            allowInsecure = false
        } else {
            // Turn on — show confirmation
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
        [toggleButton]
    }

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)
        coordinator.addCoordinatedAnimations {
            if context.nextFocusedView === self.toggleButton {
                self.toggleButton.transform = CGAffineTransform(scaleX: 1.05, y: 1.05)
                self.toggleButton.layer.shadowColor = UIColor.white.cgColor
                self.toggleButton.layer.shadowRadius = 15
                self.toggleButton.layer.shadowOpacity = 0.2
                self.toggleButton.layer.shadowOffset = .zero
            }
            if context.previouslyFocusedView === self.toggleButton {
                self.toggleButton.transform = .identity
                self.toggleButton.layer.shadowOpacity = 0
            }
        }
    }

    // MARK: - Helpers

    private func notifySettingsChanged() {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName("com.argsment.Anywhere.settingsChanged" as CFString),
            nil, nil, true
        )
    }
}
