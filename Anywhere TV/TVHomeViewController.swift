//
//  TVHomeViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit
import NetworkExtension
import Combine

class TVHomeViewController: UIViewController {

    // MARK: - Properties

    private let viewModel = VPNViewModel.shared
    private var cancellables = Set<AnyCancellable>()

    private let gradientLayer = CAGradientLayer()

    private let contentStack = UIStackView()

    // Power button
    private let powerButton = UIButton(type: .custom)
    private let powerIcon = UIImageView()
    private let activityIndicator = UIActivityIndicatorView(style: .large)
    private let glowLayer = CALayer()

    // Status
    private let statusLabel = UILabel()

    // Traffic stats
    private let statsCard = UIView()
    private let uploadIcon = UIImageView()
    private let uploadLabel = UILabel()
    private let downloadIcon = UIImageView()
    private let downloadLabel = UILabel()

    // Configuration card
    private let configButton = UIButton(type: .custom)
    private let configIcon = UIImageView()
    private let configNameLabel = UILabel()
    private let configChevron = UIImageView()

    // Empty state card
    private let emptyButton = UIButton(type: .custom)

    private var isConnected: Bool { viewModel.vpnStatus == .connected }
    private var isTransitioning: Bool {
        let s = viewModel.vpnStatus
        return s == .connecting || s == .disconnecting || s == .reasserting
    }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        navigationController?.setNavigationBarHidden(true, animated: false)
        setupGradient()
        setupPowerButton()
        setupStatusLabel()
        setupStatsCard()
        setupConfigCard()
        setupEmptyCard()
        setupLayout()
        bindViewModel()
        updateUI()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        gradientLayer.frame = view.bounds
    }

    // MARK: - Gradient

    private func setupGradient() {
        gradientLayer.startPoint = CGPoint(x: 0, y: 0)
        gradientLayer.endPoint = CGPoint(x: 1, y: 1)
        view.layer.insertSublayer(gradientLayer, at: 0)
        updateGradientColors(animated: false)
    }

    private func updateGradientColors(animated: Bool) {
        let start: UIColor
        let end: UIColor
        if isConnected {
            start = UIColor(named: "GradientStart") ?? .black
            end = UIColor(named: "GradientEnd") ?? .black
        } else {
            start = UIColor(named: "GradientDisconnectedStart") ?? .black
            end = UIColor(named: "GradientDisconnectedEnd") ?? .black
        }

        if animated {
            let animation = CABasicAnimation(keyPath: "colors")
            animation.fromValue = gradientLayer.colors
            animation.toValue = [start.cgColor, end.cgColor]
            animation.duration = 0.6
            animation.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
            gradientLayer.add(animation, forKey: "gradientChange")
        }
        gradientLayer.colors = [start.cgColor, end.cgColor]
    }

    // MARK: - Power Button

    private func setupPowerButton() {
        powerButton.translatesAutoresizingMaskIntoConstraints = false
        powerButton.backgroundColor = UIColor.white.withAlphaComponent(0.15)
        powerButton.layer.cornerRadius = 90
        powerButton.clipsToBounds = false
        powerButton.addTarget(self, action: #selector(powerButtonTapped), for: .primaryActionTriggered)

        // Glow layer behind button
        glowLayer.frame = CGRect(x: -30, y: -30, width: 240, height: 240)
        glowLayer.cornerRadius = 120
        glowLayer.backgroundColor = UIColor.cyan.withAlphaComponent(0.15).cgColor
        glowLayer.shadowColor = UIColor.cyan.cgColor
        glowLayer.shadowRadius = 40
        glowLayer.shadowOpacity = 0
        glowLayer.shadowOffset = .zero
        powerButton.layer.insertSublayer(glowLayer, at: 0)

        // Power icon
        let iconConfig = UIImage.SymbolConfiguration(pointSize: 60, weight: .light)
        powerIcon.image = UIImage(systemName: "power", withConfiguration: iconConfig)
        powerIcon.tintColor = .systemCyan
        powerIcon.contentMode = .scaleAspectFit
        powerIcon.translatesAutoresizingMaskIntoConstraints = false
        powerButton.addSubview(powerIcon)

        // Activity indicator
        activityIndicator.hidesWhenStopped = true
        activityIndicator.color = .systemCyan
        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
        powerButton.addSubview(activityIndicator)

        NSLayoutConstraint.activate([
            powerButton.widthAnchor.constraint(equalToConstant: 180),
            powerButton.heightAnchor.constraint(equalToConstant: 180),
            powerIcon.centerXAnchor.constraint(equalTo: powerButton.centerXAnchor),
            powerIcon.centerYAnchor.constraint(equalTo: powerButton.centerYAnchor),
            activityIndicator.centerXAnchor.constraint(equalTo: powerButton.centerXAnchor),
            activityIndicator.centerYAnchor.constraint(equalTo: powerButton.centerYAnchor),
        ])
    }

    // MARK: - Status Label

    private func setupStatusLabel() {
        statusLabel.font = .systemFont(ofSize: 32, weight: .medium)
        statusLabel.textAlignment = .center
        statusLabel.textColor = .secondaryLabel
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
    }

    // MARK: - Stats Card

    private func setupStatsCard() {
        statsCard.translatesAutoresizingMaskIntoConstraints = false
        statsCard.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        statsCard.layer.cornerRadius = 20

        let uploadArrow = UIImageView(image: UIImage(systemName: "arrow.up"))
        uploadArrow.tintColor = UIColor.white.withAlphaComponent(0.7)
        uploadArrow.setContentHuggingPriority(.required, for: .horizontal)

        uploadLabel.font = .monospacedDigitSystemFont(ofSize: 24, weight: .regular)
        uploadLabel.textColor = .white
        uploadLabel.text = Self.formatBytes(0)

        let downloadArrow = UIImageView(image: UIImage(systemName: "arrow.down"))
        downloadArrow.tintColor = UIColor.white.withAlphaComponent(0.7)
        downloadArrow.setContentHuggingPriority(.required, for: .horizontal)

        downloadLabel.font = .monospacedDigitSystemFont(ofSize: 24, weight: .regular)
        downloadLabel.textColor = .white
        downloadLabel.text = Self.formatBytes(0)

        let uploadStack = UIStackView(arrangedSubviews: [uploadArrow, uploadLabel])
        uploadStack.spacing = 8
        uploadStack.alignment = .center

        let downloadStack = UIStackView(arrangedSubviews: [downloadArrow, downloadLabel])
        downloadStack.spacing = 8
        downloadStack.alignment = .center

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let hStack = UIStackView(arrangedSubviews: [uploadStack, spacer, downloadStack])
        hStack.translatesAutoresizingMaskIntoConstraints = false
        statsCard.addSubview(hStack)

        NSLayoutConstraint.activate([
            hStack.leadingAnchor.constraint(equalTo: statsCard.leadingAnchor, constant: 24),
            hStack.trailingAnchor.constraint(equalTo: statsCard.trailingAnchor, constant: -24),
            hStack.topAnchor.constraint(equalTo: statsCard.topAnchor, constant: 16),
            hStack.bottomAnchor.constraint(equalTo: statsCard.bottomAnchor, constant: -16),
        ])

        statsCard.isHidden = true
    }

    // MARK: - Config Card

    private func setupConfigCard() {
        configButton.translatesAutoresizingMaskIntoConstraints = false
        configButton.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        configButton.layer.cornerRadius = 20
        configButton.layer.shadowColor = UIColor.black.cgColor
        configButton.layer.shadowOffset = CGSize(width: 0, height: 4)
        configButton.layer.shadowRadius = 10
        configButton.layer.shadowOpacity = 0
        configButton.addTarget(self, action: #selector(configCardTapped), for: .primaryActionTriggered)

        configIcon.image = UIImage(systemName: "antenna.radiowaves.left.and.right")
        configIcon.tintColor = .secondaryLabel
        configIcon.setContentHuggingPriority(.required, for: .horizontal)
        configIcon.translatesAutoresizingMaskIntoConstraints = false

        configNameLabel.font = .systemFont(ofSize: 28, weight: .medium)
        configNameLabel.textColor = .white
        configNameLabel.translatesAutoresizingMaskIntoConstraints = false

        let chevronConfig = UIImage.SymbolConfiguration(pointSize: 14, weight: .semibold)
        configChevron.image = UIImage(systemName: "chevron.up.chevron.down", withConfiguration: chevronConfig)
        configChevron.tintColor = UIColor.white.withAlphaComponent(0.4)
        configChevron.setContentHuggingPriority(.required, for: .horizontal)
        configChevron.translatesAutoresizingMaskIntoConstraints = false

        let cardContent = UIStackView(arrangedSubviews: [configIcon, configNameLabel, configChevron])
        cardContent.spacing = 12
        cardContent.alignment = .center
        cardContent.translatesAutoresizingMaskIntoConstraints = false
        cardContent.isUserInteractionEnabled = false
        configButton.addSubview(cardContent)

        NSLayoutConstraint.activate([
            cardContent.leadingAnchor.constraint(equalTo: configButton.leadingAnchor, constant: 24),
            cardContent.trailingAnchor.constraint(equalTo: configButton.trailingAnchor, constant: -24),
            cardContent.topAnchor.constraint(equalTo: configButton.topAnchor, constant: 18),
            cardContent.bottomAnchor.constraint(equalTo: configButton.bottomAnchor, constant: -18),
        ])
    }

    // MARK: - Empty Card

    private func setupEmptyCard() {
        emptyButton.translatesAutoresizingMaskIntoConstraints = false
        emptyButton.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        emptyButton.layer.cornerRadius = 20
        emptyButton.layer.shadowColor = UIColor.black.cgColor
        emptyButton.layer.shadowOffset = CGSize(width: 0, height: 4)
        emptyButton.layer.shadowRadius = 10
        emptyButton.layer.shadowOpacity = 0
        emptyButton.addTarget(self, action: #selector(addConfigTapped), for: .primaryActionTriggered)

        let plusIcon = UIImageView(image: UIImage(systemName: "plus.circle.fill"))
        plusIcon.tintColor = .systemBlue
        plusIcon.setContentHuggingPriority(.required, for: .horizontal)

        let addLabel = UILabel()
        addLabel.text = String(localized: "Add a Configuration")
        addLabel.font = .systemFont(ofSize: 28, weight: .medium)
        addLabel.textColor = .white

        let chevronConfig = UIImage.SymbolConfiguration(pointSize: 14, weight: .semibold)
        let rightChevron = UIImageView(image: UIImage(systemName: "chevron.right", withConfiguration: chevronConfig))
        rightChevron.tintColor = .tertiaryLabel
        rightChevron.setContentHuggingPriority(.required, for: .horizontal)

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let content = UIStackView(arrangedSubviews: [plusIcon, addLabel, spacer, rightChevron])
        content.spacing = 12
        content.alignment = .center
        content.translatesAutoresizingMaskIntoConstraints = false
        content.isUserInteractionEnabled = false
        emptyButton.addSubview(content)

        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: emptyButton.leadingAnchor, constant: 24),
            content.trailingAnchor.constraint(equalTo: emptyButton.trailingAnchor, constant: -24),
            content.topAnchor.constraint(equalTo: emptyButton.topAnchor, constant: 18),
            content.bottomAnchor.constraint(equalTo: emptyButton.bottomAnchor, constant: -18),
        ])
    }

    // MARK: - Layout

    private func setupLayout() {
        let centerContainer = UIView()
        centerContainer.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(centerContainer)

        let stack = UIStackView(arrangedSubviews: [powerButton, statusLabel, statsCard, configButton, emptyButton])
        stack.axis = .vertical
        stack.alignment = .center
        stack.spacing = 20
        stack.translatesAutoresizingMaskIntoConstraints = false
        centerContainer.addSubview(stack)

        NSLayoutConstraint.activate([
            centerContainer.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            centerContainer.centerYAnchor.constraint(equalTo: view.centerYAnchor),

            stack.topAnchor.constraint(equalTo: centerContainer.topAnchor),
            stack.bottomAnchor.constraint(equalTo: centerContainer.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: centerContainer.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: centerContainer.trailingAnchor),

            statsCard.widthAnchor.constraint(equalToConstant: 450),
            configButton.widthAnchor.constraint(equalToConstant: 450),
            emptyButton.widthAnchor.constraint(equalToConstant: 450),
        ])
    }

    // MARK: - Bindings

    private func bindViewModel() {
        viewModel.$vpnStatus
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.updateUI() }
            .store(in: &cancellables)

        viewModel.$selectedConfiguration
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.updateConfigCard() }
            .store(in: &cancellables)

        viewModel.$bytesIn
            .combineLatest(viewModel.$bytesOut)
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.updateTrafficStats() }
            .store(in: &cancellables)

        viewModel.$configurations
            .receive(on: RunLoop.main)
            .sink { [weak self] _ in self?.updateConfigCard() }
            .store(in: &cancellables)
    }

    // MARK: - UI Updates

    private func updateUI() {
        updateGradientColors(animated: true)
        updatePowerButton()
        updateStatusLabel()
        updateTrafficStats()
        updateConfigCard()
    }

    private func updatePowerButton() {
        let disabled = viewModel.isButtonDisabled
        powerButton.isEnabled = !disabled
        powerButton.alpha = disabled ? 0.5 : 1.0

        if isTransitioning {
            powerIcon.isHidden = true
            activityIndicator.startAnimating()
        } else {
            powerIcon.isHidden = false
            activityIndicator.stopAnimating()
        }

        UIView.animate(withDuration: 0.4) {
            self.powerButton.backgroundColor = UIColor.white.withAlphaComponent(self.isConnected ? 0.25 : 0.15)
            self.powerIcon.tintColor = self.isConnected ? .white : .systemCyan
            self.activityIndicator.color = self.isConnected ? .white : .systemCyan
        }

        CATransaction.begin()
        CATransaction.setAnimationDuration(0.6)
        glowLayer.shadowOpacity = isConnected ? 0.6 : 0
        CATransaction.commit()
    }

    private func updateStatusLabel() {
        statusLabel.text = viewModel.statusText
        UIView.animate(withDuration: 0.3) {
            self.statusLabel.textColor = self.isConnected ? .white : .secondaryLabel
        }
    }

    private func updateTrafficStats() {
        let shouldShow = isConnected
        if statsCard.isHidden == shouldShow {
            UIView.animate(withDuration: 0.3) {
                self.statsCard.isHidden = !shouldShow
                self.statsCard.alpha = shouldShow ? 1 : 0
            }
        }
        uploadLabel.text = Self.formatBytes(viewModel.bytesOut)
        downloadLabel.text = Self.formatBytes(viewModel.bytesIn)
    }

    private func updateConfigCard() {
        let hasConfig = viewModel.selectedConfiguration != nil
        configButton.isHidden = !hasConfig
        emptyButton.isHidden = hasConfig

        if let configuration = viewModel.selectedConfiguration {
            configNameLabel.text = configuration.name
            UIView.animate(withDuration: 0.3) {
                self.configIcon.tintColor = self.isConnected ? UIColor.white.withAlphaComponent(0.7) : .secondaryLabel
                self.configNameLabel.textColor = self.isConnected ? .white : .label
            }
        }
    }

    // MARK: - Actions

    @objc private func powerButtonTapped() {
        viewModel.toggleVPN()
    }

    @objc private func configCardTapped() {
        let picker = TVConfigPickerViewController()
        let nav = UINavigationController(rootViewController: picker)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    @objc private func addConfigTapped() {
        let addVC = TVAddProxyViewController()
        let nav = UINavigationController(rootViewController: addVC)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    // MARK: - Focus

    override var preferredFocusEnvironments: [UIFocusEnvironment] {
        [powerButton]
    }

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)

        coordinator.addCoordinatedAnimations {
            for button in [self.powerButton, self.configButton, self.emptyButton] {
                let isFocused = context.nextFocusedView === button
                let wasUnfocused = context.previouslyFocusedView === button

                if isFocused {
                    let scale: CGFloat = button === self.powerButton ? 1.1 : 1.03
                    button.transform = CGAffineTransform(scaleX: scale, y: scale)
                    button.layer.shadowOpacity = 0.4
                    button.layer.shadowRadius = button === self.powerButton ? 30 : 15
                    button.layer.shadowColor = (button === self.powerButton ? UIColor.cyan : UIColor.white).cgColor
                }
                if wasUnfocused {
                    button.transform = .identity
                    button.layer.shadowOpacity = 0
                }
            }
        }
    }

    // MARK: - Helpers

    private static let byteFormatter: ByteCountFormatter = {
        let f = ByteCountFormatter()
        f.countStyle = .binary
        return f
    }()

    private static func formatBytes(_ bytes: Int64) -> String {
        byteFormatter.string(fromByteCount: bytes)
    }
}
