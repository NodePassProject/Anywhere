//
//  TVLaunchpadViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit
import NetworkExtension

class TVLaunchpadViewController: UIViewController {

    // MARK: - Properties

    private let container: AppContainer
    private lazy var operations = Operations(container: container)
    private var tunnel: TunnelController { container.tunnel }
    private var selection: ProxySelection { container.selection }
    private var lastRenderedConnectedState: Bool?

    init(container: AppContainer) {
        self.container = container
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    private let gradientLayer = CAGradientLayer()

    private let contentStack = UIStackView()

    private let powerButton = UIButton(type: .custom)
    private let powerIcon = UIImageView()
    private let activityIndicator = UIActivityIndicatorView(style: .large)

    private let statusLabel = UILabel()

    private let statsButton = UIButton(type: .custom)
    private let uploadIcon = UIImageView()
    private let uploadLabel = UILabel()
    private let downloadIcon = UIImageView()
    private let downloadLabel = UILabel()

    private let configButton = UIButton(type: .custom)
    private let configIcon = UIImageView()
    private let configNameLabel = UILabel()
    private let configChevron = UIImageView()

    private let emptyButton = UIButton(type: .custom)

    private var isConnected: Bool { tunnel.rawStatus == .connected }
    private var isTransitioning: Bool { tunnel.rawStatus.isTransitioning }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        setupGradient()
        setupPowerButton()
        setupStatusLabel()
        setupStatsCard()
        setupConfigCard()
        setupEmptyCard()
        setupLayout()
        updateUI()
        lastRenderedConnectedState = isConnected
        registerForTraitChanges([UITraitUserInterfaceStyle.self]) { (self: Self, _) in
            self.updateGradientColors(animated: false)
        }
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
            start = UIColor.connectedBackgroundStart
            end = UIColor.connectedBackgroundEnd
        } else {
            start = UIColor.disconnectedBackgroundStart
            end = UIColor.disconnectedBackgroundEnd
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
        powerButton.layer.cornerRadius = 130
        powerButton.clipsToBounds = false
        powerButton.addTarget(self, action: #selector(powerButtonTapped), for: .primaryActionTriggered)

        let iconConfig = UIImage.SymbolConfiguration(pointSize: 90, weight: .light)
        powerIcon.image = UIImage(systemName: "power", withConfiguration: iconConfig)
        powerIcon.contentMode = .scaleAspectFit
        powerIcon.translatesAutoresizingMaskIntoConstraints = false
        powerButton.addSubview(powerIcon)

        activityIndicator.hidesWhenStopped = true
        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
        powerButton.addSubview(activityIndicator)

        NSLayoutConstraint.activate([
            powerButton.widthAnchor.constraint(equalToConstant: 260),
            powerButton.heightAnchor.constraint(equalToConstant: 260),
            powerIcon.centerXAnchor.constraint(equalTo: powerButton.centerXAnchor),
            powerIcon.centerYAnchor.constraint(equalTo: powerButton.centerYAnchor),
            activityIndicator.centerXAnchor.constraint(equalTo: powerButton.centerXAnchor),
            activityIndicator.centerYAnchor.constraint(equalTo: powerButton.centerYAnchor),
        ])
    }

    // MARK: - Status Label

    private func setupStatusLabel() {
        statusLabel.font = .systemFont(ofSize: 44, weight: .medium)
        statusLabel.textAlignment = .center
        statusLabel.textColor = .secondaryLabel
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
    }

    // MARK: - Stats Card

    private func setupStatsCard() {
        statsButton.translatesAutoresizingMaskIntoConstraints = false
        statsButton.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        statsButton.layer.cornerRadius = 28

        let arrowConfig = UIImage.SymbolConfiguration(pointSize: 28, weight: .medium)
        let uploadArrow = UIImageView(image: UIImage(systemName: "arrow.up", withConfiguration: arrowConfig))
        uploadArrow.tintColor = UIColor.white.withAlphaComponent(0.7)
        uploadArrow.setContentHuggingPriority(.required, for: .horizontal)
        uploadArrow.accessibilityLabel = "Upload"

        uploadLabel.font = .monospacedDigitSystemFont(ofSize: 34, weight: .regular)
        uploadLabel.textColor = .white
        uploadLabel.text = Self.formatBytes(0)

        let downloadArrow = UIImageView(image: UIImage(systemName: "arrow.down", withConfiguration: arrowConfig))
        downloadArrow.tintColor = UIColor.white.withAlphaComponent(0.7)
        downloadArrow.setContentHuggingPriority(.required, for: .horizontal)
        downloadArrow.accessibilityLabel = "Download"

        downloadLabel.font = .monospacedDigitSystemFont(ofSize: 34, weight: .regular)
        downloadLabel.textColor = .white
        downloadLabel.text = Self.formatBytes(0)

        let uploadStack = UIStackView(arrangedSubviews: [uploadArrow, uploadLabel])
        uploadStack.spacing = 12
        uploadStack.alignment = .center

        let downloadStack = UIStackView(arrangedSubviews: [downloadArrow, downloadLabel])
        downloadStack.spacing = 12
        downloadStack.alignment = .center

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let hStack = UIStackView(arrangedSubviews: [uploadStack, spacer, downloadStack])
        hStack.translatesAutoresizingMaskIntoConstraints = false
        hStack.isUserInteractionEnabled = false
        statsButton.addSubview(hStack)

        NSLayoutConstraint.activate([
            hStack.leadingAnchor.constraint(equalTo: statsButton.leadingAnchor, constant: 32),
            hStack.trailingAnchor.constraint(equalTo: statsButton.trailingAnchor, constant: -32),
            hStack.topAnchor.constraint(equalTo: statsButton.topAnchor, constant: 22),
            hStack.bottomAnchor.constraint(equalTo: statsButton.bottomAnchor, constant: -22),
        ])

        statsButton.isHidden = true
    }

    // MARK: - Config Card

    private func setupConfigCard() {
        configButton.translatesAutoresizingMaskIntoConstraints = false
        configButton.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        configButton.layer.cornerRadius = 28
        configButton.layer.shadowColor = UIColor.black.cgColor
        configButton.layer.shadowOffset = CGSize(width: 0, height: 4)
        configButton.layer.shadowRadius = 10
        configButton.layer.shadowOpacity = 0
        configButton.addTarget(self, action: #selector(configCardTapped), for: .primaryActionTriggered)

        let configIconConfig = UIImage.SymbolConfiguration(pointSize: 30, weight: .medium)
        configIcon.image = UIImage(systemName: "antenna.radiowaves.left.and.right", withConfiguration: configIconConfig)
        configIcon.tintColor = .secondaryLabel
        configIcon.setContentHuggingPriority(.required, for: .horizontal)
        configIcon.translatesAutoresizingMaskIntoConstraints = false

        configNameLabel.font = .systemFont(ofSize: 38, weight: .medium)
        configNameLabel.textColor = .white
        configNameLabel.translatesAutoresizingMaskIntoConstraints = false

        let chevronConfig = UIImage.SymbolConfiguration(pointSize: 20, weight: .semibold)
        configChevron.image = UIImage(systemName: "chevron.up.chevron.down", withConfiguration: chevronConfig)
        configChevron.tintColor = UIColor.white.withAlphaComponent(0.4)
        configChevron.setContentHuggingPriority(.required, for: .horizontal)
        configChevron.translatesAutoresizingMaskIntoConstraints = false

        let cardContent = UIStackView(arrangedSubviews: [configIcon, configNameLabel, configChevron])
        cardContent.spacing = 16
        cardContent.alignment = .center
        cardContent.translatesAutoresizingMaskIntoConstraints = false
        cardContent.isUserInteractionEnabled = false
        configButton.addSubview(cardContent)

        NSLayoutConstraint.activate([
            cardContent.leadingAnchor.constraint(equalTo: configButton.leadingAnchor, constant: 32),
            cardContent.trailingAnchor.constraint(equalTo: configButton.trailingAnchor, constant: -32),
            cardContent.topAnchor.constraint(equalTo: configButton.topAnchor, constant: 24),
            cardContent.bottomAnchor.constraint(equalTo: configButton.bottomAnchor, constant: -24),
        ])
    }

    // MARK: - Empty Card

    private func setupEmptyCard() {
        emptyButton.translatesAutoresizingMaskIntoConstraints = false
        emptyButton.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        emptyButton.layer.cornerRadius = 28
        emptyButton.layer.shadowColor = UIColor.black.cgColor
        emptyButton.layer.shadowOffset = CGSize(width: 0, height: 4)
        emptyButton.layer.shadowRadius = 10
        emptyButton.layer.shadowOpacity = 0
        emptyButton.addTarget(self, action: #selector(addConfigTapped), for: .primaryActionTriggered)

        let plusConfig = UIImage.SymbolConfiguration(pointSize: 30, weight: .medium)
        let plusIcon = UIImageView(image: UIImage(systemName: "plus.circle.fill", withConfiguration: plusConfig))
        plusIcon.tintColor = .systemBlue
        plusIcon.setContentHuggingPriority(.required, for: .horizontal)

        let addLabel = UILabel()
        addLabel.text = String(localized: "Add a Configuration")
        addLabel.font = .systemFont(ofSize: 38, weight: .medium)
        addLabel.textColor = .white

        let emptyChevronConfig = UIImage.SymbolConfiguration(pointSize: 20, weight: .semibold)
        let rightChevron = UIImageView(image: UIImage(systemName: "chevron.right", withConfiguration: emptyChevronConfig))
        rightChevron.tintColor = .tertiaryLabel
        rightChevron.setContentHuggingPriority(.required, for: .horizontal)

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)

        let content = UIStackView(arrangedSubviews: [plusIcon, addLabel, spacer, rightChevron])
        content.spacing = 16
        content.alignment = .center
        content.translatesAutoresizingMaskIntoConstraints = false
        content.isUserInteractionEnabled = false
        emptyButton.addSubview(content)

        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: emptyButton.leadingAnchor, constant: 32),
            content.trailingAnchor.constraint(equalTo: emptyButton.trailingAnchor, constant: -32),
            content.topAnchor.constraint(equalTo: emptyButton.topAnchor, constant: 24),
            content.bottomAnchor.constraint(equalTo: emptyButton.bottomAnchor, constant: -24),
        ])
    }

    // MARK: - Layout

    private func setupLayout() {
        let leftStack = UIStackView(arrangedSubviews: [powerButton, statusLabel])
        leftStack.axis = .vertical
        leftStack.alignment = .center
        leftStack.spacing = 40
        leftStack.translatesAutoresizingMaskIntoConstraints = false

        let leftContainer = UIView()
        leftContainer.translatesAutoresizingMaskIntoConstraints = false
        leftContainer.addSubview(leftStack)

        let rightStack = UIStackView(arrangedSubviews: [statsButton, configButton, emptyButton])
        rightStack.axis = .vertical
        rightStack.alignment = .center
        rightStack.spacing = 28
        rightStack.translatesAutoresizingMaskIntoConstraints = false

        let rightContainer = UIView()
        rightContainer.translatesAutoresizingMaskIntoConstraints = false
        rightContainer.addSubview(rightStack)

        view.addSubview(leftContainer)
        view.addSubview(rightContainer)

        NSLayoutConstraint.activate([
            leftContainer.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            leftContainer.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.5),
            leftContainer.topAnchor.constraint(equalTo: view.topAnchor),
            leftContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            leftStack.centerXAnchor.constraint(equalTo: leftContainer.centerXAnchor),
            leftStack.centerYAnchor.constraint(equalTo: leftContainer.centerYAnchor),

            rightContainer.leadingAnchor.constraint(equalTo: leftContainer.trailingAnchor),
            rightContainer.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            rightContainer.topAnchor.constraint(equalTo: view.topAnchor),
            rightContainer.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            rightStack.centerXAnchor.constraint(equalTo: rightContainer.centerXAnchor),
            rightStack.centerYAnchor.constraint(equalTo: rightContainer.centerYAnchor),

            statsButton.widthAnchor.constraint(equalToConstant: 620),
            configButton.widthAnchor.constraint(equalToConstant: 620),
            emptyButton.widthAnchor.constraint(equalToConstant: 620),
        ])
    }

    // MARK: - Bindings

    override func updateProperties() {
        super.updateProperties()
        updatePowerButton()
        updateStatusLabel()
        updateConfigCard()
        updateTrafficStats()

        // Animate the gradient only when the connected state actually flips, so the
        // once-per-second traffic-stats updates don't restart its 0.6s color animation.
        let connected = isConnected
        if connected != lastRenderedConnectedState {
            lastRenderedConnectedState = connected
            updateGradientColors(animated: true)
        }
        
        if let startError = tunnel.startError {
            tunnel.startError = nil
            presentStartError(startError)
        }
    }

    private func presentStartError(_ message: String) {
        let alert = UIAlertController(title: "VPN Error", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
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
        let disabled = container.configurationStore.hasConfigurations && (!tunnel.isManagerReady || tunnel.rawStatus.isTransitioning)
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
        }
    }

    private func updateStatusLabel() {
        statusLabel.text = tunnel.status.localizedText
        UIView.animate(withDuration: 0.3) {
            self.statusLabel.textColor = self.isConnected ? .white : .secondaryLabel
        }
    }

    private func updateTrafficStats() {
        let shouldShow = isConnected
        if statsButton.isHidden == shouldShow {
            UIView.animate(withDuration: 0.3) {
                self.statsButton.isHidden = !shouldShow
                self.statsButton.alpha = shouldShow ? 1 : 0
            }
        }
        uploadLabel.text = Self.formatBytes(container.stats.bytesOut)
        downloadLabel.text = Self.formatBytes(container.stats.bytesIn)
    }

    private func updateConfigCard() {
        let hasConfig = selection.selectedConfiguration != nil
        configButton.isHidden = !hasConfig
        emptyButton.isHidden = hasConfig

        if let configuration = selection.selectedConfiguration {
            configNameLabel.text = configuration.name
            UIView.animate(withDuration: 0.3) {
                self.configIcon.tintColor = self.isConnected ? UIColor.white.withAlphaComponent(0.7) : .secondaryLabel
                self.configNameLabel.textColor = self.isConnected ? .white : .label
            }
        }
    }

    // MARK: - Actions

    @objc private func powerButtonTapped() {
        guard container.configurationStore.hasConfigurations else {
            addConfigTapped()
            return
        }
        operations.tunnel.toggle()
    }

    @objc private func configCardTapped() {
        let proxies = TVProxiesPageViewController(container: container)
        let nav = UINavigationController(rootViewController: proxies)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    @objc private func addConfigTapped() {
        let addVC = TVAddProxyViewController(container: container)
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
            for button in [self.powerButton, self.statsButton, self.configButton, self.emptyButton] {
                let isFocused = context.nextFocusedView === button
                let wasUnfocused = context.previouslyFocusedView === button

                if isFocused {
                    let scale: CGFloat = button === self.powerButton ? 1.1 : 1.03
                    button.transform = CGAffineTransform(scaleX: scale, y: scale)
                    button.layer.shadowOpacity = 0.4
                    button.layer.shadowRadius = button === self.powerButton ? 30 : 15
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
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter
    }()

    private static func formatBytes(_ bytes: Int64) -> String {
        byteFormatter.string(fromByteCount: bytes)
    }
}
