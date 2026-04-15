//
//  TVDemoViews.swift
//  Anywhere
//
//  Demo view controllers for Xcode Previews. Self-contained with mock data,
//  no dependency on VPNViewModel or persistent stores.
//

#if DEBUG

import UIKit

// MARK: - Demo Home View Controller

class TVDemoHomeViewController: UIViewController {

    private let isConnected: Bool
    private let bytesIn: Int64
    private let bytesOut: Int64
    private let configName: String

    private let gradientLayer = CAGradientLayer()

    init(isConnected: Bool = true, bytesIn: Int64 = 157_286_400, bytesOut: Int64 = 12_582_912, configName: String = "Tokyo") {
        self.isConnected = isConnected
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
        self.configName = configName
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        setupGradient()
        setupLayout()
        registerForTraitChanges([UITraitUserInterfaceStyle.self]) { (self: Self, _) in
            self.updateGradientColors()
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
        updateGradientColors()
    }

    private func updateGradientColors() {
        let start: UIColor
        let end: UIColor
        if isConnected {
            start = UIColor(named: "GradientStart") ?? .black
            end = UIColor(named: "GradientEnd") ?? .black
        } else {
            start = UIColor(named: "GradientDisconnectedStart") ?? .black
            end = UIColor(named: "GradientDisconnectedEnd") ?? .black
        }
        gradientLayer.colors = [start.cgColor, end.cgColor]
    }

    // MARK: - Layout

    private func setupLayout() {
        // Left side: power button + status
        let powerButton = makePowerButton()
        let statusLabel = UILabel()
        statusLabel.text = isConnected ? String(localized: "Connected") : String(localized: "Disconnected")
        statusLabel.font = .systemFont(ofSize: 44, weight: .medium)
        statusLabel.textColor = isConnected ? .white : .secondaryLabel
        statusLabel.textAlignment = .center

        let leftStack = UIStackView(arrangedSubviews: [powerButton, statusLabel])
        leftStack.axis = .vertical
        leftStack.alignment = .center
        leftStack.spacing = 40
        leftStack.translatesAutoresizingMaskIntoConstraints = false

        let leftContainer = UIView()
        leftContainer.translatesAutoresizingMaskIntoConstraints = false
        leftContainer.addSubview(leftStack)

        // Right side: stats + config
        var rightViews: [UIView] = []
        if isConnected {
            rightViews.append(makeStatsCard())
        }
        rightViews.append(makeConfigCard())

        let rightStack = UIStackView(arrangedSubviews: rightViews)
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

            powerButton.widthAnchor.constraint(equalToConstant: 260),
            powerButton.heightAnchor.constraint(equalToConstant: 260),
        ])

        for v in rightViews {
            v.widthAnchor.constraint(equalToConstant: 620).isActive = true
        }
    }

    // MARK: - Subviews

    private func makePowerButton() -> UIView {
        let button = UIButton(type: .custom)
        button.translatesAutoresizingMaskIntoConstraints = false
        button.backgroundColor = UIColor.white.withAlphaComponent(isConnected ? 0.25 : 0.15)
        button.layer.cornerRadius = 130
        button.clipsToBounds = false

        let iconConfig = UIImage.SymbolConfiguration(pointSize: 90, weight: .light)
        let icon = UIImageView(image: UIImage(systemName: "power", withConfiguration: iconConfig))
        icon.tintColor = isConnected ? .white : .systemBlue
        icon.contentMode = .scaleAspectFit
        icon.translatesAutoresizingMaskIntoConstraints = false
        button.addSubview(icon)

        NSLayoutConstraint.activate([
            icon.centerXAnchor.constraint(equalTo: button.centerXAnchor),
            icon.centerYAnchor.constraint(equalTo: button.centerYAnchor),
        ])
        return button
    }

    private func makeStatsCard() -> UIView {
        let card = UIButton(type: .custom)
        card.translatesAutoresizingMaskIntoConstraints = false
        card.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        card.layer.cornerRadius = 28

        let arrowConfig = UIImage.SymbolConfiguration(pointSize: 28, weight: .medium)

        let upArrow = UIImageView(image: UIImage(systemName: "arrow.up", withConfiguration: arrowConfig))
        upArrow.tintColor = UIColor.white.withAlphaComponent(0.7)
        upArrow.setContentHuggingPriority(.required, for: .horizontal)
        let upLabel = UILabel()
        upLabel.font = .monospacedDigitSystemFont(ofSize: 34, weight: .regular)
        upLabel.textColor = .white
        upLabel.text = Self.formatBytes(bytesOut)

        let downArrow = UIImageView(image: UIImage(systemName: "arrow.down", withConfiguration: arrowConfig))
        downArrow.tintColor = UIColor.white.withAlphaComponent(0.7)
        downArrow.setContentHuggingPriority(.required, for: .horizontal)
        let downLabel = UILabel()
        downLabel.font = .monospacedDigitSystemFont(ofSize: 34, weight: .regular)
        downLabel.textColor = .white
        downLabel.text = Self.formatBytes(bytesIn)

        let upStack = UIStackView(arrangedSubviews: [upArrow, upLabel])
        upStack.spacing = 12
        upStack.alignment = .center
        let downStack = UIStackView(arrangedSubviews: [downArrow, downLabel])
        downStack.spacing = 12
        downStack.alignment = .center

        let spacer = UIView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let hStack = UIStackView(arrangedSubviews: [upStack, spacer, downStack])
        hStack.translatesAutoresizingMaskIntoConstraints = false
        hStack.isUserInteractionEnabled = false
        card.addSubview(hStack)

        NSLayoutConstraint.activate([
            hStack.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 32),
            hStack.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -32),
            hStack.topAnchor.constraint(equalTo: card.topAnchor, constant: 22),
            hStack.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -22),
        ])
        return card
    }

    private func makeConfigCard() -> UIView {
        let card = UIButton(type: .custom)
        card.translatesAutoresizingMaskIntoConstraints = false
        card.backgroundColor = UIColor.white.withAlphaComponent(0.12)
        card.layer.cornerRadius = 28
        card.layer.shadowColor = UIColor.black.cgColor
        card.layer.shadowOffset = CGSize(width: 0, height: 4)
        card.layer.shadowRadius = 10
        card.layer.shadowOpacity = 0

        let iconConfig = UIImage.SymbolConfiguration(pointSize: 30, weight: .medium)
        let icon = UIImageView(image: UIImage(systemName: "antenna.radiowaves.left.and.right", withConfiguration: iconConfig))
        icon.tintColor = isConnected ? UIColor.white.withAlphaComponent(0.7) : .secondaryLabel
        icon.setContentHuggingPriority(.required, for: .horizontal)

        let nameLabel = UILabel()
        nameLabel.text = configName
        nameLabel.font = .systemFont(ofSize: 38, weight: .medium)
        nameLabel.textColor = isConnected ? .white : .label

        let chevronConfig = UIImage.SymbolConfiguration(pointSize: 20, weight: .semibold)
        let chevron = UIImageView(image: UIImage(systemName: "chevron.up.chevron.down", withConfiguration: chevronConfig))
        chevron.tintColor = UIColor.white.withAlphaComponent(0.4)
        chevron.setContentHuggingPriority(.required, for: .horizontal)

        let content = UIStackView(arrangedSubviews: [icon, nameLabel, chevron])
        content.spacing = 16
        content.alignment = .center
        content.translatesAutoresizingMaskIntoConstraints = false
        content.isUserInteractionEnabled = false
        card.addSubview(content)

        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: card.leadingAnchor, constant: 32),
            content.trailingAnchor.constraint(equalTo: card.trailingAnchor, constant: -32),
            content.topAnchor.constraint(equalTo: card.topAnchor, constant: 24),
            content.bottomAnchor.constraint(equalTo: card.bottomAnchor, constant: -24),
        ])
        return card
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

// MARK: - Demo Proxy List View Controller

class TVDemoProxyListViewController: UITableViewController {

    private let standalone = SampleData.standaloneConfigurations
    private let subscriptionConfigs = SampleData.subscriptionConfigurations
    private let selectedId = SampleData.configurations[0].id

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Proxies")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(TVProxyCell.self, forCellReuseIdentifier: TVProxyCell.reuseIdentifier)
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

        let addButton = UIBarButtonItem(barButtonSystemItem: .add, target: nil, action: nil)
        addButton.tintColor = .label
        
        let testAllButton = UIBarButtonItem(title: String(localized: "Test All"), style: .plain, target: nil, action: nil)
        testAllButton.tintColor = .label
        
        navigationItem.rightBarButtonItems = [
            addButton,
            testAllButton,
        ]
    }

    // MARK: - Sections

    private var sectionCount: Int {
        (standalone.isEmpty ? 0 : 1) + (subscriptionConfigs.isEmpty ? 0 : 1)
    }

    private func configs(for section: Int) -> [ProxyConfiguration] {
        if !standalone.isEmpty && section == 0 { return standalone }
        return subscriptionConfigs
    }

    // MARK: - Data Source

    override func numberOfSections(in tableView: UITableView) -> Int { sectionCount }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        configs(for: section).count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        // Subscription sections use custom header view instead
        nil
    }

    override func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
        if !standalone.isEmpty && section == 0 { return nil }

        let header = UIView()

        // Collapse toggle button
        var collapseConfig = UIButton.Configuration.plain()
        collapseConfig.image = UIImage(systemName: "chevron.down")
        collapseConfig.title = SampleData.subscription.name
        collapseConfig.imagePadding = 10
        collapseConfig.titleTextAttributesTransformer = UIConfigurationTextAttributesTransformer { incoming in
            var outgoing = incoming
            outgoing.font = UIFont.systemFont(ofSize: 24, weight: .semibold)
            return outgoing
        }
        let collapseBtn = UIButton(configuration: collapseConfig)
        collapseBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(collapseBtn)

        // Ellipsis menu button
        var menuConfig = UIButton.Configuration.plain()
        menuConfig.image = UIImage(systemName: "ellipsis.circle")
        let menuBtn = UIButton(configuration: menuConfig)
        menuBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(menuBtn)

        // Update button
        var updateConfig = UIButton.Configuration.plain()
        updateConfig.image = UIImage(systemName: "arrow.clockwise")
        let updateBtn = UIButton(configuration: updateConfig)
        updateBtn.translatesAutoresizingMaskIntoConstraints = false
        header.addSubview(updateBtn)

        NSLayoutConstraint.activate([
            collapseBtn.leadingAnchor.constraint(equalTo: header.leadingAnchor, constant: 40),
            collapseBtn.trailingAnchor.constraint(lessThanOrEqualTo: updateBtn.leadingAnchor, constant: -20),
            collapseBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            menuBtn.trailingAnchor.constraint(equalTo: header.trailingAnchor, constant: -40),
            menuBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
            updateBtn.trailingAnchor.constraint(equalTo: menuBtn.leadingAnchor, constant: -20),
            updateBtn.centerYAnchor.constraint(equalTo: header.centerYAnchor),
        ])

        return header
    }

    override func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
        if !standalone.isEmpty && section == 0 { return UITableView.automaticDimension }
        return 100
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: TVProxyCell.reuseIdentifier, for: indexPath) as! TVProxyCell
        let config = configs(for: indexPath.section)[indexPath.row]
        let isSelected = config.id == selectedId

        cell.configure(
            name: config.name,
            isSelected: isSelected,
            protocolName: config.outboundProtocol.name,
            transport: config.outboundProtocol == .vless ? config.transport : nil,
            security: config.security,
            flow: config.flow
        )

        // Latency accessory
        if let result = SampleData.latencyResults[config.id] {
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            switch result {
            case .testing:
                let spinner = UIActivityIndicatorView(style: .medium)
                spinner.startAnimating()
                cell.accessoryView = spinner
                return cell
            case .success(let ms):
                label.text = String(localized: "\(ms) ms")
                label.textColor = ms < 300 ? .systemGreen : ms < 500 ? .systemYellow : .systemRed
            case .failed:
                label.text = String(localized: "timeout")
                label.textColor = .secondaryLabel
            case .insecure:
                label.text = String(localized: "insecure")
                label.textColor = .secondaryLabel
            }
            label.sizeToFit()
            cell.accessoryView = label
        }

        return cell
    }

    // MARK: - Focus

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)
        coordinator.addCoordinatedAnimations {
            if let cell = context.nextFocusedView as? UITableViewCell {
                cell.overrideUserInterfaceStyle = .light
            }
            if let cell = context.previouslyFocusedView as? UITableViewCell {
                cell.overrideUserInterfaceStyle = .unspecified
            }
        }
    }
}

// MARK: - Demo Chain List View Controller

class TVDemoChainListViewController: UITableViewController {

    private let chains = SampleData.chains
    private let configurations = SampleData.configurations
    private let selectedChainId = SampleData.chains[0].id

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Chains")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(TVChainCell.self, forCellReuseIdentifier: TVChainCell.reuseIdentifier)
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80

        let addButton = UIBarButtonItem(barButtonSystemItem: .add, target: nil, action: nil)
        addButton.tintColor = .label
        
        let testAllButton = UIBarButtonItem(title: String(localized: "Test All"), style: .plain, target: nil, action: nil)
        testAllButton.tintColor = .label
        
        navigationItem.rightBarButtonItems = [
            addButton,
            testAllButton,
        ]
    }

    // MARK: - Data Source

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        chains.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: TVChainCell.reuseIdentifier, for: indexPath) as! TVChainCell
        let chain = chains[indexPath.row]
        let proxies = chain.resolveProxies(from: configurations)
        let isValid = proxies.count == chain.proxyIds.count && proxies.count >= 2
        let isSelected = chain.id == selectedChainId

        var infoText = "\(proxies.count) proxies"
        if let entry = proxies.first, let exit = proxies.last {
            infoText += " · \(entry.serverAddress) → \(exit.serverAddress)"
        }

        cell.configure(
            name: chain.name,
            isSelected: isSelected,
            proxyNames: proxies.map(\.name),
            isValid: isValid,
            infoText: infoText
        )

        // Latency accessory
        if isValid, let result = SampleData.chainLatencyResults[chain.id] {
            let label = UILabel()
            label.font = .monospacedDigitSystemFont(ofSize: 22, weight: .regular)
            switch result {
            case .testing:
                let spinner = UIActivityIndicatorView(style: .medium)
                spinner.startAnimating()
                cell.accessoryView = spinner
                return cell
            case .success(let ms):
                label.text = String(localized: "\(ms) ms")
                label.textColor = ms < 300 ? .systemGreen : ms < 500 ? .systemYellow : .systemRed
            case .failed:
                label.text = String(localized: "timeout")
                label.textColor = .secondaryLabel
            case .insecure:
                label.text = String(localized: "insecure")
                label.textColor = .secondaryLabel
            }
            label.sizeToFit()
            cell.accessoryView = label
        }

        return cell
    }

    // MARK: - Focus

    override func didUpdateFocus(in context: UIFocusUpdateContext, with coordinator: UIFocusAnimationCoordinator) {
        super.didUpdateFocus(in: context, with: coordinator)
        coordinator.addCoordinatedAnimations {
            if let cell = context.nextFocusedView as? UITableViewCell {
                cell.overrideUserInterfaceStyle = .light
            }
            if let cell = context.previouslyFocusedView as? UITableViewCell {
                cell.overrideUserInterfaceStyle = .unspecified
            }
        }
    }
}

// MARK: - Previews

#Preview("Home - Connected") {
    TVDemoHomeViewController(isConnected: true)
}

#Preview("Home - Disconnected") {
    TVDemoHomeViewController(isConnected: false)
}

#Preview("Proxy List") {
    UINavigationController(rootViewController: TVDemoProxyListViewController())
}

#Preview("Chain List") {
    UINavigationController(rootViewController: TVDemoChainListViewController())
}

#endif
