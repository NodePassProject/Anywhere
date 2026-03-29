//
//  TVAddProxyViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit

class TVAddProxyViewController: UITableViewController {

    private let viewModel = VPNViewModel.shared

    private enum Method: Int, CaseIterable {
        case link = 0
        case manual = 1

        var title: String {
            switch self {
            case .link: String(localized: "Link")
            case .manual: String(localized: "Manual")
            }
        }

        var systemImage: String {
            switch self {
            case .link: "link"
            case .manual: "hand.point.up.left"
            }
        }
    }

    private enum LinkType: Int {
        case subscription = 0
        case http11 = 1
        case http2 = 2
    }

    private var selectedMethod: Method?
    private var linkURL = ""
    private var linkType: LinkType = .subscription
    private var isLoading = false

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = String(localized: "Add Proxy")
        tableView = UITableView(frame: .zero, style: .grouped)
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80
        tableView.remembersLastFocusedIndexPath = true

        navigationItem.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped)
        )
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            title: String(localized: "Continue"), style: .done, target: self, action: #selector(continueTapped)
        )
        updateContinueButton()
    }

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    // MARK: - Table View

    override func numberOfSections(in tableView: UITableView) -> Int {
        selectedMethod == .link ? 3 : 1
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch section {
        case 0: return Method.allCases.count
        case 1: return 1 // Link text field
        case 2: return isHTTPLink ? 1 : 0 // Link type picker
        default: return 0
        }
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch section {
        case 0: return String(localized: "Method")
        case 1: return String(localized: "Link")
        case 2: return isHTTPLink ? String(localized: "Link Type") : nil
        default: return nil
        }
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        if section == 1 {
            return String(localized: "Supports proxy, subscription and Clash links")
        }
        return nil
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.accessoryView = nil
        cell.accessoryType = .none

        switch indexPath.section {
        case 0:
            let method = Method(rawValue: indexPath.row)!
            var content = cell.defaultContentConfiguration()
            content.text = method.title
            content.image = UIImage(systemName: method.systemImage)
            cell.contentConfiguration = content
            cell.accessoryType = selectedMethod == method ? .checkmark : .none

        case 1:
            var content = cell.defaultContentConfiguration()
            if linkURL.isEmpty {
                content.text = String(localized: "Link")
                content.textProperties.color = .tertiaryLabel
            } else {
                content.text = linkURL
            }
            cell.contentConfiguration = content

        case 2:
            var content = cell.defaultContentConfiguration()
            let typeText: String
            switch linkType {
            case .subscription: typeText = String(localized: "Subscription")
            case .http11: typeText = String(localized: "HTTPS Proxy")
            case .http2: typeText = String(localized: "HTTP/2 Proxy")
            }
            content.text = typeText
            cell.contentConfiguration = content
            cell.accessoryType = .disclosureIndicator

        default:
            break
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

    // MARK: - Selection

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)

        switch indexPath.section {
        case 0:
            let method = Method(rawValue: indexPath.row)!
            selectedMethod = method

            if method == .manual {
                dismiss(animated: true) { [weak self] in
                    guard let self else { return }
                    let editor = TVProxyEditorViewController { config in
                        self.viewModel.addConfiguration(config)
                    }
                    let nav = UINavigationController(rootViewController: editor)
                    nav.modalPresentationStyle = .fullScreen
                    // Present from the tab bar controller
                    if let windowScene = UIApplication.shared.connectedScenes
                        .compactMap({ $0 as? UIWindowScene })
                        .first(where: { $0.activationState == .foregroundActive }),
                       let rootViewController = windowScene.windows
                        .first(where: { $0.isKeyWindow })?.rootViewController {
                        rootViewController.present(nav, animated: true)
                    }
                }
                return
            }

            tableView.reloadData()
            updateContinueButton()

        case 1:
            showTextInput()

        case 2:
            showLinkTypePicker()

        default:
            break
        }
    }

    // MARK: - Text Input

    private func showTextInput() {
        // tvOS UIAlertController does not support addTextField.
        // Use a full-screen text input VC instead.
        let inputVC = TVTextInputViewController(
            title: String(localized: "Link"),
            currentValue: linkURL,
            placeholder: String(localized: "Link")
        ) { [weak self] value in
            self?.linkURL = value
            self?.tableView.reloadData()
            self?.updateContinueButton()
        }
        let nav = UINavigationController(rootViewController: inputVC)
        nav.modalPresentationStyle = .fullScreen
        present(nav, animated: true)
    }

    // MARK: - Link Type Picker

    private var isHTTPLink: Bool {
        linkURL.hasPrefix("http://") || linkURL.hasPrefix("https://")
    }

    private func showLinkTypePicker() {
        let alert = UIAlertController(title: String(localized: "Link Type"), message: nil, preferredStyle: .actionSheet)
        alert.addAction(UIAlertAction(title: String(localized: "Subscription"), style: .default) { [weak self] _ in
            self?.linkType = .subscription
            self?.tableView.reloadData()
        })
        alert.addAction(UIAlertAction(title: String(localized: "HTTPS Proxy"), style: .default) { [weak self] _ in
            self?.linkType = .http11
            self?.tableView.reloadData()
        })
        alert.addAction(UIAlertAction(title: String(localized: "HTTP/2 Proxy"), style: .default) { [weak self] _ in
            self?.linkType = .http2
            self?.tableView.reloadData()
        })
        alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
        present(alert, animated: true)
    }

    // MARK: - Continue

    private func updateContinueButton() {
        let enabled: Bool
        switch selectedMethod {
        case .link: enabled = !linkURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isLoading
        case .manual: enabled = true
        case nil: enabled = false
        }
        navigationItem.rightBarButtonItem?.isEnabled = enabled
    }

    @objc private func continueTapped() {
        guard selectedMethod == .link else { return }
        importFromString(linkURL)
    }

    private func importFromString(_ string: String) {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        let isHTTP = trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")

        if trimmed.hasPrefix("vless://") || trimmed.hasPrefix("ss://") ||
            trimmed.hasPrefix("socks5://") || trimmed.hasPrefix("socks://") ||
            (isHTTP && linkType != .subscription) {
            let naiveProtocol: OutboundProtocol? = switch linkType {
            case .http11: .http11
            case .http2: .http2
            case .subscription: nil
            }
            do {
                let config = try ProxyConfiguration.parse(url: trimmed, naiveProtocol: naiveProtocol)
                viewModel.addConfiguration(config)
                dismiss(animated: true)
            } catch {
                showError(error.localizedDescription)
            }
        } else {
            isLoading = true
            updateContinueButton()
            Task {
                do {
                    let result = try await SubscriptionFetcher.fetch(url: trimmed)
                    let subscription = Subscription(
                        name: result.name ?? URL(string: trimmed)?.host ?? String(localized: "Subscription"),
                        url: trimmed,
                        lastUpdate: Date(),
                        upload: result.upload,
                        download: result.download,
                        total: result.total,
                        expire: result.expire
                    )
                    viewModel.addSubscription(configurations: result.configurations, subscription: subscription)
                    dismiss(animated: true)
                } catch {
                    showError(error.localizedDescription)
                }
                isLoading = false
                updateContinueButton()
            }
        }
    }

    private func showError(_ message: String) {
        let alert = UIAlertController(title: String(localized: "Import Failed"), message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: String(localized: "OK"), style: .cancel))
        present(alert, animated: true)
    }
}

// MARK: - Text Input VC (tvOS full-screen text input)

class TVTextInputViewController: UIViewController {

    private let titleText: String
    private let currentValue: String
    private let placeholder: String
    private let onDone: (String) -> Void
    var isSecure = false

    private let textField = UITextField()

    init(title: String, currentValue: String, placeholder: String, isSecure: Bool = false, onDone: @escaping (String) -> Void) {
        self.titleText = title
        self.currentValue = currentValue
        self.placeholder = placeholder
        self.isSecure = isSecure
        self.onDone = onDone
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = titleText

        textField.text = currentValue
        textField.placeholder = placeholder
        textField.font = .systemFont(ofSize: 32)
        textField.borderStyle = .roundedRect
        textField.autocorrectionType = .no
        textField.autocapitalizationType = .none
        textField.keyboardType = .URL
        textField.isSecureTextEntry = isSecure
        textField.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(textField)

        NSLayoutConstraint.activate([
            textField.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            textField.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -60),
            textField.widthAnchor.constraint(equalToConstant: 800),
        ])

        navigationItem.leftBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped))
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(doneTapped))
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        textField.becomeFirstResponder()
    }

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    @objc private func doneTapped() {
        onDone(textField.text ?? "")
        dismiss(animated: true)
    }
}
