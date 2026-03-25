//
//  TVProxyEditorViewController.swift
//  Anywhere TV
//
//  Created by Argsment Limited on 3/19/26.
//

import UIKit

class TVProxyEditorViewController: UITableViewController {

    // MARK: - Properties

    private let existingConfiguration: ProxyConfiguration?
    private let onSave: (ProxyConfiguration) -> Void

    // Form state
    private var selectedProtocol: OutboundProtocol = .vless
    private var name = ""
    private var serverAddress = ""
    private var serverPort = ""
    private var uuid = ""
    private var encryption = "none"
    private var transport = "tcp"
    private var flow = ""
    private var security = "none"
    private var wsHost = ""
    private var wsPath = "/"
    private var huHost = ""
    private var huPath = "/"
    private var xhttpHost = ""
    private var xhttpPath = "/"
    private var xhttpMode = "auto"
    private var tlsSNI = ""
    private var tlsALPN = ""
    private var muxEnabled = true
    private var xudpEnabled = true
    private var sni = ""
    private var publicKey = ""
    private var shortId = ""
    private var fingerprint: TLSFingerprint = .chrome133
    private var ssPassword = ""
    private var ssMethod = "aes-128-gcm"
    private var naiveUsername = ""
    private var naivePassword = ""

    private var isShadowsocks: Bool { selectedProtocol == .shadowsocks }
    private var isNaive: Bool { selectedProtocol.isNaive }
    private var isReality: Bool { security == "reality" }
    private var isTLS: Bool { security == "tls" }

    // MARK: - Form Structure

    private enum RowType {
        case text(label: String, value: String, placeholder: String, key: FieldKey, secure: Bool = false)
        case selection(label: String, value: String, options: [(display: String, value: String)], key: FieldKey)
        case toggle(label: String, isOn: Bool, key: FieldKey)
    }

    private enum FieldKey {
        case name, address, port, uuid
        case outboundProtocol, encryption, transport, flow, security
        case mux, xudp
        case wsHost, wsPath, huHost, huPath, xhttpHost, xhttpPath, xhttpMode
        case tlsSNI, tlsALPN, fingerprint
        case realitySNI, publicKey, shortId
        case ssPassword, ssMethod
        case naiveUsername, naivePassword
    }

    private var formSections: [(title: String?, rows: [RowType])] {
        var sections: [(title: String?, rows: [RowType])] = []

        // Name
        sections.append((nil, [
            .text(label: String(localized: "Name"), value: name, placeholder: "Name", key: .name),
        ]))

        // Protocol
        let protocolOptions: [(String, String)] = [
            ("VLESS", "vless"), ("Shadowsocks", "shadowsocks"), ("HTTPS", "http11"), ("HTTP2", "http2"),
        ]
        sections.append((String(localized: "Protocol"), [
            .selection(label: String(localized: "Protocol"), value: selectedProtocol.name, options: protocolOptions, key: .outboundProtocol),
        ]))

        // Server
        var serverRows: [RowType] = [
            .text(label: String(localized: "Address"), value: serverAddress, placeholder: "Address", key: .address),
            .text(label: String(localized: "Port"), value: serverPort, placeholder: "443", key: .port),
        ]
        if isNaive {
            serverRows.append(.text(label: String(localized: "Username"), value: naiveUsername, placeholder: "Username", key: .naiveUsername))
            serverRows.append(.text(label: String(localized: "Password"), value: naivePassword, placeholder: "Password", key: .naivePassword, secure: true))
        } else if isShadowsocks {
            serverRows.append(.text(label: String(localized: "Password"), value: ssPassword, placeholder: "Password", key: .ssPassword, secure: true))
            let methods: [(String, String)] = [
                ("None", "none"), ("AES-128-GCM", "aes-128-gcm"), ("AES-256-GCM", "aes-256-gcm"),
                ("ChaCha20-Poly1305", "chacha20-ietf-poly1305"),
                ("BLAKE3-AES-128-GCM", "2022-blake3-aes-128-gcm"), ("BLAKE3-AES-256-GCM", "2022-blake3-aes-256-gcm"),
                ("BLAKE3-ChaCha20", "2022-blake3-chacha20-poly1305"),
            ]
            serverRows.append(.selection(label: String(localized: "Method"), value: ssMethod, options: methods, key: .ssMethod))
        } else {
            serverRows.append(.text(label: "UUID", value: uuid, placeholder: "UUID", key: .uuid))
            serverRows.append(.selection(label: String(localized: "Encryption"), value: encryption, options: [("None", "none")], key: .encryption))
        }
        sections.append((String(localized: "Server"), serverRows))

        // Transport (hidden for Naive)
        if !isNaive {
            var transportRows: [RowType] = [
                .selection(label: String(localized: "Transport"), value: transport.uppercased(), options: [
                    ("TCP", "tcp"), ("WebSocket", "ws"), ("HTTPUpgrade", "httpupgrade"), ("XHTTP", "xhttp"),
                ], key: .transport),
            ]
            if !isShadowsocks && transport == "tcp" {
                transportRows.append(.selection(label: String(localized: "Flow"), value: flowDisplayValue, options: [
                    ("None", ""), ("Vision", "xtls-rprx-vision"), ("Vision + UDP 443", "xtls-rprx-vision-udp443"),
                ], key: .flow))
                transportRows.append(.toggle(label: String(localized: "Mux"), isOn: muxEnabled, key: .mux))
                if muxEnabled {
                    transportRows.append(.toggle(label: "XUDP", isOn: xudpEnabled, key: .xudp))
                }
            }
            if transport == "ws" {
                transportRows.append(.text(label: String(localized: "Host"), value: wsHost, placeholder: "Host", key: .wsHost))
                transportRows.append(.text(label: String(localized: "Path"), value: wsPath, placeholder: "/", key: .wsPath))
            }
            if transport == "httpupgrade" {
                transportRows.append(.text(label: String(localized: "Host"), value: huHost, placeholder: "Host", key: .huHost))
                transportRows.append(.text(label: String(localized: "Path"), value: huPath, placeholder: "/", key: .huPath))
            }
            if transport == "xhttp" {
                transportRows.append(.text(label: String(localized: "Host"), value: xhttpHost, placeholder: "Host", key: .xhttpHost))
                transportRows.append(.text(label: String(localized: "Path"), value: xhttpPath, placeholder: "/", key: .xhttpPath))
                transportRows.append(.selection(label: String(localized: "Mode"), value: xhttpMode, options: [
                    ("Auto", "auto"), ("Packet Up", "packet-up"), ("Stream Up", "stream-up"), ("Stream One", "stream-one"),
                ], key: .xhttpMode))
            }
            sections.append((String(localized: "Transport"), transportRows))
        }

        // TLS (hidden for Naive)
        if !isNaive {
            var tlsRows: [RowType] = [
                .selection(label: String(localized: "Security"), value: security.uppercased(), options: {
                    var opts: [(String, String)] = [("None", "none"), ("TLS", "tls")]
                    if !isShadowsocks { opts.append(("Reality", "reality")) }
                    return opts
                }(), key: .security),
            ]
            if isTLS {
                tlsRows.append(.text(label: "SNI", value: tlsSNI, placeholder: "SNI", key: .tlsSNI))
                tlsRows.append(.text(label: "ALPN", value: tlsALPN, placeholder: "h2,http/1.1", key: .tlsALPN))
                tlsRows.append(.selection(label: String(localized: "Fingerprint"), value: fingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .fingerprint))
            }
            if isReality {
                tlsRows.append(.text(label: "SNI", value: sni, placeholder: "SNI", key: .realitySNI))
                tlsRows.append(.text(label: String(localized: "Public Key"), value: publicKey, placeholder: "Public Key", key: .publicKey))
                tlsRows.append(.text(label: String(localized: "Short ID"), value: shortId, placeholder: "Short ID", key: .shortId))
                tlsRows.append(.selection(label: String(localized: "Fingerprint"), value: fingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .fingerprint))
            }
            sections.append(("TLS", tlsRows))
        }

        return sections
    }

    private var flowDisplayValue: String {
        switch flow {
        case "xtls-rprx-vision": "Vision"
        case "xtls-rprx-vision-udp443": "Vision + UDP 443"
        default: "None"
        }
    }

    private var isValid: Bool {
        guard !name.isEmpty, !serverAddress.isEmpty, UInt16(serverPort) != nil else { return false }
        if isNaive { return !naiveUsername.isEmpty && !naivePassword.isEmpty }
        if isShadowsocks { return !ssPassword.isEmpty }
        return UUID(uuidString: uuid) != nil && (!isReality || (!sni.isEmpty && !publicKey.isEmpty))
    }

    // MARK: - Init

    init(configuration: ProxyConfiguration? = nil, onSave: @escaping (ProxyConfiguration) -> Void) {
        self.existingConfiguration = configuration
        self.onSave = onSave
        super.init(style: .grouped)
    }

    required init?(coder: NSCoder) { fatalError() }

    // MARK: - Lifecycle

    override func viewDidLoad() {
        super.viewDidLoad()
        title = existingConfiguration != nil ? String(localized: "Edit Configuration") : String(localized: "Add Configuration")
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "cell")

        navigationItem.leftBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped))
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .save, target: self, action: #selector(saveTapped))

        if let config = existingConfiguration {
            populateFromExisting(config)
        }
        updateSaveButton()
    }

    // MARK: - Table View

    override func numberOfSections(in tableView: UITableView) -> Int {
        formSections.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        formSections[section].rows.count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        formSections[section].title
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.accessoryType = .none
        cell.accessoryView = nil

        let row = formSections[indexPath.section].rows[indexPath.row]

        switch row {
        case .text(let label, let value, let placeholder, _, let secure):
            var content = cell.defaultContentConfiguration()
            content.text = label
            if value.isEmpty {
                content.secondaryText = placeholder
                content.secondaryTextProperties.color = .tertiaryLabel
            } else {
                content.secondaryText = secure ? String(repeating: "•", count: min(value.count, 12)) : value
                content.secondaryTextProperties.color = .label
            }
            cell.contentConfiguration = content
            cell.accessoryType = .disclosureIndicator

        case .selection(let label, let value, _, _):
            var content = cell.defaultContentConfiguration()
            content.text = label
            content.secondaryText = value
            content.secondaryTextProperties.color = .systemBlue
            cell.contentConfiguration = content
            cell.accessoryType = .disclosureIndicator

        case .toggle(let label, let isOn, _):
            var content = cell.defaultContentConfiguration()
            content.text = label
            content.secondaryText = isOn ? String(localized: "On") : String(localized: "Off")
            content.secondaryTextProperties.color = isOn ? .systemGreen : .secondaryLabel
            cell.contentConfiguration = content
        }

        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let row = formSections[indexPath.section].rows[indexPath.row]

        switch row {
        case .text(let label, let value, let placeholder, let key, let secure):
            let inputVC = TVTextInputViewController(
                title: label,
                currentValue: value,
                placeholder: placeholder,
                isSecure: secure
            ) { [weak self] newValue in
                self?.updateField(key, value: newValue)
                self?.tableView.reloadData()
                self?.updateSaveButton()
            }
            let nav = UINavigationController(rootViewController: inputVC)
            nav.modalPresentationStyle = .fullScreen
            present(nav, animated: true)

        case .selection(_, _, let options, let key):
            let alert = UIAlertController(title: nil, message: nil, preferredStyle: .actionSheet)
            for (display, value) in options {
                alert.addAction(UIAlertAction(title: display, style: .default) { [weak self] _ in
                    self?.updateField(key, value: value)
                    self?.tableView.reloadData()
                    self?.updateSaveButton()
                })
            }
            alert.addAction(UIAlertAction(title: String(localized: "Cancel"), style: .cancel))
            present(alert, animated: true)

        case .toggle(_, let isOn, let key):
            updateField(key, value: isOn ? "false" : "true")
            tableView.reloadData()
            updateSaveButton()
        }
    }

    // MARK: - Field Updates

    private func updateField(_ key: FieldKey, value: String) {
        switch key {
        case .name: name = value
        case .address: serverAddress = value
        case .port: serverPort = value
        case .uuid: uuid = value
        case .outboundProtocol:
            if let proto = OutboundProtocol(rawValue: value) {
                selectedProtocol = proto
                if isShadowsocks || isNaive {
                    flow = ""
                    if security == "reality" { security = "none" }
                }
            }
        case .encryption: encryption = value
        case .transport:
            transport = value
            if flow != "" && transport != "tcp" { flow = "" }
        case .flow: flow = value
        case .security: security = value
        case .mux:
            muxEnabled = value == "true"
            if !muxEnabled { xudpEnabled = false }
        case .xudp: xudpEnabled = value == "true"
        case .wsHost: wsHost = value
        case .wsPath: wsPath = value
        case .huHost: huHost = value
        case .huPath: huPath = value
        case .xhttpHost: xhttpHost = value
        case .xhttpPath: xhttpPath = value
        case .xhttpMode: xhttpMode = value
        case .tlsSNI: tlsSNI = value
        case .tlsALPN: tlsALPN = value
        case .fingerprint:
            if let fp = TLSFingerprint(rawValue: value) { fingerprint = fp }
        case .realitySNI: sni = value
        case .publicKey: publicKey = value
        case .shortId: shortId = value
        case .ssPassword: ssPassword = value
        case .ssMethod: ssMethod = value
        case .naiveUsername: naiveUsername = value
        case .naivePassword: naivePassword = value
        }
    }

    // MARK: - Populate

    private func populateFromExisting(_ config: ProxyConfiguration) {
        selectedProtocol = config.outboundProtocol
        name = config.name
        serverAddress = config.serverAddress
        serverPort = String(config.serverPort)
        uuid = config.uuid.uuidString
        encryption = config.encryption
        transport = config.transport
        flow = config.flow ?? ""
        security = config.security
        muxEnabled = config.muxEnabled
        xudpEnabled = config.xudpEnabled

        if let ws = config.websocket {
            wsHost = ws.host
            wsPath = ws.path
        }
        if let hu = config.httpUpgrade {
            huHost = hu.host
            huPath = hu.path
        }
        if let xhttp = config.xhttp {
            xhttpHost = xhttp.host
            xhttpPath = xhttp.path
            xhttpMode = xhttp.mode.rawValue
        }
        if let tls = config.tls {
            tlsSNI = tls.serverName
            tlsALPN = tls.alpn?.joined(separator: ",") ?? ""
            fingerprint = tls.fingerprint
        }
        if let reality = config.reality {
            sni = reality.serverName
            publicKey = reality.publicKey.base64URLEncodedString()
            shortId = reality.shortId.hexEncodedString()
            fingerprint = reality.fingerprint
        }

        ssPassword = config.ssPassword ?? ""
        ssMethod = config.ssMethod ?? "aes-128-gcm"
        naiveUsername = config.activeUsername ?? ""
        naivePassword = config.activePassword ?? ""
    }

    // MARK: - Actions

    @objc private func cancelTapped() {
        dismiss(animated: true)
    }

    @objc private func saveTapped() {
        save()
    }

    private func updateSaveButton() {
        navigationItem.rightBarButtonItem?.isEnabled = isValid
    }

    private func save() {
        guard let port = UInt16(serverPort) else { return }
        let parsedUUID: UUID
        if isShadowsocks || isNaive {
            parsedUUID = existingConfiguration?.uuid ?? UUID()
        } else {
            guard let u = UUID(uuidString: uuid) else { return }
            parsedUUID = u
        }

        var tlsConfiguration: TLSConfiguration?
        if isTLS {
            let sniValue = tlsSNI.isEmpty ? serverAddress : tlsSNI
            let alpn: [String]? = tlsALPN.isEmpty ? nil : tlsALPN.split(separator: ",").map { String($0) }
            tlsConfiguration = TLSConfiguration(serverName: sniValue, alpn: alpn, fingerprint: fingerprint)
        }

        var realityConfiguration: RealityConfiguration?
        if isReality {
            guard let pk = Data(base64URLEncoded: publicKey) else { return }
            let sid = Data(hexString: shortId) ?? Data()
            realityConfiguration = RealityConfiguration(serverName: sni, publicKey: pk, shortId: sid, fingerprint: fingerprint)
        }

        var wsConfig: WebSocketConfiguration?
        if transport == "ws" {
            wsConfig = WebSocketConfiguration(host: wsHost.isEmpty ? serverAddress : wsHost, path: wsPath.isEmpty ? "/" : wsPath)
        }

        var huConfig: HTTPUpgradeConfiguration?
        if transport == "httpupgrade" {
            huConfig = HTTPUpgradeConfiguration(host: huHost.isEmpty ? serverAddress : huHost, path: huPath.isEmpty ? "/" : huPath)
        }

        var xhttpConfig: XHTTPConfiguration?
        if transport == "xhttp" {
            let host = xhttpHost.isEmpty ? serverAddress : xhttpHost
            let mode = XHTTPMode(rawValue: xhttpMode) ?? .auto
            xhttpConfig = XHTTPConfiguration.parse(from: ["host": host, "path": xhttpPath, "mode": mode.rawValue], serverAddress: serverAddress)
        }

        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast()) : serverAddress

        let config = ProxyConfiguration(
            id: existingConfiguration?.id ?? UUID(),
            name: name,
            serverAddress: bareAddress,
            serverPort: port,
            uuid: parsedUUID,
            encryption: encryption,
            transport: transport,
            flow: flow.isEmpty ? nil : flow,
            security: security,
            tls: tlsConfiguration,
            reality: realityConfiguration,
            websocket: wsConfig,
            httpUpgrade: huConfig,
            xhttp: xhttpConfig,
            testseed: existingConfiguration?.testseed,
            muxEnabled: muxEnabled,
            xudpEnabled: xudpEnabled,
            subscriptionId: existingConfiguration?.subscriptionId,
            outboundProtocol: selectedProtocol,
            ssPassword: isShadowsocks ? ssPassword : nil,
            ssMethod: isShadowsocks ? ssMethod : nil,
            http11Username: selectedProtocol == .http11 ? naiveUsername : nil,
            http11Password: selectedProtocol == .http11 ? naivePassword : nil,
            http2Username: selectedProtocol == .http2 ? naiveUsername : nil,
            http2Password: selectedProtocol == .http2 ? naivePassword : nil,
            http3Username: selectedProtocol == .http3 ? naiveUsername : nil,
            http3Password: selectedProtocol == .http3 ? naivePassword : nil
        )

        onSave(config)
        dismiss(animated: true)
    }
}

