//
//  TVProxyEditorViewController.swift
//  Anywhere
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
    private var grpcServiceName = ""
    private var grpcAuthority = ""
    private var grpcMode = "gun"
    private var grpcUserAgent = ""
    private var xhttpHost = ""
    private var xhttpPath = "/"
    private var xhttpMode = "auto"
    private var xhttpExtra = ""
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
    private var hysteriaPassword = ""
    private var hysteriaUploadMbpsText = String(HysteriaUploadMbpsDefault)
    private var trojanPassword = ""
    private var socks5Username = ""
    private var socks5Password = ""
    private var sudokuKey = ""
    private var sudokuAEADMethod: SudokuAEADMethod = .chacha20Poly1305
    private var sudokuPaddingMinText = "5"
    private var sudokuPaddingMaxText = "15"
    private var sudokuASCIIMode: SudokuASCIIMode = .preferEntropy
    private var sudokuCustomTablesText = ""
    private var sudokuEnablePureDownlink = true
    private var sudokuHTTPMaskDisable = false
    private var sudokuHTTPMaskMode: SudokuHTTPMaskMode = .legacy
    private var sudokuHTTPMaskTLS = false
    private var sudokuHTTPMaskHost = ""
    private var sudokuHTTPMaskPathRoot = ""
    private var sudokuHTTPMaskMultiplex: SudokuHTTPMaskMultiplex = .off
    private var naiveUsername = ""
    private var naivePassword = ""

    private var isVLESS: Bool { selectedProtocol == .vless }
    private var isHysteria: Bool { selectedProtocol == .hysteria }
    private var isTrojan: Bool { selectedProtocol == .trojan }
    private var isShadowsocks: Bool { selectedProtocol == .shadowsocks }
    private var isSOCKS5: Bool { selectedProtocol == .socks5 }
    private var isSudoku: Bool { selectedProtocol == .sudoku }
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
        case wsHost, wsPath
        case huHost, huPath
        case grpcServiceName, grpcAuthority, grpcMode, grpcUserAgent
        case xhttpHost, xhttpPath, xhttpMode
        case tlsSNI, tlsALPN, fingerprint
        case realitySNI, publicKey, shortId
        case hysteriaPassword, hysteriaUploadMbps
        case trojanPassword
        case ssPassword, ssMethod
        case sudokuKey, sudokuAEADMethod, sudokuPaddingMin, sudokuPaddingMax
        case sudokuASCIIMode, sudokuCustomTables
        case sudokuPureDownlink
        case sudokuHTTPMaskDisable, sudokuHTTPMaskMode, sudokuHTTPMaskTLS
        case sudokuHTTPMaskHost, sudokuHTTPMaskPathRoot, sudokuHTTPMaskMultiplex
        case naiveUsername, naivePassword
        case socks5Username, socks5Password
    }

    private var formSections: [(title: String?, rows: [RowType])] {
        var sections: [(title: String?, rows: [RowType])] = []

        // Name
        sections.append((nil, [
            .text(label: String(localized: "Name"), value: name, placeholder: "Name", key: .name),
        ]))

        // Protocol
        let protocolOptions: [(String, String)] = [
            ("VLESS", "vless"),
            ("Hysteria", "hysteria"),
            ("Trojan", "trojan"),
            ("Shadowsocks", "shadowsocks"),
            ("SOCKS5", "socks5"),
            ("Sudoku", "sudoku"),
            ("HTTPS", "http11"),
            ("HTTP2", "http2"),
            ("QUIC", "http3"),
        ]
        sections.append((String(localized: "Protocol"), [
            .selection(label: String(localized: "Protocol"), value: selectedProtocol.name, options: protocolOptions, key: .outboundProtocol),
        ]))

        // Server
        var serverRows: [RowType] = [
            .text(label: String(localized: "Address"), value: serverAddress, placeholder: String(localized: "Address"), key: .address),
            .text(label: String(localized: "Port"), value: serverPort, placeholder: "443", key: .port),
        ]
        if isVLESS {
            serverRows.append(.text(label: String(localized: "UUID", comment: "UUID for VLESS protocol"), value: uuid, placeholder: String(localized: "UUID", comment: "UUID for VLESS protocol"), key: .uuid))
            serverRows.append(.selection(label: String(localized: "Encryption", comment: "Encryption for VLESS protocol"), value: encryptionDisplayValue, options: [("None", "none")], key: .encryption))
        } else if isHysteria {
            serverRows.append(.text(label: String(localized: "Password"), value: hysteriaPassword, placeholder: String(localized: "Password"), key: .hysteriaPassword, secure: true))
            serverRows.append(.text(label: String(localized: "Upload Speed", comment: "Upload Speed for Hysteria protocol"), value: hysteriaUploadMbpsText, placeholder: String(localized: "Mbps"), key: .hysteriaUploadMbps))
        } else if isTrojan {
            serverRows.append(.text(label: String(localized: "Password"), value: trojanPassword, placeholder: String(localized: "Password"), key: .trojanPassword, secure: true))
        } else if isShadowsocks {
            serverRows.append(.text(label: String(localized: "Password"), value: ssPassword, placeholder: String(localized: "Password"), key: .ssPassword, secure: true))
            let methods: [(String, String)] = [
                (String(localized: "None"), "none"),
                ("AES-128-GCM", "aes-128-gcm"),
                ("AES-256-GCM", "aes-256-gcm"),
                ("ChaCha20-Poly1305", "chacha20-ietf-poly1305"),
                ("BLAKE3-AES-128-GCM", "2022-blake3-aes-128-gcm"),
                ("BLAKE3-AES-256-GCM", "2022-blake3-aes-256-gcm"),
                ("BLAKE3-ChaCha20", "2022-blake3-chacha20-poly1305"),
            ]
            serverRows.append(.selection(label: String(localized: "Method", comment: "Method for Shadowsocks protocol"), value: ssMethodDisplayValue, options: methods, key: .ssMethod))
        } else if isSOCKS5 {
            serverRows.append(.text(label: String(localized: "Username"), value: socks5Username, placeholder: String(localized: "Username"), key: .socks5Username))
            serverRows.append(.text(label: String(localized: "Password"), value: socks5Password, placeholder: String(localized: "Password"), key: .socks5Password, secure: true))
        } else if isSudoku {
            serverRows.append(.text(label: String(localized: "Key", comment: "Key for Sudoku protocol"), value: sudokuKey, placeholder: String(localized: "Key", comment: "Key for Sudoku protocol"), key: .sudokuKey, secure: true))
            serverRows.append(.selection(label: String(localized: "AEAD", comment: "AEAD for Sudoku protocol"), value: sudokuAEADMethod.displayName, options: SudokuAEADMethod.allCases.map { ($0.displayName, $0.rawValue) }, key: .sudokuAEADMethod))
            serverRows.append(.text(label: String(localized: "Padding Min", comment: "Padding Min for Sudoku protocol"), value: sudokuPaddingMinText, placeholder: "0-100", key: .sudokuPaddingMin))
            serverRows.append(.text(label: String(localized: "Padding Max", comment: "Padding Max for Sudoku protocol"), value: sudokuPaddingMaxText, placeholder: "0-100", key: .sudokuPaddingMax))
            serverRows.append(.selection(label: String(localized: "ASCII"), value: sudokuASCIIMode.displayName, options: SudokuASCIIMode.allCases.map { ($0.displayName, $0.rawValue) }, key: .sudokuASCIIMode))
            serverRows.append(.text(label: String(localized: "Custom Tables", comment: "Custom Tables for Sudoku protocol"), value: sudokuCustomTablesText, placeholder: "comma,separated", key: .sudokuCustomTables))
            serverRows.append(.toggle(label: String(localized: "Pure Downlink", comment: "Pure Downlink for Sudoku protocol"), isOn: sudokuEnablePureDownlink, key: .sudokuPureDownlink))
        } else if isNaive {
            serverRows.append(.text(label: String(localized: "Username"), value: naiveUsername, placeholder: String(localized: "Username"), key: .naiveUsername))
            serverRows.append(.text(label: String(localized: "Password"), value: naivePassword, placeholder: String(localized: "Password"), key: .naivePassword, secure: true))
        }
        sections.append((String(localized: "Server"), serverRows))
        
        if isVLESS {
            var transportRows: [RowType] = [
                .selection(label: String(localized: "Transport", comment: "Transport for VLESS protocol"), value: transportDisplayValue, options: [
                    ("TCP", "tcp"), ("WebSocket", "ws"), ("HTTPUpgrade", "httpupgrade"), ("gRPC", "grpc"), ("XHTTP", "xhttp"),
                ], key: .transport),
            ]
            if transport == "tcp" {
                transportRows.append(.selection(label: String(localized: "Flow", comment: "Flow for VLESS protocol TCP transport"), value: flowDisplayValue, options: [
                    (String(localized: "None"), ""),
                    ("Vision", "xtls-rprx-vision"),
                    ("Vision + UDP 443", "xtls-rprx-vision-udp443"),
                ], key: .flow))
                transportRows.append(.toggle(label: String(localized: "Mux", comment: "Mux for VLESS protocol TCP transport"), isOn: muxEnabled, key: .mux))
                if muxEnabled {
                    transportRows.append(.toggle(label: String(localized: "XUDP", comment: "XUDP for VLESS protocol TCP transport"), isOn: xudpEnabled, key: .xudp))
                }
            }
            if transport == "ws" {
                transportRows.append(.text(label: String(localized: "Host"), value: wsHost, placeholder: String(localized: "Host"), key: .wsHost))
                transportRows.append(.text(label: String(localized: "Path"), value: wsPath, placeholder: String(localized: "Path"), key: .wsPath))
            }
            if transport == "httpupgrade" {
                transportRows.append(.text(label: String(localized: "Host"), value: huHost, placeholder: String(localized: "Host"), key: .huHost))
                transportRows.append(.text(label: String(localized: "Path"), value: huPath, placeholder: String(localized: "Path"), key: .huPath))
            }
            if transport == "grpc" {
                transportRows.append(.text(label: String(localized: "Service Name", comment: "Service Name for VLESS protocol gRPC transport"), value: grpcServiceName, placeholder: String(localized: "Service Name", comment: "Service Name for VLESS protocol gRPC transport"), key: .grpcServiceName))
                transportRows.append(.text(label: String(localized: "Authority", comment: "Authority for VLESS protocol gRPC transport"), value: grpcAuthority, placeholder: String(localized: "Authority", comment: "Authority for VLESS protocol gRPC transport"), key: .grpcAuthority))
                transportRows.append(.selection(label: String(localized: "Mode"), value: grpcModeDisplayValue, options: [
                    ("Gun", "gun"),
                    ("Multi", "multi"),
                ], key: .grpcMode))
                transportRows.append(.text(label: String(localized: "User Agent"), value: grpcUserAgent, placeholder: String(localized: "User Agent"), key: .grpcUserAgent))
            }
            if transport == "xhttp" {
                transportRows.append(.text(label: String(localized: "Host"), value: xhttpHost, placeholder: String(localized: "Host"), key: .xhttpHost))
                transportRows.append(.text(label: String(localized: "Path"), value: xhttpPath, placeholder: String(localized: "Path"), key: .xhttpPath))
                transportRows.append(.selection(label: String(localized: "Mode"), value: xhttpModeDisplayValue, options: [
                    (String(localized: "Auto"), "auto"),
                    ("Packet Up", "packet-up"),
                    ("Stream Up", "stream-up"),
                    ("Stream One", "stream-one"),
                ], key: .xhttpMode))
            }
            sections.append((String(localized: "Transport"), transportRows))
        }
        
        if isVLESS || isTrojan {
            var tlsRows: [RowType] = []
            if isVLESS {
                tlsRows.append(.selection(label: String(localized: "Security", comment: "Security for VLESS protocol"), value: securityDisplayValue, options: [
                    (String("None"), "none"),
                    ("TLS", "tls"),
                    ("Reality", "reality"),
                ], key: .security))
            }
            if isTLS || isTrojan {
                tlsRows.append(.text(label: String(localized: "SNI"), value: tlsSNI, placeholder: String(localized: "SNI"), key: .tlsSNI))
                tlsRows.append(.text(label: String(localized: "ALPN"), value: tlsALPN, placeholder: String(localized: "h2,http/1.1"), key: .tlsALPN))
                tlsRows.append(.selection(label: String(localized: "Fingerprint"), value: fingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .fingerprint))
            }
            if isReality {
                tlsRows.append(.text(label: String(localized: "SNI"), value: sni, placeholder: String(localized: "SNI"), key: .realitySNI))
                tlsRows.append(.text(label: String(localized: "Public Key", comment: "Public Key for Reality security layer"), value: publicKey, placeholder: String(localized: "Public Key", comment: "Public Key for Reality security layer"), key: .publicKey))
                tlsRows.append(.text(label: String(localized: "Short ID", comment: "Short ID for Reality security layer"), value: shortId, placeholder: String(localized: "Short ID", comment: "Short ID for Reality security layer"), key: .shortId))
                tlsRows.append(.selection(label: String(localized: "Fingerprint"), value: fingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .fingerprint))
            }
            sections.append((String(localized: "TLS"), tlsRows))
        }
        
        if isSudoku {
            var httpMaskRows: [RowType] = [
                .toggle(label: String(localized: "Disable HTTP Mask", comment: "Disable HTTP Mask for Sudoku protocol"), isOn: sudokuHTTPMaskDisable, key: .sudokuHTTPMaskDisable),
            ]
            if !sudokuHTTPMaskDisable {
                httpMaskRows.append(.selection(label: String(localized: "Mode"), value: sudokuHTTPMaskMode.displayName, options: SudokuHTTPMaskMode.allCases.map { ($0.displayName, $0.rawValue) }, key: .sudokuHTTPMaskMode))
                httpMaskRows.append(.toggle(label: String(localized: "TLS"), isOn: sudokuHTTPMaskTLS, key: .sudokuHTTPMaskTLS))
                httpMaskRows.append(.text(label: String(localized: "Host"), value: sudokuHTTPMaskHost, placeholder: String(localized: "Host"), key: .sudokuHTTPMaskHost))
                httpMaskRows.append(.text(label: String(localized: "Path Root", comment: "Path Root for Sudoku protocol HTTP Mask feature"), value: sudokuHTTPMaskPathRoot, placeholder: String(localized: "Path Root", comment: "Path Root for Sudoku protocol HTTP Mask feature"), key: .sudokuHTTPMaskPathRoot))
                httpMaskRows.append(.selection(label: String(localized: "Multiplex", comment: "Multiplex for Sudoku protocol HTTP Mask feature"), value: sudokuHTTPMaskMultiplex.displayName, options: SudokuHTTPMaskMultiplex.allCases.map { ($0.displayName, $0.rawValue) }, key: .sudokuHTTPMaskMultiplex))
            }
            sections.append((String(localized: "HTTP Mask", comment: "HTTP Mask for Sudoku protocol"), httpMaskRows))
        }

        return sections
    }
    
    private var encryptionDisplayValue: String {
        switch encryption {
        case "none": String(localized: "None")
        default: encryption
        }
    }

    private var ssMethodDisplayValue: String {
        switch ssMethod {
        case "none": String(localized: "None")
        case "aes-128-gcm": "AES-128-GCM"
        case "aes-256-gcm": "AES-256-GCM"
        case "chacha20-ietf-poly1305": "ChaCha20-Poly1305"
        case "2022-blake3-aes-128-gcm": "BLAKE3-AES-128-GCM"
        case "2022-blake3-aes-256-gcm": "BLAKE3-AES-256-GCM"
        case "2022-blake3-chacha20-poly1305": "BLAKE3-ChaCha20"
        default: ssMethod
        }
    }

    private var transportDisplayValue: String {
        switch transport {
        case "tcp": "TCP"
        case "ws": "WebSocket"
        case "httpupgrade": "HTTPUpgrade"
        case "grpc": "gRPC"
        case "xhttp": "XHTTP"
        default: transport
        }
    }

    private var grpcModeDisplayValue: String {
        switch grpcMode {
        case "gun": "Gun"
        case "multi": "Multi"
        default: grpcMode
        }
    }

    private var flowDisplayValue: String {
        switch flow {
        case "xtls-rprx-vision": "Vision"
        case "xtls-rprx-vision-udp443": "Vision + UDP 443"
        default: String(localized: "None")
        }
    }

    private var xhttpModeDisplayValue: String {
        switch xhttpMode {
        case "auto": String(localized: "Auto")
        case "packet-up": "Packet Up"
        case "stream-up": "Stream Up"
        case "stream-one": "Stream One"
        default: xhttpMode
        }
    }
    private var securityDisplayValue: String {
        switch security {
        case "none": String(localized: "None")
        case "tls": "TLS"
        case "reality": "Reality"
        default: security
        }
    }

    private var isValid: Bool {
        guard !name.isEmpty, !serverAddress.isEmpty, UInt16(serverPort) != nil else { return false }
        if isHysteria {
            if hysteriaPassword.isEmpty { return false }
            guard let v = Int(hysteriaUploadMbpsText),
                  HysteriaUploadMbpsRange.contains(v) else { return false }
            return true
        }
        if isTrojan { return !trojanPassword.isEmpty }
        if isShadowsocks { return !ssPassword.isEmpty }
        if isSOCKS5 { return true }
        if isSudoku {
            guard !sudokuKey.isEmpty else { return false }
            guard let min = Int(sudokuPaddingMinText), let max = Int(sudokuPaddingMaxText) else { return false }
            return (0...100).contains(min) && min <= max && max <= 100
        }
        if isNaive { return !naiveUsername.isEmpty && !naivePassword.isEmpty }
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
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 80
        tableView.remembersLastFocusedIndexPath = true

        navigationItem.leftBarButtonItem = UIBarButtonItem(barButtonSystemItem: .cancel, target: self, action: #selector(cancelTapped))
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .save, target: self, action: #selector(saveTapped))

        if let configuration = existingConfiguration {
            populateFromExisting(configuration)
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
                if isHysteria || isTrojan || isShadowsocks || isSOCKS5 || isSudoku || isNaive {
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
        case .grpcServiceName: grpcServiceName = value
        case .grpcAuthority: grpcAuthority = value
        case .grpcMode: grpcMode = value
        case .grpcUserAgent: grpcUserAgent = value
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
        case .hysteriaPassword: hysteriaPassword = value
        case .hysteriaUploadMbps: hysteriaUploadMbpsText = value
        case .trojanPassword: trojanPassword = value
        case .ssPassword: ssPassword = value
        case .ssMethod: ssMethod = value
        case .socks5Username: socks5Username = value
        case .socks5Password: socks5Password = value
        case .sudokuKey: sudokuKey = value
        case .sudokuAEADMethod:
            if let method = SudokuAEADMethod(rawValue: value) { sudokuAEADMethod = method }
        case .sudokuPaddingMin: sudokuPaddingMinText = value
        case .sudokuPaddingMax: sudokuPaddingMaxText = value
        case .sudokuASCIIMode:
            if let mode = SudokuASCIIMode(rawValue: value) { sudokuASCIIMode = mode }
        case .sudokuCustomTables: sudokuCustomTablesText = value
        case .sudokuPureDownlink: sudokuEnablePureDownlink = value == "true"
        case .sudokuHTTPMaskDisable: sudokuHTTPMaskDisable = value == "true"
        case .sudokuHTTPMaskMode:
            if let mode = SudokuHTTPMaskMode(rawValue: value) { sudokuHTTPMaskMode = mode }
        case .sudokuHTTPMaskTLS: sudokuHTTPMaskTLS = value == "true"
        case .sudokuHTTPMaskHost: sudokuHTTPMaskHost = value
        case .sudokuHTTPMaskPathRoot: sudokuHTTPMaskPathRoot = value
        case .sudokuHTTPMaskMultiplex:
            if let mode = SudokuHTTPMaskMultiplex(rawValue: value) { sudokuHTTPMaskMultiplex = mode }
        case .naiveUsername: naiveUsername = value
        case .naivePassword: naivePassword = value
        }
    }

    // MARK: - Populate

    private func populateFromExisting(_ configuration: ProxyConfiguration) {
        selectedProtocol = configuration.outboundProtocol
        name = configuration.name
        serverAddress = configuration.serverAddress
        serverPort = String(configuration.serverPort)
        uuid = configuration.uuid.uuidString
        encryption = configuration.encryption
        transport = configuration.transport
        flow = configuration.flow ?? ""
        security = configuration.security
        muxEnabled = configuration.muxEnabled
        xudpEnabled = configuration.xudpEnabled

        if let ws = configuration.websocket {
            wsHost = ws.host
            wsPath = ws.path
        }
        if let hu = configuration.httpUpgrade {
            huHost = hu.host
            huPath = hu.path
        }
        if let grpc = configuration.grpc {
            grpcServiceName = grpc.serviceName
            grpcAuthority = grpc.authority
            grpcMode = grpc.multiMode ? "multi" : "gun"
            grpcUserAgent = grpc.userAgent
        }
        if let xhttp = configuration.xhttp {
            xhttpHost = xhttp.host
            xhttpPath = xhttp.path
            xhttpMode = xhttp.mode.rawValue
            xhttpExtra = Self.encodeExtra(from: xhttp)
        }
        if let tls = configuration.tls {
            tlsSNI = tls.serverName
            tlsALPN = tls.alpn?.joined(separator: ",") ?? ""
            fingerprint = tls.fingerprint
        }
        if let reality = configuration.reality {
            sni = reality.serverName
            publicKey = reality.publicKey.base64URLEncodedString()
            shortId = reality.shortId.hexEncodedString()
            fingerprint = reality.fingerprint
        }

        switch configuration.outbound {
        case .vless:
            break
        case .hysteria(let password, let uploadMbps, _):
            hysteriaPassword = password
            hysteriaUploadMbpsText = String(uploadMbps)
        case .trojan(let password, let tls):
            trojanPassword = password
            tlsSNI = tls.serverName
            tlsALPN = tls.alpn?.joined(separator: ",") ?? ""
            fingerprint = tls.fingerprint
        case .shadowsocks(let password, let method):
            ssPassword = password
            ssMethod = method
        case .socks5(let user, let pass):
            socks5Username = user ?? ""
            socks5Password = pass ?? ""
        case .sudoku(let sudoku):
            sudokuKey = sudoku.key
            sudokuAEADMethod = sudoku.aeadMethod
            sudokuPaddingMinText = String(sudoku.paddingMin)
            sudokuPaddingMaxText = String(sudoku.paddingMax)
            sudokuASCIIMode = sudoku.asciiMode
            sudokuCustomTablesText = sudoku.customTables.joined(separator: ",")
            sudokuEnablePureDownlink = sudoku.enablePureDownlink
            sudokuHTTPMaskDisable = sudoku.httpMask.disable
            sudokuHTTPMaskMode = sudoku.httpMask.mode
            sudokuHTTPMaskTLS = sudoku.httpMask.tls
            sudokuHTTPMaskHost = sudoku.httpMask.host
            sudokuHTTPMaskPathRoot = sudoku.httpMask.pathRoot
            sudokuHTTPMaskMultiplex = sudoku.httpMask.multiplex
        case .http11(let user, let pass), .http2(let user, let pass), .http3(let user, let pass):
            naiveUsername = user
            naivePassword = pass
        }
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

    private static func encodeExtra(from configuration: XHTTPConfiguration) -> String {
        var dict: [String: Any] = [:]

        if !configuration.headers.isEmpty { dict["headers"] = configuration.headers }
        if configuration.noGRPCHeader { dict["noGRPCHeader"] = true }
        if configuration.scMaxEachPostBytes != 1_000_000 { dict["scMaxEachPostBytes"] = configuration.scMaxEachPostBytes }
        if configuration.scMinPostsIntervalMs != 30 { dict["scMinPostsIntervalMs"] = configuration.scMinPostsIntervalMs }
        if configuration.xPaddingBytesFrom != 100 || configuration.xPaddingBytesTo != 1000 {
            dict["xPaddingBytes"] = ["from": configuration.xPaddingBytesFrom, "to": configuration.xPaddingBytesTo]
        }
        if configuration.xPaddingObfsMode { dict["xPaddingObfsMode"] = true }
        if configuration.xPaddingKey != "x_padding" { dict["xPaddingKey"] = configuration.xPaddingKey }
        if configuration.xPaddingHeader != "X-Padding" { dict["xPaddingHeader"] = configuration.xPaddingHeader }
        if configuration.xPaddingPlacement != .queryInHeader { dict["xPaddingPlacement"] = configuration.xPaddingPlacement.rawValue }
        if configuration.xPaddingMethod != .repeatX { dict["xPaddingMethod"] = configuration.xPaddingMethod.rawValue }
        if configuration.uplinkHTTPMethod != "POST" { dict["uplinkHTTPMethod"] = configuration.uplinkHTTPMethod }
        if configuration.sessionPlacement != .path { dict["sessionPlacement"] = configuration.sessionPlacement.rawValue }
        if !configuration.sessionKey.isEmpty { dict["sessionKey"] = configuration.sessionKey }
        if configuration.seqPlacement != .path { dict["seqPlacement"] = configuration.seqPlacement.rawValue }
        if !configuration.seqKey.isEmpty { dict["seqKey"] = configuration.seqKey }
        if configuration.uplinkDataPlacement != .body { dict["uplinkDataPlacement"] = configuration.uplinkDataPlacement.rawValue }
        let defaultDataKey: String
        let defaultChunkSize: Int
        switch configuration.uplinkDataPlacement {
        case .header: defaultDataKey = "X-Data"; defaultChunkSize = 4096
        case .cookie: defaultDataKey = "x_data"; defaultChunkSize = 3072
        default: defaultDataKey = ""; defaultChunkSize = 0
        }
        if configuration.uplinkDataKey != defaultDataKey { dict["uplinkDataKey"] = configuration.uplinkDataKey }
        if configuration.uplinkChunkSize != defaultChunkSize { dict["uplinkChunkSize"] = configuration.uplinkChunkSize }

        guard !dict.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys, .prettyPrinted]),
              let str = String(data: data, encoding: .utf8) else {
            return ""
        }
        return str
    }

    private func save() {
        guard let port = UInt16(serverPort) else { return }
        let parsedUUID: UUID
        if isHysteria || isTrojan || isShadowsocks || isSOCKS5 || isSudoku || isNaive {
            parsedUUID = existingConfiguration?.uuid ?? UUID()
        } else {
            guard let uuid = UUID(uuidString: uuid) else { return }
            parsedUUID = uuid
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
        
        var grpcConfig: GRPCConfiguration?
        if transport == "grpc" {
            grpcConfig = GRPCConfiguration(
                serviceName: grpcServiceName,
                authority: grpcAuthority,
                multiMode: grpcMode == "multi",
                userAgent: grpcUserAgent
            )
        }

        var xhttpConfig: XHTTPConfiguration?
        if transport == "xhttp" {
            let host = xhttpHost.isEmpty ? serverAddress : xhttpHost
            let mode = XHTTPMode(rawValue: xhttpMode) ?? .auto
            var params: [String: String] = ["host": host, "path": xhttpPath, "mode": mode.rawValue]
            if !xhttpExtra.isEmpty {
                params["extra"] = xhttpExtra
            }
            xhttpConfig = XHTTPConfiguration.parse(from: params, serverAddress: serverAddress)
        }

        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast()) : serverAddress

        let outbound: Outbound
        switch selectedProtocol {
        case .vless:
            let transportLayer: TransportLayer
            if let wsConfig { transportLayer = .ws(wsConfig) }
            else if let huConfig { transportLayer = .httpUpgrade(huConfig) }
            else if let grpcConfig { transportLayer = .grpc(grpcConfig) }
            else if let xhttpConfig { transportLayer = .xhttp(xhttpConfig) }
            else { transportLayer = .tcp }

            let securityLayer: SecurityLayer
            if let realityConfiguration { securityLayer = .reality(realityConfiguration) }
            else if let tlsConfiguration { securityLayer = .tls(tlsConfiguration) }
            else { securityLayer = .none }

            outbound = .vless(
                uuid: parsedUUID,
                encryption: encryption,
                flow: flow.isEmpty ? nil : flow,
                transport: transportLayer,
                security: securityLayer,
                muxEnabled: muxEnabled,
                xudpEnabled: xudpEnabled
            )
        case .hysteria:
            let mbps = clampHysteriaUploadMbps(Int(hysteriaUploadMbpsText) ?? HysteriaUploadMbpsDefault)
            outbound = .hysteria(
                password: hysteriaPassword,
                uploadMbps: mbps,
                sni: existingConfiguration?.hysteriaSNI ?? bareAddress
            )
        case .trojan:
            let sniValue = tlsSNI.isEmpty ? bareAddress : tlsSNI
            let alpn: [String]? = tlsALPN.isEmpty ? nil : tlsALPN.split(separator: ",").map { String($0) }
            outbound = .trojan(
                password: trojanPassword,
                tls: TLSConfiguration(serverName: sniValue, alpn: alpn, fingerprint: fingerprint)
            )
        case .shadowsocks:
            outbound = .shadowsocks(password: ssPassword, method: ssMethod)
        case .socks5:
            outbound = .socks5(
                username: socks5Username.isEmpty ? nil : socks5Username,
                password: socks5Password.isEmpty ? nil : socks5Password
            )
        case .sudoku:
            outbound = .sudoku(SudokuConfiguration(
                key: sudokuKey,
                aeadMethod: sudokuAEADMethod,
                paddingMin: Int(sudokuPaddingMinText) ?? 5,
                paddingMax: Int(sudokuPaddingMaxText) ?? 15,
                asciiMode: sudokuASCIIMode,
                customTables: sudokuCustomTablesText
                    .split(separator: ",")
                    .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty },
                enablePureDownlink: sudokuEnablePureDownlink,
                httpMask: SudokuHTTPMaskConfiguration(
                    disable: sudokuHTTPMaskDisable,
                    mode: sudokuHTTPMaskMode,
                    tls: sudokuHTTPMaskTLS,
                    host: sudokuHTTPMaskHost,
                    pathRoot: sudokuHTTPMaskPathRoot,
                    multiplex: sudokuHTTPMaskMultiplex
                )
            ))
        case .http11:
            outbound = .http11(username: naiveUsername, password: naivePassword)
        case .http2:
            outbound = .http2(username: naiveUsername, password: naivePassword)
        case .http3:
            outbound = .http3(username: naiveUsername, password: naivePassword)
        }

        let configuration = ProxyConfiguration(
            id: existingConfiguration?.id ?? UUID(),
            name: name,
            serverAddress: bareAddress,
            serverPort: port,
            subscriptionId: existingConfiguration?.subscriptionId,
            outbound: outbound
        )

        onSave(configuration)
        dismiss(animated: true)
    }
}
