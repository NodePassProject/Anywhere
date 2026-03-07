//
//  ProxyEditorView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct ProxyEditorView: View {
    let configuration: ProxyConfiguration?
    let onSave: (ProxyConfiguration) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var selectedProtocol: OutboundProtocol = .vless
    @State private var name = ""
    @State private var serverAddress = ""
    @State private var serverPort = ""
    @State private var uuid = ""
    @State private var encryption = "none"
    @State private var transport = "tcp"
    @State private var flow = ""
    @State private var security = "none"

    // XHTTP fields
    @State private var xhttpHost = ""
    @State private var xhttpPath = "/"
    @State private var xhttpMode = "auto"
    @State private var xhttpExtra = ""

    // TLS fields
    @State private var tlsSNI = ""
    @State private var tlsALPN = ""
    @State private var tlsAllowInsecure = false

    // Mux + XUDP
    @State private var muxEnabled = true
    @State private var xudpEnabled = true

    // Reality fields
    @State private var sni = ""
    @State private var publicKey = ""
    @State private var shortId = ""
    @State private var fingerprint: TLSFingerprint = .chrome120

    // Shadowsocks fields
    @State private var ssPassword = ""
    @State private var ssMethod = "aes-128-gcm"

    private var isShadowsocks: Bool { selectedProtocol == .shadowsocks }
    private var isReality: Bool { security == "reality" }
    private var isTLS: Bool { security == "tls" }

    private var isValid: Bool {
        !name.isEmpty &&
        !serverAddress.isEmpty &&
        UInt16(serverPort) != nil &&
        (isShadowsocks ? !ssPassword.isEmpty : UUID(uuidString: uuid) != nil) &&
        (!isReality || (!sni.isEmpty && !publicKey.isEmpty))
    }

    init(configuration: ProxyConfiguration? = nil, onSave: @escaping (ProxyConfiguration) -> Void) {
        self.configuration = configuration
        self.onSave = onSave
    }

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Picker(selection: $selectedProtocol) {
                        Text("VLESS").tag(OutboundProtocol.vless)
                        Text("Shadowsocks").tag(OutboundProtocol.shadowsocks)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Protocol", systemName: "arrow.down.left.arrow.up.right.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                    .onChange(of: selectedProtocol) {
                        if isShadowsocks {
                            flow = ""
                            security = security == "reality" ? "none" : security
                        }
                    }
                }
                
                Section("Name") {
                    LabeledContent {
                        TextField("Name", text: $name)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Name", systemName: "tag.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                }

                Section("Server") {
                    LabeledContent {
                        TextField("Address", text: $serverAddress)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Address", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Port", text: $serverPort)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Port", systemName: "123.rectangle", foregroundColor: .white, backgroundColor: .cyan)
                    }
                    if isShadowsocks {
                        LabeledContent {
                            SecureField("Password", text: $ssPassword)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Password", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                        Picker(selection: $ssMethod) {
                            Text("None").tag("none")
                            Text("AES-128-GCM").tag("aes-128-gcm")
                            Text("AES-256-GCM").tag("aes-256-gcm")
                            Text("ChaCha20-Poly1305").tag("chacha20-ietf-poly1305")
                            Text("BLAKE3-AES-128-GCM").tag("2022-blake3-aes-128-gcm")
                            Text("BLAKE3-AES-256-GCM").tag("2022-blake3-aes-256-gcm")
                            Text("BLAKE3-ChaCha20-Poly1305").tag("2022-blake3-chacha20-poly1305")
                        } label: {
                            TextWithColorfulIcon(titleKey: "Method", systemName: "lock.fill", foregroundColor: .white, backgroundColor: .red)
                        }
                    } else {
                        LabeledContent {
                            TextField("UUID", text: $uuid)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "UUID", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                        Picker(selection: $encryption) {
                            Text("None").tag("none")
                        } label: {
                            TextWithColorfulIcon(titleKey: "Encryption", systemName: "lock.fill", foregroundColor: .white, backgroundColor: .red)
                        }
                    }
                }
                
                Section("Transport") {
                    Picker(selection: $transport) {
                        Text("TCP").tag("tcp")
                        Text("WebSocket").tag("ws")
                        Text("HTTPUpgrade").tag("httpupgrade")
                        Text("XHTTP").tag("xhttp")
                    } label: {
                        TextWithColorfulIcon(titleKey: "Transport", systemName: "arrow.triangle.swap", foregroundColor: .white, backgroundColor: .purple)
                    }
                    .onChange(of: transport) {
                        if flow != "" && transport != "tcp" {
                            flow = ""
                        }
                    }
                    if !isShadowsocks && transport == "tcp" {
                        Picker(selection: $flow) {
                            Text("None").tag("")
                            Text("Vision").tag("xtls-rprx-vision")
                            Text("Vision with UDP 443").tag("xtls-rprx-vision-udp443")
                        } label: {
                            TextWithColorfulIcon(titleKey: "Flow", systemName: "arrow.left.arrow.right", foregroundColor: .white, backgroundColor: .indigo)
                        }
                        Toggle(isOn: $muxEnabled) {
                            TextWithColorfulIcon(titleKey: "Mux", systemName: "rectangle.split.3x1.fill", foregroundColor: .white, backgroundColor: .teal)
                        }
                            .onChange(of: muxEnabled) {
                                if muxEnabled == false {
                                    xudpEnabled = false
                                }
                            }
                        if muxEnabled {
                            Toggle(isOn: $xudpEnabled) {
                                TextWithColorfulIcon(titleKey: "XUDP", systemName: "arrow.up.arrow.down.circle.fill", foregroundColor: .white, backgroundColor: .cyan)
                            }
                        }
                    }
                    if transport == "xhttp" {
                        LabeledContent {
                            TextField("Host", text: $xhttpHost)
                                .keyboardType(.URL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Host", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                        }
                        LabeledContent {
                            TextField("/", text: $xhttpPath)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Path", systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                        }
                        Picker(selection: $xhttpMode) {
                            Text("Auto").tag("auto")
                            Text("Packet Up").tag("packet-up")
                            Text("Stream Up").tag("stream-up")
                            Text("Stream One").tag("stream-one")
                        } label: {
                            TextWithColorfulIcon(titleKey: "Mode", systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .purple)
                        }
                        LabeledContent {
                            TextEditor(text: $xhttpExtra)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .font(.system(.caption, design: .monospaced))
                                .lineLimit(1...5)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Extra", systemName: "ellipsis.rectangle", foregroundColor: .white, backgroundColor: .gray)
                        }
                    }
                }
                
                Section("TLS") {
                    Picker(selection: $security) {
                        Text("None").tag("none")
                        Text("TLS").tag("tls")
                        if !isShadowsocks {
                            Text("Reality").tag("reality")
                        }
                    } label: {
                        TextWithColorfulIcon(titleKey: "Security", systemName: "shield.lefthalf.filled", foregroundColor: .white, backgroundColor: .blue)
                    }
                    if isTLS {
                        LabeledContent {
                            TextField("SNI", text: $tlsSNI)
                                .keyboardType(.URL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "SNI", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                        }
                        LabeledContent {
                            TextField("h2,http/1.1", text: $tlsALPN)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "ALPN", systemName: "list.bullet", foregroundColor: .white, backgroundColor: .blue)
                        }
                        Toggle(isOn: $tlsAllowInsecure) {
                            TextWithColorfulIcon(titleKey: "Allow Insecure", systemName: "exclamationmark.shield.fill", foregroundColor: .white, backgroundColor: .red)
                        }
                        Picker(selection: $fingerprint) {
                            ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                                Text(fp.displayName).tag(fp)
                            }
                        } label: {
                            TextWithColorfulIcon(titleKey: "Fingerprint", systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                        }
                    }
                    if isReality {
                        LabeledContent {
                            TextField("SNI", text: $sni)
                                .keyboardType(.URL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "SNI", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                        }
                        LabeledContent {
                            TextField("Public Key", text: $publicKey)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Public Key", systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                        LabeledContent {
                            TextField("Short ID", text: $shortId)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Short ID", systemName: "person.crop.square.filled.and.at.rectangle.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                        Picker(selection: $fingerprint) {
                            ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                                Text(fp.displayName).tag(fp)
                            }
                        } label: {
                            TextWithColorfulIcon(titleKey: "Fingerprint", systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                        }
                    }
                }
            }
            .navigationTitle(configuration != nil ? "Edit Configuration" : "Add Configuration")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    if #available(iOS 26.0, *) {
                        Button(role: .cancel) {
                            dismiss()
                        } label: {
                            Label("Cancel", systemImage: "xmark")
                        }
                    }
                    else {
                        Button("Cancel") {
                            dismiss()
                        }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if #available(iOS 26.0, *) {
                        Button(role: .confirm) {
                            save()
                        } label: {
                            Label("Save", systemImage: "checkmark")
                        }
                        .disabled(!isValid)
                    }
                    else {
                        Button("Save") {
                            save()
                        }
                        .disabled(!isValid)
                    }
                }
            }
        }
        .onAppear { populateFromExisting() }
    }

    private func populateFromExisting() {
        guard let configuration else { return }
        selectedProtocol = configuration.outboundProtocol
        name = configuration.name
        serverAddress = configuration.serverAddress
        serverPort = String(configuration.serverPort)
        uuid = configuration.uuid.uuidString
        encryption = configuration.encryption
        transport = configuration.transport
        flow = configuration.flow ?? ""
        security = configuration.security

        if let xhttp = configuration.xhttp {
            xhttpHost = xhttp.host
            xhttpPath = xhttp.path
            xhttpMode = xhttp.mode.rawValue
            xhttpExtra = Self.encodeExtra(from: xhttp)
        }

        muxEnabled = configuration.muxEnabled
        xudpEnabled = configuration.xudpEnabled

        if let tls = configuration.tls {
            tlsSNI = tls.serverName
            tlsALPN = tls.alpn?.joined(separator: ",") ?? ""
            tlsAllowInsecure = tls.allowInsecure
            fingerprint = tls.fingerprint
        }

        if let reality = configuration.reality {
            sni = reality.serverName
            publicKey = reality.publicKey.base64URLEncodedString()
            shortId = reality.shortId.hexEncodedString()
            fingerprint = reality.fingerprint
        }

        ssPassword = configuration.ssPassword ?? ""
        ssMethod = configuration.ssMethod ?? "aes-128-gcm"
    }

    /// Encodes non-default extra fields from an XHTTPConfiguration back to a JSON string.
    private static func encodeExtra(from config: XHTTPConfiguration) -> String {
        var dict: [String: Any] = [:]

        if !config.headers.isEmpty { dict["headers"] = config.headers }
        if config.noGRPCHeader { dict["noGRPCHeader"] = true }
        if config.scMaxEachPostBytes != 1_000_000 { dict["scMaxEachPostBytes"] = config.scMaxEachPostBytes }
        if config.scMinPostsIntervalMs != 30 { dict["scMinPostsIntervalMs"] = config.scMinPostsIntervalMs }
        if config.xPaddingBytesFrom != 100 || config.xPaddingBytesTo != 1000 {
            dict["xPaddingBytes"] = ["from": config.xPaddingBytesFrom, "to": config.xPaddingBytesTo]
        }
        if config.xPaddingObfsMode { dict["xPaddingObfsMode"] = true }
        if config.xPaddingKey != "x_padding" { dict["xPaddingKey"] = config.xPaddingKey }
        if config.xPaddingHeader != "X-Padding" { dict["xPaddingHeader"] = config.xPaddingHeader }
        if config.xPaddingPlacement != .queryInHeader { dict["xPaddingPlacement"] = config.xPaddingPlacement.rawValue }
        if config.xPaddingMethod != .repeatX { dict["xPaddingMethod"] = config.xPaddingMethod.rawValue }
        if config.uplinkHTTPMethod != "POST" { dict["uplinkHTTPMethod"] = config.uplinkHTTPMethod }
        if config.sessionPlacement != .path { dict["sessionPlacement"] = config.sessionPlacement.rawValue }
        if !config.sessionKey.isEmpty { dict["sessionKey"] = config.sessionKey }
        if config.seqPlacement != .path { dict["seqPlacement"] = config.seqPlacement.rawValue }
        if !config.seqKey.isEmpty { dict["seqKey"] = config.seqKey }
        if config.uplinkDataPlacement != .body { dict["uplinkDataPlacement"] = config.uplinkDataPlacement.rawValue }
        // Compare against placement-dependent defaults (Xray-core Build())
        let defaultDataKey: String
        let defaultChunkSize: Int
        switch config.uplinkDataPlacement {
        case .header: defaultDataKey = "X-Data"; defaultChunkSize = 4096
        case .cookie: defaultDataKey = "x_data"; defaultChunkSize = 3072
        default: defaultDataKey = ""; defaultChunkSize = 0
        }
        if config.uplinkDataKey != defaultDataKey { dict["uplinkDataKey"] = config.uplinkDataKey }
        if config.uplinkChunkSize != defaultChunkSize { dict["uplinkChunkSize"] = config.uplinkChunkSize }

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
        if isShadowsocks {
            parsedUUID = self.configuration?.uuid ?? UUID()
        } else {
            guard let u = UUID(uuidString: uuid) else { return }
            parsedUUID = u
        }

        var tlsConfiguration: TLSConfiguration?
        if isTLS {
            let sni = tlsSNI.isEmpty ? serverAddress : tlsSNI
            let alpn: [String]? = tlsALPN.isEmpty ? nil : tlsALPN.split(separator: ",").map { String($0) }
            tlsConfiguration = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
                allowInsecure: tlsAllowInsecure,
                fingerprint: fingerprint
            )
        }
        
        var realityConfiguration: RealityConfiguration?
        if isReality {
            guard let pk = Data(base64URLEncoded: publicKey) else { return }
            let sid = Data(hexString: shortId) ?? Data()
            realityConfiguration = RealityConfiguration(
                serverName: sni,
                publicKey: pk,
                shortId: sid,
                fingerprint: fingerprint
            )
        }

        var xhttpConfiguration: XHTTPConfiguration?
        if transport == "xhttp" {
            let host = xhttpHost.isEmpty ? serverAddress : xhttpHost
            let mode = XHTTPMode(rawValue: xhttpMode) ?? .auto
            // Parse extra JSON for advanced settings, passing through to XHTTPConfiguration.parse
            var params: [String: String] = [
                "host": host,
                "path": xhttpPath,
                "mode": mode.rawValue
            ]
            if !xhttpExtra.isEmpty {
                // Store raw JSON as the extra param (parse expects it URL-decoded)
                params["extra"] = xhttpExtra
            }
            xhttpConfiguration = XHTTPConfiguration.parse(from: params, serverAddress: serverAddress)
        }

        // Strip brackets from IPv6 addresses (e.g. "[::1]" → "::1")
        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast())
            : serverAddress

        let configuration = ProxyConfiguration(
            id: self.configuration?.id ?? UUID(),
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
            xhttp: xhttpConfiguration,
            muxEnabled: muxEnabled,
            xudpEnabled: xudpEnabled,
            outboundProtocol: selectedProtocol,
            ssPassword: isShadowsocks ? ssPassword : nil,
            ssMethod: isShadowsocks ? ssMethod : nil
        )

        onSave(configuration)
        dismiss()
    }
}
