//
//  ProxyEditorView.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import SwiftUI

struct ProxyEditorView: View {
    let configuration: VLESSConfiguration?
    let onSave: (VLESSConfiguration) -> Void

    @Environment(\.dismiss) private var dismiss

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

    private var isReality: Bool { security == "reality" }
    private var isTLS: Bool { security == "tls" }

    private var isValid: Bool {
        !name.isEmpty &&
        !serverAddress.isEmpty &&
        UInt16(serverPort) != nil &&
        UUID(uuidString: uuid) != nil &&
        (!isReality || (!sni.isEmpty && !publicKey.isEmpty))
    }

    init(configuration: VLESSConfiguration? = nil, onSave: @escaping (VLESSConfiguration) -> Void) {
        self.configuration = configuration
        self.onSave = onSave
    }

    var body: some View {
        NavigationView {
            Form {
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
                        TextWithColorfulIcon(titleKey: "Address", systemName: "server.rack", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Port", text: $serverPort)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Port", systemName: "123.rectangle", foregroundColor: .white, backgroundColor: .cyan)
                    }
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
                    if transport == "xhttp" {
                        LabeledContent {
                            TextField("Host", text: $xhttpHost)
                                .keyboardType(.URL)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Host", systemName: "globe", foregroundColor: .white, backgroundColor: .purple)
                        }
                        LabeledContent {
                            TextField("/", text: $xhttpPath)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Path", systemName: "point.topleft.down.to.point.bottomright.curvepath.fill", foregroundColor: .white, backgroundColor: .purple)
                        }
                        Picker(selection: $xhttpMode) {
                            Text("Auto").tag("auto")
                            Text("Packet Up").tag("packet-up")
                            Text("Stream One").tag("stream-one")
                        } label: {
                            TextWithColorfulIcon(titleKey: "Mode", systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .purple)
                        }
                    }
                    if transport == "tcp" {
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
                }
                
                Section("TLS") {
                    Picker(selection: $security) {
                        Text("None").tag("none")
                        Text("TLS").tag("tls")
                        Text("Reality").tag("reality")
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
    }

    private func save() {
        guard let port = UInt16(serverPort),
              let parsedUUID = UUID(uuidString: uuid) else { return }

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
            xhttpConfiguration = XHTTPConfiguration(host: host, path: xhttpPath, mode: mode)
        }

        // Strip brackets from IPv6 addresses (e.g. "[::1]" → "::1")
        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast())
            : serverAddress

        let configuration = VLESSConfiguration(
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
            xudpEnabled: xudpEnabled
        )

        onSave(configuration)
        dismiss()
    }
}
