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

    // WebSocket fields
    @State private var wsHost = ""
    @State private var wsPath = "/"

    // HTTPUpgrade fields
    @State private var huHost = ""
    @State private var huPath = "/"
    
    // gRPC fields
    @State private var grpcServiceName = ""
    @State private var grpcAuthority = ""
    @State private var grpcMode = "gun"
    @State private var grpcUserAgent = ""

    // XHTTP fields
    @State private var xhttpHost = ""
    @State private var xhttpPath = "/"
    @State private var xhttpMode = "auto"
    @State private var xhttpExtra = ""

    // TLS fields
    @State private var tlsSNI = ""
    @State private var tlsALPN = ""

    // Mux + XUDP
    @State private var muxEnabled = true
    @State private var xudpEnabled = true

    // Reality fields
    @State private var sni = ""
    @State private var publicKey = ""
    @State private var shortId = ""
    @State private var fingerprint: TLSFingerprint = .chrome133
    
    // Hysteria fields
    @State private var hysteriaPassword = ""
    @State private var hysteriaUploadMbpsText = String(HysteriaUploadMbpsDefault)

    // Trojan fields (TLS knobs reuse the VLESS tlsSNI/tlsALPN/fingerprint state).
    @State private var trojanPassword = ""

    // Shadowsocks fields
    @State private var ssPassword = ""
    @State private var ssMethod = "aes-128-gcm"
    
    // SOCKS5 fields
    @State private var socks5Username = ""
    @State private var socks5Password = ""

    // Sudoku fields
    @State private var sudokuKey = ""
    @State private var sudokuAEADMethod: SudokuAEADMethod = .chacha20Poly1305
    @State private var sudokuPaddingMinText = "5"
    @State private var sudokuPaddingMaxText = "15"
    @State private var sudokuASCIIMode: SudokuASCIIMode = .preferEntropy
    @State private var sudokuCustomTablesText = ""
    @State private var sudokuEnablePureDownlink = true
    @State private var sudokuHTTPMaskDisable = false
    @State private var sudokuHTTPMaskMode: SudokuHTTPMaskMode = .legacy
    @State private var sudokuHTTPMaskTLS = false
    @State private var sudokuHTTPMaskHost = ""
    @State private var sudokuHTTPMaskPathRoot = ""
    @State private var sudokuHTTPMaskMultiplex: SudokuHTTPMaskMultiplex = .off

    // Shared credential fields for HTTPS/HTTP2/QUIC (persisted per-protocol at save time)
    @State private var naiveUsername = ""
    @State private var naivePassword = ""

    private var isVLESS: Bool { selectedProtocol == .vless }
    private var isHysteria: Bool { selectedProtocol == .hysteria }
    private var isTrojan: Bool { selectedProtocol == .trojan }
    private var isShadowsocks: Bool { selectedProtocol == .shadowsocks }
    private var isSOCKS5: Bool { selectedProtocol == .socks5 }
    private var isSudoku: Bool { selectedProtocol == .sudoku }
    private var isNaive: Bool { selectedProtocol.isNaive }
    private var isReality: Bool { security == "reality" }
    private var isTLS: Bool { security == "tls" }

    private var isValid: Bool {
        guard !name.isEmpty, !serverAddress.isEmpty, UInt16(serverPort) != nil else { return false }
        if isHysteria {
            if hysteriaPassword.isEmpty { return false }
            guard let v = Int(hysteriaUploadMbpsText),
                  HysteriaUploadMbpsRange.contains(v) else { return false }
            return true
        }
        if isTrojan {
            return !trojanPassword.isEmpty
        }
        if isShadowsocks {
            return !ssPassword.isEmpty
        }
        if isSOCKS5 {
            return true // username/password optional for SOCKS5
        }
        if isSudoku {
            guard !sudokuKey.isEmpty else { return false }
            guard let min = Int(sudokuPaddingMinText), let max = Int(sudokuPaddingMaxText) else { return false }
            return (0...100).contains(min) && min <= max && max <= 100
        }
        if isNaive {
            return !naiveUsername.isEmpty && !naivePassword.isEmpty
        }
        return UUID(xrayString: uuid) != nil && (!isReality || (!sni.isEmpty && !publicKey.isEmpty))
    }

    init(configuration: ProxyConfiguration? = nil, onSave: @escaping (ProxyConfiguration) -> Void) {
        self.configuration = configuration
        self.onSave = onSave
    }

    var body: some View {
        NavigationView {
            Form {
                Section {
                    LabeledContent {
                        TextField("Name", text: $name)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Name", systemName: "tag.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                }
                
                Section {
                    Picker(selection: $selectedProtocol) {
                        Text("VLESS").tag(OutboundProtocol.vless)
                        Text("Hysteria").tag(OutboundProtocol.hysteria)
                        Text("Trojan").tag(OutboundProtocol.trojan)
                        Text("Shadowsocks").tag(OutboundProtocol.shadowsocks)
                        Text("SOCKS5").tag(OutboundProtocol.socks5)
                        Text("Sudoku").tag(OutboundProtocol.sudoku)
                        Text("HTTPS").tag(OutboundProtocol.http11)
                        Text("HTTP2").tag(OutboundProtocol.http2)
                        Text("QUIC").tag(OutboundProtocol.http3)
                    } label: {
                        TextWithColorfulIcon(titleKey: "Protocol", systemName: "arrow.down.left.arrow.up.right.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                    .onChange(of: selectedProtocol) {
                        if isTrojan || isShadowsocks || isSOCKS5 || isSudoku || isNaive {
                            flow = ""
                            security = security == "reality" ? "none" : security
                        }
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
                    if isHysteria {
                       LabeledContent {
                           SecureField("Password", text: $hysteriaPassword)
                               .autocorrectionDisabled()
                               .textInputAutocapitalization(.never)
                               .multilineTextAlignment(.trailing)
                       } label: {
                           TextWithColorfulIcon(titleKey: "Password", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                       }
                       LabeledContent {
                           TextField("Mbps", text: $hysteriaUploadMbpsText)
                               .keyboardType(.numberPad)
                               .multilineTextAlignment(.trailing)
                       } label: {
                           TextWithColorfulIcon(titleKey: "Upload Speed", systemName: "arrow.up.circle.fill", foregroundColor: .white, backgroundColor: .blue)
                       }
                   } else if isTrojan {
                        LabeledContent {
                            SecureField("Password", text: $trojanPassword)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Password", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                    } else if isShadowsocks {
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
                    } else if isSOCKS5 {
                        LabeledContent {
                            TextField("Username", text: $socks5Username)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Username", systemName: "person.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                        LabeledContent {
                            SecureField("Password", text: $socks5Password)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Password", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                    } else if isSudoku {
                        LabeledContent {
                            SecureField("Key", text: $sudokuKey)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Key", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                    } else if isNaive {
                        LabeledContent {
                            TextField("Username", text: $naiveUsername)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Username", systemName: "person.fill", foregroundColor: .white, backgroundColor: .green)
                        }
                        LabeledContent {
                            SecureField("Password", text: $naivePassword)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Password", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
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

                if isSudoku {
                    Section("Sudoku") {
                        Picker(selection: $sudokuAEADMethod) {
                            ForEach(SudokuAEADMethod.allCases, id: \.self) { method in
                                Text(method.displayName).tag(method)
                            }
                        } label: {
                            TextWithColorfulIcon(titleKey: "AEAD", systemName: "lock.fill", foregroundColor: .white, backgroundColor: .red)
                        }
                        LabeledContent {
                            TextField("0-100", text: $sudokuPaddingMinText)
                                .keyboardType(.numberPad)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Padding Min", systemName: "arrow.down.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                        }
                        LabeledContent {
                            TextField("0-100", text: $sudokuPaddingMaxText)
                                .keyboardType(.numberPad)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Padding Max", systemName: "arrow.up.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                        }
                        Picker(selection: $sudokuASCIIMode) {
                            ForEach(SudokuASCIIMode.allCases, id: \.self) { mode in
                                Text(mode.displayName).tag(mode)
                            }
                        } label: {
                            TextWithColorfulIcon(titleKey: "ASCII", systemName: "textformat.alt", foregroundColor: .white, backgroundColor: .blue)
                        }
                        LabeledContent {
                            TextField("comma,separated,tables", text: $sudokuCustomTablesText)
                                .autocorrectionDisabled()
                                .textInputAutocapitalization(.never)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            TextWithColorfulIcon(titleKey: "Custom Tables", systemName: "square.stack.3d.up.fill", foregroundColor: .white, backgroundColor: .indigo)
                        }
                        Toggle(isOn: $sudokuEnablePureDownlink) {
                            TextWithColorfulIcon(titleKey: "Pure Downlink", systemName: "arrow.down.to.line.compact", foregroundColor: .white, backgroundColor: .teal)
                        }
                    }

                    Section("HTTPMask") {
                        Toggle(isOn: $sudokuHTTPMaskDisable) {
                            TextWithColorfulIcon(titleKey: "Disable", systemName: "xmark.circle.fill", foregroundColor: .white, backgroundColor: .gray)
                        }
                        if !sudokuHTTPMaskDisable {
                            Picker(selection: $sudokuHTTPMaskMode) {
                                ForEach(SudokuHTTPMaskMode.allCases, id: \.self) { mode in
                                    Text(mode.displayName).tag(mode)
                                }
                            } label: {
                                TextWithColorfulIcon(titleKey: "Mode", systemName: "network.badge.shield.half.filled", foregroundColor: .white, backgroundColor: .purple)
                            }
                            Toggle(isOn: $sudokuHTTPMaskTLS) {
                                TextWithColorfulIcon(titleKey: "TLS", systemName: "lock.shield.fill", foregroundColor: .white, backgroundColor: .blue)
                            }
                            LabeledContent {
                                TextField("Host", text: $sudokuHTTPMaskHost)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Host", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                            }
                            LabeledContent {
                                TextField("path-root", text: $sudokuHTTPMaskPathRoot)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Path Root", systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                            }
                            Picker(selection: $sudokuHTTPMaskMultiplex) {
                                ForEach(SudokuHTTPMaskMultiplex.allCases, id: \.self) { mode in
                                    Text(mode.displayName).tag(mode)
                                }
                            } label: {
                                TextWithColorfulIcon(titleKey: "Multiplex", systemName: "rectangle.split.3x1.fill", foregroundColor: .white, backgroundColor: .teal)
                            }
                        }
                    }
                }

                if isVLESS {
                    Section("Transport") {
                        Picker(selection: $transport) {
                            Text("TCP").tag("tcp")
                            Text("WebSocket").tag("ws")
                            Text("HTTPUpgrade").tag("httpupgrade")
                            Text("gRPC").tag("grpc")
                            Text("XHTTP").tag("xhttp")
                        } label: {
                            TextWithColorfulIcon(titleKey: "Transport", systemName: "arrow.triangle.swap", foregroundColor: .white, backgroundColor: .purple)
                        }
                        .onChange(of: transport) {
                            if flow != "" && transport != "tcp" {
                                flow = ""
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
                        if transport == "ws" {
                            LabeledContent {
                                TextField("Host", text: $wsHost)
                                    .keyboardType(.URL)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Host", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                            }
                            LabeledContent {
                                TextField("/", text: $wsPath)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Path", systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                            }
                        }
                        if transport == "httpupgrade" {
                            LabeledContent {
                                TextField("Host", text: $huHost)
                                    .keyboardType(.URL)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Host", systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                            }
                            LabeledContent {
                                TextField("/", text: $huPath)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Path", systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                            }
                        }
                        if transport == "grpc" {
                            LabeledContent {
                                TextField("Service Name", text: $grpcServiceName)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Service Name", systemName: "realtimetext", foregroundColor: .white, backgroundColor: .mint)
                            }
                            LabeledContent {
                                TextField("Authority", text: $grpcAuthority)
                                    .keyboardType(.URL)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "Authority", systemName: "person.fill", foregroundColor: .white, backgroundColor: .green)
                            }
                            Picker(selection: $grpcMode) {
                                Text("Gun").tag("gun")
                                Text("Multi").tag("multi")
                            } label: {
                                TextWithColorfulIcon(titleKey: "Mode", systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .gray)
                            }
                            LabeledContent {
                                TextField("User Agent", text: $grpcUserAgent)
                                    .autocorrectionDisabled()
                                    .textInputAutocapitalization(.never)
                                    .multilineTextAlignment(.trailing)
                            } label: {
                                TextWithColorfulIcon(titleKey: "User Agent", systemName: "laptopcomputer", foregroundColor: .white, backgroundColor: .orange)
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
                                TextWithColorfulIcon(titleKey: "Mode", systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .gray)
                            }
                        }
                    }
                }

                if isVLESS || isTrojan {
                    Section("TLS") {
                        if isVLESS {
                            Picker(selection: $security) {
                                Text("None").tag("none")
                                Text("TLS").tag("tls")
                                Text("Reality").tag("reality")
                            } label: {
                                TextWithColorfulIcon(titleKey: "Security", systemName: "shield.lefthalf.filled", foregroundColor: .white, backgroundColor: .blue)
                            }
                        }
                        if isTLS || isTrojan {
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
                    } else {
                        Button("Cancel") { dismiss() }
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if #available(iOS 26.0, *) {
                        Button {
                            save()
                        } label: {
                            Label("Save", systemImage: "checkmark")
                        }
                        .disabled(!isValid)
                    } else {
                        Button("Save") { save() }
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

        if let ws = configuration.websocket {
            wsHost = ws.host
            wsPath = ws.path
        }

        if let hu = configuration.httpUpgrade {
            huHost = hu.host
            huPath = hu.path
        }

        if let xhttp = configuration.xhttp {
            xhttpHost = xhttp.host
            xhttpPath = xhttp.path
            xhttpMode = xhttp.mode.rawValue
            xhttpExtra = Self.encodeExtra(from: xhttp)
        }

        if let grpc = configuration.grpc {
            grpcServiceName = grpc.serviceName
            grpcAuthority = grpc.authority
            grpcMode = grpc.multiMode ? "multi" : "gun"
            grpcUserAgent = grpc.userAgent
        }

        muxEnabled = configuration.muxEnabled
        xudpEnabled = configuration.xudpEnabled

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

    /// Encodes non-default extra fields from an XHTTPConfiguration back to a JSON string.
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
        // Compare against placement-dependent defaults (Xray-core Build())
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
        if isHysteria || isTrojan || isShadowsocks || isSOCKS5 || isNaive {
            parsedUUID = self.configuration?.uuid ?? UUID()
        } else {
            guard let u = UUID(xrayString: uuid) else { return }
            parsedUUID = u
        }
        
        var tlsConfiguration: TLSConfiguration?
        if isTLS {
            let sni = tlsSNI.isEmpty ? serverAddress : tlsSNI
            let alpn: [String]? = tlsALPN.isEmpty ? nil : tlsALPN.split(separator: ",").map { String($0) }
            tlsConfiguration = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
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

        var websocketConfiguration: WebSocketConfiguration?
        if transport == "ws" {
            let host = wsHost.isEmpty ? serverAddress : wsHost
            let path = wsPath.isEmpty ? "/" : wsPath
            websocketConfiguration = WebSocketConfiguration(host: host, path: path)
        }

        var httpUpgradeConfiguration: HTTPUpgradeConfiguration?
        if transport == "httpupgrade" {
            httpUpgradeConfiguration = HTTPUpgradeConfiguration(host: huHost.isEmpty ? serverAddress : huHost, path: huPath.isEmpty ? "/" : huPath)
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

        var grpcConfiguration: GRPCConfiguration?
        if transport == "grpc" {
            grpcConfiguration = GRPCConfiguration(
                serviceName: grpcServiceName,
                authority: grpcAuthority,
                multiMode: grpcMode == "multi",
                userAgent: grpcUserAgent
            )
        }

        // Strip brackets from IPv6 addresses (e.g. "[::1]" → "::1")
        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast())
            : serverAddress

        let outbound: Outbound
        switch selectedProtocol {
        case .vless:
            let transportLayer: TransportLayer
            if let websocketConfiguration { transportLayer = .ws(websocketConfiguration) }
            else if let httpUpgradeConfiguration { transportLayer = .httpUpgrade(httpUpgradeConfiguration) }
            else if let xhttpConfiguration { transportLayer = .xhttp(xhttpConfiguration) }
            else if let grpcConfiguration { transportLayer = .grpc(grpcConfiguration) }
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
                sni: self.configuration?.hysteriaSNI ?? bareAddress
            )
        case .trojan:
            let sni = tlsSNI.isEmpty ? bareAddress : tlsSNI
            let alpn: [String]? = tlsALPN.isEmpty ? nil : tlsALPN.split(separator: ",").map { String($0) }
            outbound = .trojan(
                password: trojanPassword,
                tls: TLSConfiguration(serverName: sni, alpn: alpn, fingerprint: fingerprint)
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
            id: self.configuration?.id ?? UUID(),
            name: name,
            serverAddress: bareAddress,
            serverPort: port,
            subscriptionId: self.configuration?.subscriptionId,
            outbound: outbound
        )

        onSave(configuration)
        dismiss()
    }
}
