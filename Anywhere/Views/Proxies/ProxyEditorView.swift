//
//  ProxyEditorView.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
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
    
    // VLESS fields
    @State private var vlessUUID = ""
    @State private var vlessEncryption = "none"
    @State private var vlessFlow = ""
    @State private var vlessTransport = "tcp"
    @State private var vlessMuxEnabled = true
    @State private var vlessXUDPEnabled = true

    @State private var vlessWebSocketHost = ""
    @State private var vlessWebSocketPath = "/"
    
    @State private var vlessHTTPUpgradeHost = ""
    @State private var vlessHTTPUpgradePath = "/"
    
    @State private var vlessGRPCServiceName = ""
    @State private var vlessGRPCAuthority = ""
    @State private var vlessGRPCMode = "gun"
    @State private var vlessGRPCUserAgent = ""
    
    @State private var vlessXHTTPHost = ""
    @State private var vlessXHTTPPath = "/"
    @State private var vlessXHTTPMode = "auto"
    @State private var vlessXHTTPExtra = ""
    
    @State private var vlessSecurity = "none"
    @State private var vlessTLSSNI = ""
    @State private var vlessTLSALPN = ""
    @State private var vlessRealitySNI = ""
    @State private var vlessRealityPublicKey = ""
    @State private var vlessRealityShortId = ""
    @State private var vlessFingerprint: TLSFingerprint = .chrome120
    
    @State private var vlessXHTTPDownloadEnabled = false
    @State private var vlessXHTTPDownloadAddress = ""
    @State private var vlessXHTTPDownloadPort = ""
    @State private var vlessXHTTPDownloadHost = ""
    @State private var vlessXHTTPDownloadPath = "/"
    
    @State private var vlessXHTTPDownloadSecurity = "none"
    @State private var vlessXHTTPDownloadTLSSNI = ""
    @State private var vlessXHTTPDownloadTLSALPN = ""
    @State private var vlessXHTTPDownloadRealitySNI = ""
    @State private var vlessXHTTPDownloadRealityPublicKey = ""
    @State private var vlessXHTTPDownloadRealityShortId = ""
    @State private var vlessXHTTPDownloadFingerprint: TLSFingerprint = .chrome120
    
    // Hysteria fields
    @State private var hysteriaPassword = ""
    @State private var hysteriaCC: HysteriaCongestionControl = .brutal
    @State private var hysteriaUploadMbpsText = String(HysteriaCongestionControl.uploadMbpsDefault)
    @State private var hysteriaDownloadMbpsText = String(HysteriaCongestionControl.downloadMbpsDefault)
    @State private var hysteriaPortsSpec = ""
    @State private var hysteriaHopIntervalText = String(HysteriaPortHopping.defaultIntervalSeconds)
    @State private var hysteriaSNI = ""

    // Nowhere fields
    @State private var nowhereKey = ""

    // Trojan fields
    @State private var trojanPassword = ""
    @State private var trojanSNI = ""
    @State private var trojanALPN = ""
    @State private var trojanFingerprint: TLSFingerprint = .chrome120

    // AnyTLS fields
    @State private var anytlsPassword = ""
    @State private var anytlsSNI = ""
    @State private var anytlsALPN = ""
    @State private var anytlsFingerprint: TLSFingerprint = .chrome120

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

    // Shared credential fields for HTTPS/HTTP2/QUIC
    @State private var naiveUsername = ""
    @State private var naivePassword = ""

    private var isVLESS: Bool { selectedProtocol == .vless }
    private var isVLESSReality: Bool { vlessSecurity == "reality" }
    private var isVLESSTLS: Bool { vlessSecurity == "tls" }
    private var isHysteria: Bool { selectedProtocol == .hysteria }
    private var isNowhere: Bool { selectedProtocol == .nowhere }
    private var isTrojan: Bool { selectedProtocol == .trojan }
    private var isAnyTLS: Bool { selectedProtocol == .anytls }
    private var isShadowsocks: Bool { selectedProtocol == .shadowsocks }
    private var isSOCKS5: Bool { selectedProtocol == .socks5 }
    private var isSudoku: Bool { selectedProtocol == .sudoku }
    private var isNaive: Bool { selectedProtocol.isNaive }

    private var isValid: Bool {
        guard !name.isEmpty, !serverAddress.isEmpty, UInt16(serverPort) != nil else { return false }
        if isVLESS {
            guard UUID(xrayString: vlessUUID) != nil,
                  !isVLESSReality || (!vlessRealitySNI.isEmpty && !vlessRealityPublicKey.isEmpty) else { return false }
            if vlessTransport == "xhttp", vlessXHTTPDownloadEnabled {
                guard !vlessXHTTPDownloadAddress.isEmpty, UInt16(vlessXHTTPDownloadPort) != nil else { return false }
                if vlessXHTTPDownloadSecurity == "reality", vlessXHTTPDownloadRealityPublicKey.isEmpty { return false }
            }
            return true
        }
        if isHysteria {
            if hysteriaPassword.isEmpty { return false }
            if hysteriaCC == .brutal {
                guard let up = Int(hysteriaUploadMbpsText), HysteriaCongestionControl.uploadMbpsRange.contains(up),
                      let down = Int(hysteriaDownloadMbpsText), HysteriaCongestionControl.downloadMbpsRange.contains(down)
                else { return false }
            }
            return true
        }
        if isNowhere {
            return !nowhereKey.isEmpty
        }
        if isTrojan {
            return !trojanPassword.isEmpty
        }
        if isAnyTLS {
            return !anytlsPassword.isEmpty
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
        return false
    }

    init(configuration: ProxyConfiguration? = nil, onSave: @escaping (ProxyConfiguration) -> Void) {
        self.configuration = configuration
        self.onSave = onSave
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent {
                        TextField("Name", text: $name)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Name", comment: nil, systemName: "tag.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                }
                
                Section {
                    Picker(selection: $selectedProtocol) {
                        Text(String("VLESS")).tag(OutboundProtocol.vless)
                        Text(String("Hysteria")).tag(OutboundProtocol.hysteria)
                        Text(String("Nowhere")).tag(OutboundProtocol.nowhere)
                        Text(String("Trojan")).tag(OutboundProtocol.trojan)
                        Text(String("AnyTLS")).tag(OutboundProtocol.anytls)
                        Text(String("Shadowsocks")).tag(OutboundProtocol.shadowsocks)
                        Text(String("SOCKS5")).tag(OutboundProtocol.socks5)
                        Text(String("Sudoku")).tag(OutboundProtocol.sudoku)
                        Text(String("HTTPS")).tag(OutboundProtocol.http11)
                        Text(String("HTTP2")).tag(OutboundProtocol.http2)
                        Text(String("QUIC")).tag(OutboundProtocol.http3)
                    } label: {
                        TextWithColorfulIcon(title: "Protocol", comment: nil, systemName: "arrow.down.left.arrow.up.right.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
                
                serverSettings
                
                transportSettings
                
                securityLayerSettings
                
                extraSettings
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
    
    @ViewBuilder
    private var serverSettings: some View {
        Section("Server") {
            LabeledContent {
                TextField("Address", text: $serverAddress)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .multilineTextAlignment(.trailing)
            } label: {
                TextWithColorfulIcon(title: "Address", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
            }
            LabeledContent {
                TextField(String("443"), text: $serverPort)
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.trailing)
            } label: {
                TextWithColorfulIcon(title: "Port", comment: nil, systemName: "123.rectangle", foregroundColor: .white, backgroundColor: .cyan)
            }
            if isVLESS {
                LabeledContent {
                    TextField(String(localized: "UUID", comment: "UUID for VLESS protocol"), text: $vlessUUID)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "UUID", comment: "UUID for VLESS protocol", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
                // Encryption (mlkem768x25519plus) requires CryptoKit's
                // ML-KEM-768 — iOS/macOS/tvOS 26+ only.
                if #available(iOS 26.0, macOS 26.0, tvOS 26.0, *) {
                    LabeledContent {
                        TextField(String("none"), text: $vlessEncryption)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Encryption", comment: "Encryption for VLESS protocol", systemName: "lock.fill", foregroundColor: .white, backgroundColor: .red)
                    }
                }
            } else if isHysteria {
                LabeledContent {
                    SecureField("Password", text: $hysteriaPassword)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Password", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
                if !hysteriaPortsSpec.isEmpty {
                    LabeledContent {
                        TextField("Seconds", text: $hysteriaHopIntervalText)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Port Hopping Interval", comment: "Port Hopping Interval for Hysteria protocol", systemName: "timer", foregroundColor: .white, backgroundColor: .green)
                    }
                }
                Picker(selection: $hysteriaCC) {
                    ForEach(HysteriaCongestionControl.allCases, id: \.self) { cc in
                        Text(cc.displayName).tag(cc)
                    }
                } label: {
                    TextWithColorfulIcon(title: "Congestion Control", comment: "Congestion control algorithm for Hysteria protocol", systemName: "speedometer", foregroundColor: .white, backgroundColor: .blue)
                }
                if hysteriaCC == .brutal {
                    LabeledContent {
                        TextField("Mbps", text: $hysteriaUploadMbpsText)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Upload Speed", comment: "Upload Speed for Hysteria protocol", systemName: "arrow.up.circle.fill", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Mbps", text: $hysteriaDownloadMbpsText)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Download Speed", comment: "Download Speed for Hysteria protocol", systemName: "arrow.down.circle.fill", foregroundColor: .white, backgroundColor: .blue)
                    }
                }
                LabeledContent {
                    TextField(String("443,5000-6000"), text: $hysteriaPortsSpec)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Port Hopping", comment: "Port Hopping for Hysteria protocol", systemName: "arrowshape.bounce.forward.fill", foregroundColor: .white, backgroundColor: .cyan)
                }
            } else if isNowhere {
                LabeledContent {
                    SecureField("Key", text: $nowhereKey)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Key", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
            } else if isTrojan {
                LabeledContent {
                    SecureField("Password", text: $trojanPassword)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Password", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
            } else if isAnyTLS {
                LabeledContent {
                    SecureField("Password", text: $anytlsPassword)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Password", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
            } else if isShadowsocks {
                LabeledContent {
                    SecureField("Password", text: $ssPassword)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Password", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
                Picker(selection: $ssMethod) {
                    Text("None").tag("none")
                    Text(String("AES-128-GCM")).tag("aes-128-gcm")
                    Text(String("AES-256-GCM")).tag("aes-256-gcm")
                    Text(String("ChaCha20-Poly1305")).tag("chacha20-ietf-poly1305")
                    Text(String("BLAKE3-AES-128-GCM")).tag("2022-blake3-aes-128-gcm")
                    Text(String("BLAKE3-AES-256-GCM")).tag("2022-blake3-aes-256-gcm")
                    Text(String("BLAKE3-ChaCha20-Poly1305")).tag("2022-blake3-chacha20-poly1305")
                } label: {
                    TextWithColorfulIcon(title: "Method", comment: "Method for Shadowsocks protocol", systemName: "lock.fill", foregroundColor: .white, backgroundColor: .red)
                }
            } else if isSOCKS5 {
                LabeledContent {
                    TextField("Username", text: $socks5Username)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Username", comment: nil, systemName: "person.fill", foregroundColor: .white, backgroundColor: .green)
                }
                LabeledContent {
                    SecureField("Password", text: $socks5Password)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Password", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
            } else if isSudoku {
                LabeledContent {
                    SecureField(String(localized: "Key", comment: "Key for Sudoku protocol"), text: $sudokuKey)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Key", comment: "Key for Sudoku protocol", systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
                Picker(selection: $sudokuAEADMethod) {
                    ForEach(SudokuAEADMethod.allCases, id: \.self) { method in
                        Text(method.displayName).tag(method)
                    }
                } label: {
                    TextWithColorfulIcon(title: "AEAD", comment: "AEAD for Sudoku protocol", systemName: "lock.fill", foregroundColor: .white, backgroundColor: .red)
                }
                LabeledContent {
                    TextField(String("0-100"), text: $sudokuPaddingMinText)
                        .keyboardType(.numberPad)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Padding Min", comment: "Padding Min for Sudoku protocol", systemName: "arrow.down.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                }
                LabeledContent {
                    TextField(String("0-100"), text: $sudokuPaddingMaxText)
                        .keyboardType(.numberPad)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Padding Max", comment: "Padding Max for Sudoku protocol", systemName: "arrow.up.circle.fill", foregroundColor: .white, backgroundColor: .orange)
                }
                Picker(selection: $sudokuASCIIMode) {
                    ForEach(SudokuASCIIMode.allCases, id: \.self) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                } label: {
                    TextWithColorfulIcon(title: "ASCII", comment: nil, systemName: "textformat.alt", foregroundColor: .white, backgroundColor: .blue)
                }
                LabeledContent {
                    TextField("Comma Separated", text: $sudokuCustomTablesText)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Custom Tables", comment: "Custom Tables for Sudoku protocol", systemName: "square.stack.3d.up.fill", foregroundColor: .white, backgroundColor: .indigo)
                }
                Toggle(isOn: $sudokuEnablePureDownlink) {
                    TextWithColorfulIcon(title: "Pure Downlink", comment: "Pure Downlink for Sudoku protocol", systemName: "arrow.down.to.line.compact", foregroundColor: .white, backgroundColor: .teal)
                }
            } else if isNaive {
                LabeledContent {
                    TextField("Username", text: $naiveUsername)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Username", comment: nil, systemName: "person.fill", foregroundColor: .white, backgroundColor: .green)
                }
                LabeledContent {
                    SecureField("Password", text: $naivePassword)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "Password", comment: nil, systemName: "key.fill", foregroundColor: .white, backgroundColor: .green)
                }
            }
        }
    }
    
    @ViewBuilder
    private var transportSettings: some View {
        if isVLESS {
            Section {
                Picker(selection: $vlessFlow) {
                    Text("None").tag("")
                    Text("Vision").tag("xtls-rprx-vision")
                } label: {
                    TextWithColorfulIcon(title: "Flow", comment: "Flow for VLESS protocol TCP transport", systemName: "arrow.left.arrow.right", foregroundColor: .white, backgroundColor: .indigo)
                }
            }
            
            Section("Transport") {
                Picker(selection: $vlessTransport) {
                    Text("TCP").tag("tcp")
                    Text("WebSocket").tag("ws")
                    Text("HTTPUpgrade").tag("httpupgrade")
                    Text("gRPC").tag("grpc")
                    Text("XHTTP").tag("xhttp")
                } label: {
                    TextWithColorfulIcon(title: "Transport", comment: "Transport for VLESS protocol", systemName: "arrow.triangle.swap", foregroundColor: .white, backgroundColor: .purple)
                }
                if vlessTransport == "tcp" {
                    Toggle(isOn: $vlessMuxEnabled) {
                        TextWithColorfulIcon(title: "Mux", comment: "Mux for VLESS protocol TCP transport", systemName: "rectangle.split.3x1.fill", foregroundColor: .white, backgroundColor: .teal)
                    }
                    .onChange(of: vlessMuxEnabled) {
                        if vlessMuxEnabled == false {
                            vlessXUDPEnabled = false
                        }
                    }
                    if vlessMuxEnabled {
                        Toggle(isOn: $vlessXUDPEnabled) {
                            TextWithColorfulIcon(title: "XUDP", comment: "XUDP for VLESS protocol TCP transport", systemName: "arrow.up.arrow.down.circle.fill", foregroundColor: .white, backgroundColor: .cyan)
                        }
                    }
                }
                if vlessTransport == "ws" {
                    LabeledContent {
                        TextField("Host", text: $vlessWebSocketHost)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Host", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("/", text: $vlessWebSocketPath)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Path", comment: nil, systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                    }
                }
                if vlessTransport == "httpupgrade" {
                    LabeledContent {
                        TextField("Host", text: $vlessHTTPUpgradeHost)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Host", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("/", text: $vlessHTTPUpgradePath)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Path", comment: nil, systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                    }
                }
                if vlessTransport == "grpc" {
                    LabeledContent {
                        TextField("Service Name", text: $vlessGRPCServiceName)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Service Name", comment: "Service Name for VLESS protocol gRPC transport", systemName: "realtimetext", foregroundColor: .white, backgroundColor: .mint)
                    }
                    LabeledContent {
                        TextField("Authority", text: $vlessGRPCAuthority)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Authority", comment: "Authority for VLESS protocol gRPC transport", systemName: "person.fill", foregroundColor: .white, backgroundColor: .green)
                    }
                    Picker(selection: $vlessGRPCMode) {
                        Text("Gun").tag("gun")
                        Text("Multi").tag("multi")
                    } label: {
                        TextWithColorfulIcon(title: "Mode", comment: nil, systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                    LabeledContent {
                        TextField("User Agent", text: $vlessGRPCUserAgent)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "User Agent", comment: nil, systemName: "laptopcomputer", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
                if vlessTransport == "xhttp" {
                    LabeledContent {
                        TextField("Host", text: $vlessXHTTPHost)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Host", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("/", text: $vlessXHTTPPath)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Path", comment: nil, systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                    }
                    Picker(selection: $vlessXHTTPMode) {
                        Text("Auto").tag("auto")
                        Text(String("Packet Up")).tag("packet-up")
                        Text(String("Stream Up")).tag("stream-up")
                        Text(String("Stream One")).tag("stream-one")
                    } label: {
                        TextWithColorfulIcon(title: "Mode", comment: nil, systemName: "gearshape.fill", foregroundColor: .white, backgroundColor: .gray)
                    }
                }
            }
        }
    }
    
    @ViewBuilder
    private var securityLayerSettings: some View {
        if isVLESS {
            Section((vlessTransport == "xhttp" && vlessXHTTPDownloadEnabled) ? String(localized: "TLS (Upload)") : String(localized: "TLS")) {
                Picker(selection: $vlessSecurity) {
                    Text("None").tag("none")
                    Text("TLS").tag("tls")
                    Text("Reality").tag("reality")
                } label: {
                    TextWithColorfulIcon(title: "Security", comment: "Security for VLESS protocol", systemName: "shield.lefthalf.filled", foregroundColor: .white, backgroundColor: .blue)
                }
                if isVLESSTLS {
                    LabeledContent {
                        TextField("SNI", text: $vlessTLSSNI)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("h2,http/1.1", text: $vlessTLSALPN)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "ALPN", comment: nil, systemName: "list.bullet", foregroundColor: .white, backgroundColor: .blue)
                    }
                    Picker(selection: $vlessFingerprint) {
                        ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                            Text(fp.displayName).tag(fp)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Fingerprint", comment: nil, systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
                if isVLESSReality {
                    LabeledContent {
                        TextField("SNI", text: $vlessRealitySNI)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Public Key", text: $vlessRealityPublicKey)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Public Key", comment: "Public Key for Reality security layer", systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .green)
                    }
                    LabeledContent {
                        TextField("Short ID", text: $vlessRealityShortId)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Short ID", comment: "Short ID for Reality security layer", systemName: "person.crop.square.filled.and.at.rectangle.fill", foregroundColor: .white, backgroundColor: .green)
                    }
                    Picker(selection: $vlessFingerprint) {
                        ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                            Text(fp.displayName).tag(fp)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Fingerprint", comment: nil, systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
            }
        } else if isTrojan {
            Section("TLS") {
                LabeledContent {
                    TextField("SNI", text: $trojanSNI)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                }
                LabeledContent {
                    TextField("h2,http/1.1", text: $trojanALPN)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "ALPN", comment: nil, systemName: "list.bullet", foregroundColor: .white, backgroundColor: .blue)
                }
                Picker(selection: $trojanFingerprint) {
                    ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                        Text(fp.displayName).tag(fp)
                    }
                } label: {
                    TextWithColorfulIcon(title: "Fingerprint", comment: nil, systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                }
            }
        } else if isAnyTLS {
            Section("TLS") {
                LabeledContent {
                    TextField("SNI", text: $anytlsSNI)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                }
                LabeledContent {
                    TextField("h2,http/1.1", text: $anytlsALPN)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "ALPN", comment: nil, systemName: "list.bullet", foregroundColor: .white, backgroundColor: .blue)
                }
                Picker(selection: $anytlsFingerprint) {
                    ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                        Text(fp.displayName).tag(fp)
                    }
                } label: {
                    TextWithColorfulIcon(title: "Fingerprint", comment: nil, systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                }
            }
        } else if isHysteria {
            Section {
                LabeledContent {
                    TextField("SNI", text: $hysteriaSNI)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .multilineTextAlignment(.trailing)
                } label: {
                    TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                }
            }
        } else if isSudoku {
            Section(String(localized: "HTTP Mask", comment: "HTTP Mask for Sudoku protocol")) {
                Toggle(isOn: $sudokuHTTPMaskDisable) {
                    TextWithColorfulIcon(title: "Disable HTTP Mask", comment: "Disable HTTP Mask for Sudoku protocol", systemName: "xmark.circle.fill", foregroundColor: .white, backgroundColor: .gray)
                }
                if !sudokuHTTPMaskDisable {
                    Picker(selection: $sudokuHTTPMaskMode) {
                        ForEach(SudokuHTTPMaskMode.allCases, id: \.self) { mode in
                            Text(mode.displayName).tag(mode)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Mode", comment: nil, systemName: "network.badge.shield.half.filled", foregroundColor: .white, backgroundColor: .purple)
                    }
                    Toggle(isOn: $sudokuHTTPMaskTLS) {
                        TextWithColorfulIcon(title: "TLS", comment: nil, systemName: "lock.shield.fill", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Host", text: $sudokuHTTPMaskHost)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Host", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Path Root", text: $sudokuHTTPMaskPathRoot)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Path Root", comment: "Path Root for Sudoku protocol HTTP Mask feature", systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                    }
                    Picker(selection: $sudokuHTTPMaskMultiplex) {
                        ForEach(SudokuHTTPMaskMultiplex.allCases, id: \.self) { mode in
                            Text(mode.displayName).tag(mode)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Multiplex", comment: "Multiplex for Sudoku protocol HTTP Mask feature", systemName: "rectangle.split.3x1.fill", foregroundColor: .white, backgroundColor: .teal)
                    }
                }
            }
        }
    }
    
    @ViewBuilder
    private var extraSettings: some View {
        if isVLESS && vlessTransport == "xhttp" {
            Section {
                Toggle(isOn: $vlessXHTTPDownloadEnabled) {
                    TextWithColorfulIcon(title: "Detached Download", comment: nil, systemName: "arrow.down.circle.fill", foregroundColor: .white, backgroundColor: .indigo)
                }
                if vlessXHTTPDownloadEnabled {
                    LabeledContent {
                        TextField("Address", text: $vlessXHTTPDownloadAddress)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Address", comment: nil, systemName: "server.rack", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Port", text: $vlessXHTTPDownloadPort)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Port", comment: nil, systemName: "123.rectangle", foregroundColor: .white, backgroundColor: .cyan)
                    }
                    LabeledContent {
                        TextField("Host", text: $vlessXHTTPDownloadHost)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Host", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("/", text: $vlessXHTTPDownloadPath)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Path", comment: nil, systemName: "point.topleft.down.to.point.bottomright.curvepath", foregroundColor: .white, backgroundColor: .blue)
                    }
                }
            }
        }
        
        if isVLESS && vlessTransport == "xhttp" && vlessXHTTPDownloadEnabled {
            Section("TLS (Download)") {
                Picker(selection: $vlessXHTTPDownloadSecurity) {
                    Text("None").tag("none")
                    Text("TLS").tag("tls")
                    Text("Reality").tag("reality")
                } label: {
                    TextWithColorfulIcon(title: "Security", comment: nil, systemName: "shield.lefthalf.filled", foregroundColor: .white, backgroundColor: .blue)
                }
                if vlessXHTTPDownloadSecurity == "tls" {
                    LabeledContent {
                        TextField("SNI", text: $vlessXHTTPDownloadTLSSNI)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("h2,http/1.1", text: $vlessXHTTPDownloadTLSALPN)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "ALPN", comment: nil, systemName: "list.bullet", foregroundColor: .white, backgroundColor: .blue)
                    }
                    Picker(selection: $vlessXHTTPDownloadFingerprint) {
                        ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                            Text(fp.displayName).tag(fp)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Fingerprint", comment: nil, systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
                if vlessXHTTPDownloadSecurity == "reality" {
                    LabeledContent {
                        TextField("SNI", text: $vlessXHTTPDownloadRealitySNI)
                            .keyboardType(.URL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "SNI", comment: nil, systemName: "network", foregroundColor: .white, backgroundColor: .blue)
                    }
                    LabeledContent {
                        TextField("Public Key", text: $vlessXHTTPDownloadRealityPublicKey)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Public Key", comment: nil, systemName: "key.horizontal.fill", foregroundColor: .white, backgroundColor: .green)
                    }
                    LabeledContent {
                        TextField("Short ID", text: $vlessXHTTPDownloadRealityShortId)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        TextWithColorfulIcon(title: "Short ID", comment: nil, systemName: "person.crop.square.filled.and.at.rectangle.fill", foregroundColor: .white, backgroundColor: .green)
                    }
                    Picker(selection: $vlessXHTTPDownloadFingerprint) {
                        ForEach(TLSFingerprint.allCases, id: \.self) { fp in
                            Text(fp.displayName).tag(fp)
                        }
                    } label: {
                        TextWithColorfulIcon(title: "Fingerprint", comment: nil, systemName: "hand.raised.fingers.spread.fill", foregroundColor: .white, backgroundColor: .orange)
                    }
                }
            }
        }
    }

    private func populateFromExisting() {
        guard let configuration else { return }
        selectedProtocol = configuration.outboundProtocol
        name = configuration.name
        serverAddress = configuration.serverAddress
        serverPort = String(configuration.serverPort)
        if case .vless(let vlessUUID, let vlessEncryption, let vlessFlow, _, _, _, _) = configuration.outbound {
            self.vlessUUID = vlessUUID.uuidString
            self.vlessEncryption = vlessEncryption
            self.vlessFlow = vlessFlow ?? ""
        } else {
            vlessUUID = configuration.id.uuidString
            vlessEncryption = "none"
            vlessFlow = ""
        }
        if isVLESS {
            vlessTransport = configuration.transportLayer.tag
            vlessSecurity = configuration.securityLayer.tag

            if case .ws(let ws) = configuration.transportLayer {
                vlessWebSocketHost = ws.host
                vlessWebSocketPath = ws.path
            }

            if case .httpUpgrade(let httpUpgrade) = configuration.transportLayer {
                vlessHTTPUpgradeHost = httpUpgrade.host
                vlessHTTPUpgradePath = httpUpgrade.path
            }
        
            if case .grpc(let grpc) = configuration.transportLayer {
                vlessGRPCServiceName = grpc.serviceName
                vlessGRPCAuthority = grpc.authority
                vlessGRPCMode = grpc.multiMode ? "multi" : "gun"
                vlessGRPCUserAgent = grpc.userAgent
            }

            if case .xhttp(let xhttp) = configuration.transportLayer {
                vlessXHTTPHost = xhttp.host
                vlessXHTTPPath = xhttp.path
                vlessXHTTPMode = xhttp.mode.rawValue
                vlessXHTTPExtra = Self.encodeExtra(from: xhttp)
                if let download = xhttp.downloadSettings {
                    vlessXHTTPDownloadEnabled = true
                    vlessXHTTPDownloadAddress = download.serverAddress
                    vlessXHTTPDownloadPort = String(download.serverPort)
                    vlessXHTTPDownloadSecurity = download.security
                    if let tls = download.tls {
                        vlessXHTTPDownloadTLSSNI = tls.serverName
                        vlessXHTTPDownloadTLSALPN = tls.alpn?.joined(separator: ",") ?? ""
                        vlessXHTTPDownloadFingerprint = tls.fingerprint
                    }
                    if let reality = download.reality {
                        vlessXHTTPDownloadRealitySNI = reality.serverName
                        vlessXHTTPDownloadRealityPublicKey = reality.publicKey.base64URLEncodedString()
                        vlessXHTTPDownloadRealityShortId = reality.shortId.hexEncodedString()
                        vlessXHTTPDownloadFingerprint = reality.fingerprint
                    }
                    vlessXHTTPDownloadHost = download.xhttp.host
                    vlessXHTTPDownloadPath = download.xhttp.path
                }
            }

            vlessMuxEnabled = configuration.muxEnabled
            vlessXUDPEnabled = configuration.xudpEnabled

            if case .tls(let tls) = configuration.securityLayer {
                vlessTLSSNI = tls.serverName
                vlessTLSALPN = tls.alpn?.joined(separator: ",") ?? ""
                vlessFingerprint = tls.fingerprint
            }

            if case .reality(let reality) = configuration.securityLayer {
                vlessRealitySNI = reality.serverName
                vlessRealityPublicKey = reality.publicKey.base64URLEncodedString()
                vlessRealityShortId = reality.shortId.hexEncodedString()
                vlessFingerprint = reality.fingerprint
            }
        }

        switch configuration.outbound {
        case .vless:
            break
        case .hysteria(let password, let congestionControl, let uploadMbps, let downloadMbps, let portHopping, let sni):
            hysteriaPassword = password
            hysteriaCC = congestionControl
            hysteriaUploadMbpsText = String(uploadMbps)
            hysteriaDownloadMbpsText = String(downloadMbps)
            hysteriaPortsSpec = portHopping?.portsSpec ?? ""
            hysteriaHopIntervalText = String(portHopping?.intervalSeconds ?? HysteriaPortHopping.defaultIntervalSeconds)
            hysteriaSNI = sni
        case .nowhere(let key):
            nowhereKey = key
        case .trojan(let password, let tls):
            trojanPassword = password
            trojanSNI = tls.serverName
            trojanALPN = tls.alpn?.joined(separator: ",") ?? ""
            trojanFingerprint = tls.fingerprint
        case .anytls(let password, _, _, _, let tls):
            anytlsPassword = password
            anytlsSNI = tls.serverName
            anytlsALPN = tls.alpn?.joined(separator: ",") ?? ""
            anytlsFingerprint = tls.fingerprint
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

    /// Builds the `downloadSettings` object for the XHTTP `extra` blob from the
    /// flattened detach fields, or nil when the split is off or its address/port
    /// are missing. Keys match what `XHTTPConfiguration.parse` reads back.
    private func xhttpDownloadSettingsDict() -> [String: Any]? {
        guard vlessXHTTPDownloadEnabled,
              !vlessXHTTPDownloadAddress.isEmpty,
              let port = UInt16(vlessXHTTPDownloadPort) else { return nil }
        var download: [String: Any] = [
            "address": vlessXHTTPDownloadAddress,
            "port": Int(port),
            "security": vlessXHTTPDownloadSecurity
        ]
        switch vlessXHTTPDownloadSecurity {
        case "tls":
            var tls: [String: Any] = ["fingerprint": vlessXHTTPDownloadFingerprint.rawValue]
            if !vlessXHTTPDownloadTLSSNI.isEmpty { tls["serverName"] = vlessXHTTPDownloadTLSSNI }
            let alpn = vlessXHTTPDownloadTLSALPN
                .split(separator: ",")
                .map { String($0).trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            if !alpn.isEmpty { tls["alpn"] = alpn }
            download["tlsSettings"] = tls
        case "reality":
            download["realitySettings"] = [
                "serverName": vlessXHTTPDownloadRealitySNI,
                "publicKey": vlessXHTTPDownloadRealityPublicKey,
                "shortId": vlessXHTTPDownloadRealityShortId,
                "fingerprint": vlessXHTTPDownloadFingerprint.rawValue
            ]
        default:
            break
        }
        var xhttpSettings: [String: Any] = [:]
        if !vlessXHTTPDownloadHost.isEmpty { xhttpSettings["host"] = vlessXHTTPDownloadHost }
        if !vlessXHTTPDownloadPath.isEmpty, vlessXHTTPDownloadPath != "/" { xhttpSettings["path"] = vlessXHTTPDownloadPath }
        if !xhttpSettings.isEmpty { download["xhttpSettings"] = xhttpSettings }
        return download
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
        if isHysteria || isNowhere || isTrojan || isAnyTLS || isShadowsocks || isSOCKS5 || isSudoku || isNaive {
            parsedUUID = self.configuration?.id ?? UUID()
        } else {
            guard let u = UUID(xrayString: vlessUUID) else { return }
            parsedUUID = u
        }
        
        var vlessTLSConfiguration: TLSConfiguration?
        if isVLESSTLS {
            let sni = vlessTLSSNI.isEmpty ? serverAddress : vlessTLSSNI
            let alpn: [String]? = vlessTLSALPN.isEmpty ? nil : vlessTLSALPN.split(separator: ",").map { String($0) }
            vlessTLSConfiguration = TLSConfiguration(
                serverName: sni,
                alpn: alpn,
                fingerprint: vlessFingerprint
            )
        }
        
        var vlessRealityConfiguration: RealityConfiguration?
        if isVLESSReality {
            guard let pk = Data(base64URLEncoded: vlessRealityPublicKey) else { return }
            let sid = Data(hexString: vlessRealityShortId) ?? Data()
            vlessRealityConfiguration = RealityConfiguration(
                serverName: vlessRealitySNI,
                publicKey: pk,
                shortId: sid,
                fingerprint: vlessFingerprint
            )
        }

        var vlessWebSocketConfiguration: WebSocketConfiguration?
        if vlessTransport == "ws" {
            let host = vlessWebSocketHost.isEmpty ? serverAddress : vlessWebSocketHost
            let path = vlessWebSocketPath.isEmpty ? "/" : vlessWebSocketPath
            vlessWebSocketConfiguration = WebSocketConfiguration(host: host, path: path)
        }

        var vlessHTTPUpgradeConfiguration: HTTPUpgradeConfiguration?
        if vlessTransport == "httpupgrade" {
            vlessHTTPUpgradeConfiguration = HTTPUpgradeConfiguration(host: vlessHTTPUpgradeHost.isEmpty ? serverAddress : vlessHTTPUpgradeHost, path: vlessHTTPUpgradePath.isEmpty ? "/" : vlessHTTPUpgradePath)
        }

        var vlessXHTTPConfiguration: XHTTPConfiguration?
        if vlessTransport == "xhttp" {
            let host = vlessXHTTPHost.isEmpty ? serverAddress : vlessXHTTPHost
            let mode = XHTTPMode(rawValue: vlessXHTTPMode) ?? .auto
            // Parse extra JSON for advanced settings, passing through to XHTTPConfiguration.parse
            var params: [String: String] = [
                "host": host,
                "path": vlessXHTTPPath,
                "mode": mode.rawValue
            ]
            // `extra` carries the advanced fields (vlessXHTTPExtra) plus the detached
            // download source; merge so neither clobbers the other.
            var extra: [String: Any] = [:]
            if !vlessXHTTPExtra.isEmpty, let data = vlessXHTTPExtra.data(using: .utf8),
               let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                extra = parsed
            }
            if let download = xhttpDownloadSettingsDict() {
                extra["downloadSettings"] = download
            }
            if !extra.isEmpty,
               let data = try? JSONSerialization.data(withJSONObject: extra, options: [.sortedKeys]),
               let json = String(data: data, encoding: .utf8) {
                params["extra"] = json
            }
            vlessXHTTPConfiguration = XHTTPConfiguration.parse(from: params, serverAddress: serverAddress)
        }

        var vlessGRPCConfiguration: GRPCConfiguration?
        if vlessTransport == "grpc" {
            vlessGRPCConfiguration = GRPCConfiguration(
                serviceName: vlessGRPCServiceName,
                authority: vlessGRPCAuthority,
                multiMode: vlessGRPCMode == "multi",
                userAgent: vlessGRPCUserAgent
            )
        }

        // Strip brackets from IPv6 addresses (e.g. "[::1]" → "::1")
        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast())
            : serverAddress

        let outbound: Outbound
        switch selectedProtocol {
        case .vless:
            let vlessTransportLayer: TransportLayer
            if let vlessWebSocketConfiguration { vlessTransportLayer = .ws(vlessWebSocketConfiguration) }
            else if let vlessHTTPUpgradeConfiguration { vlessTransportLayer = .httpUpgrade(vlessHTTPUpgradeConfiguration) }
            else if let vlessXHTTPConfiguration { vlessTransportLayer = .xhttp(vlessXHTTPConfiguration) }
            else if let vlessGRPCConfiguration { vlessTransportLayer = .grpc(vlessGRPCConfiguration) }
            else { vlessTransportLayer = .tcp }

            let vlessSecurityLayer: SecurityLayer
            if let vlessRealityConfiguration { vlessSecurityLayer = .reality(vlessRealityConfiguration) }
            else if let vlessTLSConfiguration { vlessSecurityLayer = .tls(vlessTLSConfiguration) }
            else { vlessSecurityLayer = .none }

            outbound = .vless(
                uuid: parsedUUID,
                encryption: vlessEncryption,
                flow: vlessFlow.isEmpty ? nil : vlessFlow,
                transport: vlessTransportLayer,
                security: vlessSecurityLayer,
                muxEnabled: vlessMuxEnabled,
                xudpEnabled: vlessXUDPEnabled
            )
        case .hysteria:
            let up = HysteriaCongestionControl.clampUploadMbps(Int(hysteriaUploadMbpsText) ?? HysteriaCongestionControl.uploadMbpsDefault)
            let down = HysteriaCongestionControl.clampDownloadMbps(Int(hysteriaDownloadMbpsText) ?? HysteriaCongestionControl.downloadMbpsDefault)
            let sni = hysteriaSNI.isEmpty ? bareAddress : hysteriaSNI
            let portHopping = HysteriaPortHopping.make(
                spec: hysteriaPortsSpec,
                intervalSeconds: Int(hysteriaHopIntervalText)
            )
            outbound = .hysteria(
                password: hysteriaPassword,
                congestionControl: hysteriaCC,
                uploadMbps: up,
                downloadMbps: down,
                portHopping: portHopping,
                sni: sni
            )
        case .nowhere:
            outbound = .nowhere(
                key: nowhereKey
            )
        case .trojan:
            let sni = trojanSNI.isEmpty ? bareAddress : trojanSNI
            let alpn: [String]? = trojanALPN.isEmpty ? nil : trojanALPN.split(separator: ",").map { String($0) }
            outbound = .trojan(
                password: trojanPassword,
                tls: TLSConfiguration(serverName: sni, alpn: alpn, fingerprint: trojanFingerprint)
            )
        case .anytls:
            let sni = anytlsSNI.isEmpty ? bareAddress : anytlsSNI
            let alpn: [String]? = anytlsALPN.isEmpty ? nil : anytlsALPN.split(separator: ",").map { String($0) }
            // Pool-tuning knobs are not editable in the UI — preserve any
            // values the original config carried (URL/dict imports may set
            // them), or fall back to sing-anytls's defaults.
            let ici: Int
            let it: Int
            let mis: Int
            if let existing = self.configuration?.outbound, case .anytls(_, let c, let t, let m, _) = existing {
                ici = c; it = t; mis = m
            } else {
                ici = 30; it = 30; mis = 0
            }
            outbound = .anytls(
                password: anytlsPassword,
                idleCheckInterval: ici,
                idleTimeout: it,
                minIdleSession: mis,
                tls: TLSConfiguration(serverName: sni, alpn: alpn, fingerprint: anytlsFingerprint)
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
