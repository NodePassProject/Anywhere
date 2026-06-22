//
//  TVProxyEditorViewController.swift
//  Anywhere
//
//  Created by NodePassProject on 3/19/26.
//

import UIKit

class TVProxyEditorViewController: UITableViewController {

    // MARK: - Properties

    private let existingConfiguration: ProxyConfiguration?
    private let onSave: (ProxyConfiguration) -> Void

    private var selectedProtocol: OutboundProtocol = .vless
    private var name = ""
    private var serverAddress = ""
    private var serverPort = ""

    private var vlessUUID = ""
    private var vlessEncryption = "none"
    private var vlessFlow = ""
    private var vlessTransport = "tcp"

    private var vlessWebSocketHost = ""
    private var vlessWebSocketPath = "/"

    private var vlessHTTPUpgradeHost = ""
    private var vlessHTTPUpgradePath = "/"

    private var vlessGRPCServiceName = ""
    private var vlessGRPCAuthority = ""
    private var vlessGRPCMode = "gun"
    private var vlessGRPCUserAgent = ""

    private var vlessXHTTPHost = ""
    private var vlessXHTTPPath = "/"
    private var vlessXHTTPMode = "auto"
    private var vlessXHTTPExtra = ""

    private var vlessSecurity = "none"
    private var vlessTLSSNI = ""
    private var vlessTLSALPN = ""
    private var vlessRealitySNI = ""
    private var vlessRealityPublicKey = ""
    private var vlessRealityShortId = ""
    private var vlessTLSECHEnabled = false
    private var vlessTLSECH = ""
    private var vlessFingerprint: TLSFingerprint = .chrome120

    // XHTTP detach: download stream dialed to a separate server, flattened into its own security + host/path (effectively a second proxy).
    private var vlessXHTTPDownloadEnabled = false
    private var vlessXHTTPDownloadAddress = ""
    private var vlessXHTTPDownloadPort = ""
    private var vlessXHTTPDownloadHost = ""
    private var vlessXHTTPDownloadPath = "/"

    private var vlessXHTTPDownloadSecurity = "none"
    private var vlessXHTTPDownloadTLSSNI = ""
    private var vlessXHTTPDownloadTLSALPN = ""
    private var vlessXHTTPDownloadRealitySNI = ""
    private var vlessXHTTPDownloadRealityPublicKey = ""
    private var vlessXHTTPDownloadRealityShortId = ""
    private var vlessXHTTPDownloadFingerprint: TLSFingerprint = .chrome120

    private var hysteriaPassword = ""
    private var hysteriaCC: HysteriaCongestionControl = .brutal
    private var hysteriaUploadMbpsText = String(HysteriaCongestionControl.uploadMbpsDefault)
    private var hysteriaDownloadMbpsText = String(HysteriaCongestionControl.downloadMbpsDefault)
    private var hysteriaPortsSpec = ""
    private var hysteriaHopIntervalText = String(HysteriaPortHopping.defaultIntervalSeconds)
    private var hysteriaSNI = ""

    private var nowhereKey = ""
    private var nowhereSpec = ""
    private var nowhereNetwork: NowhereNetwork = .udp
    private var nowherePool = 0
    private var nowhereLastPool = NowherePool.enabledDefault
    private var nowhereSNI = ""
    private var nowhereALPN = ""

    private var trojanPassword = ""
    private var trojanSNI = ""
    private var trojanALPN = ""
    private var trojanECHEnabled = false
    private var trojanECH = ""
    private var trojanFingerprint: TLSFingerprint = .chrome120

    private var anytlsPassword = ""
    private var anytlsSNI = ""
    private var anytlsALPN = ""
    private var anytlsECHEnabled = false
    private var anytlsECH = ""
    private var anytlsFingerprint: TLSFingerprint = .chrome120

    private var ssPassword = ""
    private var ssMethod = "aes-128-gcm"

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

    // MARK: - Form Structure

    private enum RowType {
        case text(label: String, value: String, placeholder: String, key: FieldKey, secure: Bool = false)
        case selection(label: String, value: String, options: [(display: String, value: String)], key: FieldKey, systemImage: String? = nil)
        case toggle(label: String, isOn: Bool, key: FieldKey, systemImage: String? = nil)
    }

    private enum FieldKey {
        case name, address, port
        case outboundProtocol
        case vlessUUID, vlessEncryption, vlessTransport, vlessFlow, vlessSecurity
        case vlessWebSocketHost, vlessWebSocketPath
        case vlessHTTPUpgradeHost, vlessHTTPUpgradePath
        case vlessGRPCServiceName, vlessGRPCAuthority, vlessGRPCMode, vlessGRPCUserAgent
        case vlessXHTTPHost, vlessXHTTPPath, vlessXHTTPMode
        case vlessTLSSNI, vlessTLSALPN, vlessTLSECHEnabled, vlessTLSECH, vlessFingerprint
        case vlessRealitySNI, vlessRealityPublicKey, vlessRealityShortId
        case vlessXHTTPDownloadEnabled, vlessXHTTPDownloadAddress, vlessXHTTPDownloadPort
        case vlessXHTTPDownloadHost, vlessXHTTPDownloadPath
        case vlessXHTTPDownloadSecurity, vlessXHTTPDownloadTLSSNI, vlessXHTTPDownloadTLSALPN, vlessXHTTPDownloadFingerprint
        case vlessXHTTPDownloadRealitySNI, vlessXHTTPDownloadRealityPublicKey,
             vlessXHTTPDownloadRealityShortId
        case hysteriaPassword, hysteriaCC, hysteriaUploadMbps, hysteriaDownloadMbps,
             hysteriaPorts, hysteriaHopInterval, hysteriaSNI
        case nowhereKey, nowhereSpec, nowhereNetwork, nowherePoolEnabled, nowherePool, nowhereSNI, nowhereALPN
        case trojanPassword, trojanSNI, trojanALPN, trojanECHEnabled, trojanECH, trojanFingerprint
        case anytlsPassword, anytlsSNI, anytlsALPN, anytlsECHEnabled, anytlsECH, anytlsFingerprint
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

        sections.append((nil, [
            .text(label: String(localized: "Name"), value: name, placeholder: "Name", key: .name),
        ]))

        let protocolOptions: [(String, String)] = [
            ("VLESS", "vless"),
            ("Hysteria", "hysteria"),
            ("Nowhere", "nowhere"),
            ("Trojan", "trojan"),
            ("AnyTLS", "anytls"),
            ("Shadowsocks", "shadowsocks"),
            ("SOCKS5", "socks5"),
            ("Sudoku", "sudoku"),
            ("HTTPS", "http11"),
            ("HTTP/2", "http2"),
            ("HTTP/3", "http3"),
        ]
        sections.append((String(localized: "Protocol"), [
            .selection(label: String(localized: "Protocol"), value: selectedProtocol.name, options: protocolOptions, key: .outboundProtocol),
        ]))

        var serverRows: [RowType] = [
            .text(label: String(localized: "Address"), value: serverAddress, placeholder: String(localized: "Address"), key: .address),
            .text(label: String(localized: "Port"), value: serverPort, placeholder: "443", key: .port),
        ]
        if isVLESS {
            serverRows.append(.text(label: String(localized: "UUID", comment: "UUID for VLESS protocol"), value: vlessUUID, placeholder: String(localized: "UUID", comment: "UUID for VLESS protocol"), key: .vlessUUID))
            // Encryption (mlkem768x25519plus) needs CryptoKit ML-KEM-768; older OSes refuse it at dial time, so hide the field.
            if #available(tvOS 26.0, *) {
                serverRows.append(.text(label: String(localized: "Encryption", comment: "Encryption for VLESS protocol"), value: vlessEncryption, placeholder: "none", key: .vlessEncryption))
            }
        } else if isHysteria {
            serverRows.append(.text(label: String(localized: "Password"), value: hysteriaPassword, placeholder: String(localized: "Password"), key: .hysteriaPassword, secure: true))
            serverRows.append(.selection(label: String(localized: "Congestion Control", comment: "Congestion control algorithm for Hysteria protocol"), value: hysteriaCC.displayName, options: HysteriaCongestionControl.allCases.map { ($0.displayName, $0.rawValue) }, key: .hysteriaCC))
            if hysteriaCC == .brutal {
                serverRows.append(.text(label: String(localized: "Upload Speed", comment: "Upload Speed for Hysteria protocol"), value: hysteriaUploadMbpsText, placeholder: String(localized: "Mbps"), key: .hysteriaUploadMbps))
                serverRows.append(.text(label: String(localized: "Download Speed", comment: "Download Speed for Hysteria protocol"), value: hysteriaDownloadMbpsText, placeholder: String(localized: "Mbps"), key: .hysteriaDownloadMbps))
            }
            serverRows.append(.text(label: String(localized: "Port Hopping", comment: "Port Hopping for Hysteria protocol"), value: hysteriaPortsSpec, placeholder: String("443,5000-6000"), key: .hysteriaPorts))
            if !hysteriaPortsSpec.isEmpty {
                serverRows.append(.text(label: String(localized: "Port Hopping Interval", comment: "Port Hopping Interval for Hysteria protocol"), value: hysteriaHopIntervalText, placeholder: String(localized: "Seconds"), key: .hysteriaHopInterval))
            }
        } else if isNowhere {
            serverRows.append(.text(label: String(localized: "Key"), value: nowhereKey, placeholder: String(localized: "Key"), key: .nowhereKey, secure: true))
            serverRows.append(.text(label: String(localized: "Spec"), value: nowhereSpec, placeholder: String(localized: "Spec"), key: .nowhereSpec))
        } else if isTrojan {
            serverRows.append(.text(label: String(localized: "Password"), value: trojanPassword, placeholder: String(localized: "Password"), key: .trojanPassword, secure: true))
        } else if isAnyTLS {
            serverRows.append(.text(label: String(localized: "Password"), value: anytlsPassword, placeholder: String(localized: "Password"), key: .anytlsPassword, secure: true))
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
                ], key: .vlessTransport),
            ]
            if vlessTransport == "ws" {
                transportRows.append(.text(label: String(localized: "Host"), value: vlessWebSocketHost, placeholder: String(localized: "Host"), key: .vlessWebSocketHost))
                transportRows.append(.text(label: String(localized: "Path"), value: vlessWebSocketPath, placeholder: String(localized: "Path"), key: .vlessWebSocketPath))
            }
            if vlessTransport == "httpupgrade" {
                transportRows.append(.text(label: String(localized: "Host"), value: vlessHTTPUpgradeHost, placeholder: String(localized: "Host"), key: .vlessHTTPUpgradeHost))
                transportRows.append(.text(label: String(localized: "Path"), value: vlessHTTPUpgradePath, placeholder: String(localized: "Path"), key: .vlessHTTPUpgradePath))
            }
            if vlessTransport == "grpc" {
                transportRows.append(.text(label: String(localized: "Service Name", comment: "Service Name for VLESS protocol gRPC transport"), value: vlessGRPCServiceName, placeholder: String(localized: "Service Name", comment: "Service Name for VLESS protocol gRPC transport"), key: .vlessGRPCServiceName))
                transportRows.append(.text(label: String(localized: "Authority", comment: "Authority for VLESS protocol gRPC transport"), value: vlessGRPCAuthority, placeholder: String(localized: "Authority", comment: "Authority for VLESS protocol gRPC transport"), key: .vlessGRPCAuthority))
                transportRows.append(.selection(label: String(localized: "Mode"), value: grpcModeDisplayValue, options: [
                    ("Gun", "gun"),
                    ("Multi", "multi"),
                ], key: .vlessGRPCMode))
                transportRows.append(.text(label: String(localized: "User Agent"), value: vlessGRPCUserAgent, placeholder: String(localized: "User Agent"), key: .vlessGRPCUserAgent))
            }
            if vlessTransport == "xhttp" {
                transportRows.append(.text(label: String(localized: "Host"), value: vlessXHTTPHost, placeholder: String(localized: "Host"), key: .vlessXHTTPHost))
                transportRows.append(.text(label: String(localized: "Path"), value: vlessXHTTPPath, placeholder: String(localized: "Path"), key: .vlessXHTTPPath))
                transportRows.append(.selection(label: String(localized: "Mode"), value: xhttpModeDisplayValue, options: [
                    (String(localized: "Auto"), "auto"),
                    ("Packet Up", "packet-up"),
                    ("Stream Up", "stream-up"),
                    ("Stream One", "stream-one"),
                ], key: .vlessXHTTPMode))
            }
            sections.append((nil, [
                .selection(label: String(localized: "Flow", comment: "Flow for VLESS protocol TCP transport"), value: flowDisplayValue, options: [
                    (String(localized: "None"), ""),
                    ("Vision", "xtls-rprx-vision"),
                ], key: .vlessFlow),
            ]))
            sections.append((String(localized: "Transport"), transportRows))
        } else if isNowhere {
            var transportRows: [RowType] = [
                .selection(
                    label: String(localized: "Network"),
                    value: nowhereNetwork.rawValue.uppercased(),
                    options: [("TCP", "tcp"), ("UDP", "udp")],
                    key: .nowhereNetwork,
                    systemImage: "globe"
                ),
            ]
            if nowhereNetwork == .tcp {
                transportRows.append(.toggle(label: String(localized: "Boost"), isOn: nowherePool > 0, key: .nowherePoolEnabled, systemImage: "speedometer"))
                if nowherePool > 0 {
                    transportRows.append(.selection(
                        label: String(localized: "Boost"),
                        value: String(nowherePool),
                        options: NowherePool.sliderRange.map { (String($0), String($0)) },
                        key: .nowherePool
                    ))
                }
            }
            sections.append((String(localized: "Network"), transportRows))
        }

        if isVLESS {
            var tlsRows: [RowType] = [
                .selection(label: String(localized: "Security", comment: "Security for VLESS protocol"), value: securityDisplayValue, options: [
                    (String("None"), "none"),
                    ("TLS", "tls"),
                    ("Reality", "reality"),
                ], key: .vlessSecurity),
            ]
            if isVLESSTLS {
                tlsRows.append(.text(label: String(localized: "SNI"), value: vlessTLSSNI, placeholder: String(localized: "SNI"), key: .vlessTLSSNI))
                tlsRows.append(.text(label: String(localized: "ALPN"), value: vlessTLSALPN, placeholder: String(localized: "h2,http/1.1"), key: .vlessTLSALPN))
                tlsRows.append(.toggle(label: String(localized: "Enable ECH"), isOn: vlessTLSECHEnabled, key: .vlessTLSECHEnabled))
                if vlessTLSECHEnabled {
                    tlsRows.append(.text(label: String(localized: "ECH Config"), value: vlessTLSECH, placeholder: String(localized: "Base64"), key: .vlessTLSECH))
                }
                tlsRows.append(.selection(label: String(localized: "Fingerprint"), value: vlessFingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .vlessFingerprint))
            }
            if isVLESSReality {
                tlsRows.append(.text(label: String(localized: "SNI"), value: vlessRealitySNI, placeholder: String(localized: "SNI"), key: .vlessRealitySNI))
                tlsRows.append(.text(label: String(localized: "Public Key", comment: "Public Key for Reality security layer"), value: vlessRealityPublicKey, placeholder: String(localized: "Public Key", comment: "Public Key for Reality security layer"), key: .vlessRealityPublicKey))
                tlsRows.append(.text(label: String(localized: "Short ID", comment: "Short ID for Reality security layer"), value: vlessRealityShortId, placeholder: String(localized: "Short ID", comment: "Short ID for Reality security layer"), key: .vlessRealityShortId))
                tlsRows.append(.selection(label: String(localized: "Fingerprint"), value: vlessFingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .vlessFingerprint))
            }
            // With detach on, the main TLS only secures the upload leg; label it to pair with the "TLS (Download)" section.
            let tlsTitle = (vlessTransport == "xhttp" && vlessXHTTPDownloadEnabled)
                ? String(localized: "TLS (Upload)") : String(localized: "TLS")
            sections.append((tlsTitle, tlsRows))
        } else if isNowhere {
            sections.append((String(localized: "TLS"), [
                .text(label: String(localized: "SNI"), value: nowhereSNI, placeholder: String(localized: "SNI"), key: .nowhereSNI),
                .text(label: String(localized: "ALPN"), value: nowhereALPN, placeholder: String(localized: "ALPN"), key: .nowhereALPN),
            ]))
        } else if isTrojan {
            var trojanRows: [RowType] = [
                .text(label: String(localized: "SNI"), value: trojanSNI, placeholder: String(localized: "SNI"), key: .trojanSNI),
                .text(label: String(localized: "ALPN"), value: trojanALPN, placeholder: String(localized: "h2,http/1.1"), key: .trojanALPN),
                .toggle(label: String(localized: "Enable ECH"), isOn: trojanECHEnabled, key: .trojanECHEnabled),
            ]
            if trojanECHEnabled {
                trojanRows.append(.text(label: String(localized: "ECH Config"), value: trojanECH, placeholder: String(localized: "Base64"), key: .trojanECH))
            }
            trojanRows.append(.selection(label: String(localized: "Fingerprint"), value: trojanFingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .trojanFingerprint))
            sections.append((String(localized: "TLS"), trojanRows))
        } else if isAnyTLS {
            var anytlsRows: [RowType] = [
                .text(label: String(localized: "SNI"), value: anytlsSNI, placeholder: String(localized: "SNI"), key: .anytlsSNI),
                .text(label: String(localized: "ALPN"), value: anytlsALPN, placeholder: String(localized: "h2,http/1.1"), key: .anytlsALPN),
                .toggle(label: String(localized: "Enable ECH"), isOn: anytlsECHEnabled, key: .anytlsECHEnabled),
            ]
            if anytlsECHEnabled {
                anytlsRows.append(.text(label: String(localized: "ECH Config"), value: anytlsECH, placeholder: String(localized: "Base64"), key: .anytlsECH))
            }
            anytlsRows.append(.selection(label: String(localized: "Fingerprint"), value: anytlsFingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .anytlsFingerprint))
            sections.append((String(localized: "TLS"), anytlsRows))
        } else if isHysteria {
            var hysteriaRows: [RowType] = [
                .text(label: String(localized: "SNI"), value: hysteriaSNI, placeholder: String(localized: "SNI"), key: .hysteriaSNI),
            ]
            sections.append((nil, hysteriaRows))
        }

        if isVLESS && vlessTransport == "xhttp" {
            var detachRows: [RowType] = [
                .toggle(label: String(localized: "Detached Download"), isOn: vlessXHTTPDownloadEnabled, key: .vlessXHTTPDownloadEnabled),
            ]
            if vlessXHTTPDownloadEnabled {
                detachRows.append(.text(label: String(localized: "Address"), value: vlessXHTTPDownloadAddress, placeholder: String(localized: "Address"), key: .vlessXHTTPDownloadAddress))
                detachRows.append(.text(label: String(localized: "Port"), value: vlessXHTTPDownloadPort, placeholder: "443", key: .vlessXHTTPDownloadPort))
            }
            sections.append((nil, detachRows))

            if vlessXHTTPDownloadEnabled {
                var downloadRows: [RowType] = [
                    .selection(label: String(localized: "Security", comment: "Security for VLESS protocol"), value: downloadSecurityDisplayValue, options: [
                        (String(localized: "None"), "none"),
                        ("TLS", "tls"),
                        ("Reality", "reality"),
                    ], key: .vlessXHTTPDownloadSecurity),
                ]
                if vlessXHTTPDownloadSecurity == "tls" {
                    downloadRows.append(.text(label: String(localized: "SNI"), value: vlessXHTTPDownloadTLSSNI, placeholder: String(localized: "SNI"), key: .vlessXHTTPDownloadTLSSNI))
                    downloadRows.append(.text(label: String(localized: "ALPN"), value: vlessXHTTPDownloadTLSALPN, placeholder: String(localized: "h2,http/1.1"), key: .vlessXHTTPDownloadTLSALPN))
                    downloadRows.append(.selection(label: String(localized: "Fingerprint"), value: vlessXHTTPDownloadFingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .vlessXHTTPDownloadFingerprint))
                }
                if vlessXHTTPDownloadSecurity == "reality" {
                    downloadRows.append(.text(label: String(localized: "SNI"), value: vlessXHTTPDownloadRealitySNI, placeholder: String(localized: "SNI"), key: .vlessXHTTPDownloadRealitySNI))
                    downloadRows.append(.text(label: String(localized: "Public Key", comment: "Public Key for Reality security layer"), value: vlessXHTTPDownloadRealityPublicKey, placeholder: String(localized: "Public Key", comment: "Public Key for Reality security layer"), key: .vlessXHTTPDownloadRealityPublicKey))
                    downloadRows.append(.text(label: String(localized: "Short ID", comment: "Short ID for Reality security layer"), value: vlessXHTTPDownloadRealityShortId, placeholder: String(localized: "Short ID", comment: "Short ID for Reality security layer"), key: .vlessXHTTPDownloadRealityShortId))
                    downloadRows.append(.selection(label: String(localized: "Fingerprint"), value: vlessXHTTPDownloadFingerprint.displayName, options: TLSFingerprint.allCases.map { ($0.displayName, $0.rawValue) }, key: .vlessXHTTPDownloadFingerprint))
                }
                downloadRows.append(.text(label: String(localized: "Host"), value: vlessXHTTPDownloadHost, placeholder: String(localized: "Host"), key: .vlessXHTTPDownloadHost))
                downloadRows.append(.text(label: String(localized: "Path"), value: vlessXHTTPDownloadPath, placeholder: String(localized: "Path"), key: .vlessXHTTPDownloadPath))
                sections.append((String(localized: "TLS (Download)"), downloadRows))
            }
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
        switch vlessTransport {
        case "tcp": "TCP"
        case "ws": "WebSocket"
        case "httpupgrade": "HTTPUpgrade"
        case "grpc": "gRPC"
        case "xhttp": "XHTTP"
        default: vlessTransport
        }
    }

    private var grpcModeDisplayValue: String {
        switch vlessGRPCMode {
        case "gun": "Gun"
        case "multi": "Multi"
        default: vlessGRPCMode
        }
    }

    private var flowDisplayValue: String {
        switch vlessFlow {
        case "xtls-rprx-vision": "Vision"
        default: String(localized: "None")
        }
    }

    private var xhttpModeDisplayValue: String {
        switch vlessXHTTPMode {
        case "auto": String(localized: "Auto")
        case "packet-up": "Packet Up"
        case "stream-up": "Stream Up"
        case "stream-one": "Stream One"
        default: vlessXHTTPMode
        }
    }

    private var securityDisplayValue: String {
        switch vlessSecurity {
        case "none": String(localized: "None")
        case "tls": "TLS"
        case "reality": "Reality"
        default: vlessSecurity
        }
    }

    private var downloadSecurityDisplayValue: String {
        switch vlessXHTTPDownloadSecurity {
        case "none": String(localized: "None")
        case "tls": "TLS"
        case "reality": "Reality"
        default: vlessXHTTPDownloadSecurity
        }
    }

    private var isValid: Bool {
        guard !name.isEmpty, !serverAddress.isEmpty, UInt16(serverPort) != nil else { return false }
        if isVLESS {
            guard UUID(uuidString: vlessUUID) != nil,
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
                && nowhereKey.utf8.count <= 255
                && nowhereSpec.utf8.count <= 255
                && nowhereALPN.utf8.count <= 255
        }
        if isTrojan { return !trojanPassword.isEmpty }
        if isAnyTLS { return !anytlsPassword.isEmpty }
        if isShadowsocks { return !ssPassword.isEmpty }
        if isSOCKS5 { return true }
        if isSudoku {
            guard !sudokuKey.isEmpty else { return false }
            guard let min = Int(sudokuPaddingMinText), let max = Int(sudokuPaddingMaxText) else { return false }
            return (0...100).contains(min) && min <= max && max <= 100
        }
        if isNaive { return !naiveUsername.isEmpty && !naivePassword.isEmpty }
        return false
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
        let row = formSections[indexPath.section].rows[indexPath.row]
        let cell = tableView.dequeueReusableCell(withIdentifier: "cell", for: indexPath)
        cell.accessoryType = .none
        cell.accessoryView = nil

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

        case .selection(let label, let value, _, _, let systemImage):
            var content = cell.defaultContentConfiguration()
            content.text = label
            content.image = systemImage.flatMap(UIImage.init(systemName:))
            content.secondaryText = value
            content.secondaryTextProperties.color = .systemBlue
            cell.contentConfiguration = content
            cell.accessoryType = .disclosureIndicator

        case .toggle(let label, let isOn, _, let systemImage):
            var content = cell.defaultContentConfiguration()
            content.text = label
            content.image = systemImage.flatMap(UIImage.init(systemName:))
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

        case .selection(_, _, let options, let key, _):
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

        case .toggle(_, let isOn, let key, _):
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
        case .outboundProtocol:
            if let proto = OutboundProtocol(rawValue: value) {
                selectedProtocol = proto
            }
        case .vlessUUID: vlessUUID = value
        case .vlessEncryption: vlessEncryption = value
        case .vlessTransport: vlessTransport = value
        case .vlessFlow: vlessFlow = value
        case .vlessSecurity: vlessSecurity = value
        case .vlessWebSocketHost: vlessWebSocketHost = value
        case .vlessWebSocketPath: vlessWebSocketPath = value
        case .vlessHTTPUpgradeHost: vlessHTTPUpgradeHost = value
        case .vlessHTTPUpgradePath: vlessHTTPUpgradePath = value
        case .vlessGRPCServiceName: vlessGRPCServiceName = value
        case .vlessGRPCAuthority: vlessGRPCAuthority = value
        case .vlessGRPCMode: vlessGRPCMode = value
        case .vlessGRPCUserAgent: vlessGRPCUserAgent = value
        case .vlessXHTTPHost: vlessXHTTPHost = value
        case .vlessXHTTPPath: vlessXHTTPPath = value
        case .vlessXHTTPMode: vlessXHTTPMode = value
        case .vlessTLSSNI: vlessTLSSNI = value
        case .vlessTLSALPN: vlessTLSALPN = value
        case .vlessTLSECHEnabled: vlessTLSECHEnabled = value == "true"
        case .vlessTLSECH: vlessTLSECH = value
        case .vlessRealitySNI: vlessRealitySNI = value
        case .vlessRealityPublicKey: vlessRealityPublicKey = value
        case .vlessRealityShortId: vlessRealityShortId = value
        case .vlessFingerprint:
            if let fingerprint = TLSFingerprint(rawValue: value) { vlessFingerprint = fingerprint }
        case .vlessXHTTPDownloadEnabled: vlessXHTTPDownloadEnabled = value == "true"
        case .vlessXHTTPDownloadAddress: vlessXHTTPDownloadAddress = value
        case .vlessXHTTPDownloadPort: vlessXHTTPDownloadPort = value
        case .vlessXHTTPDownloadSecurity: vlessXHTTPDownloadSecurity = value
        case .vlessXHTTPDownloadTLSSNI: vlessXHTTPDownloadTLSSNI = value
        case .vlessXHTTPDownloadTLSALPN: vlessXHTTPDownloadTLSALPN = value
        case .vlessXHTTPDownloadFingerprint:
            if let fingerprint = TLSFingerprint(rawValue: value) { vlessXHTTPDownloadFingerprint = fingerprint }
        case .vlessXHTTPDownloadRealitySNI: vlessXHTTPDownloadRealitySNI = value
        case .vlessXHTTPDownloadRealityPublicKey: vlessXHTTPDownloadRealityPublicKey = value
        case .vlessXHTTPDownloadRealityShortId: vlessXHTTPDownloadRealityShortId = value
        case .vlessXHTTPDownloadHost: vlessXHTTPDownloadHost = value
        case .vlessXHTTPDownloadPath: vlessXHTTPDownloadPath = value
        case .hysteriaPassword: hysteriaPassword = value
        case .hysteriaCC:
            if let congestionControl = HysteriaCongestionControl(rawValue: value) { hysteriaCC = congestionControl }
        case .hysteriaUploadMbps: hysteriaUploadMbpsText = value
        case .hysteriaDownloadMbps: hysteriaDownloadMbpsText = value
        case .hysteriaPorts: hysteriaPortsSpec = value
        case .hysteriaHopInterval: hysteriaHopIntervalText = value
        case .hysteriaSNI: hysteriaSNI = value
        case .nowhereKey: nowhereKey = value
        case .nowhereSpec: nowhereSpec = value
        case .nowhereNetwork:
            if let network = NowhereNetwork(rawValue: value) { nowhereNetwork = network }
        case .nowherePoolEnabled:
            if value == "true" {
                nowherePool = NowherePool.sliderRange.contains(nowhereLastPool)
                    ? nowhereLastPool : NowherePool.enabledDefault
            } else {
                if nowherePool > 0 { nowhereLastPool = nowherePool }
                nowherePool = 0
            }
        case .nowherePool:
            if let count = Int(value), NowherePool.sliderRange.contains(count) {
                nowherePool = count
                nowhereLastPool = count
            }
        case .nowhereSNI: nowhereSNI = value
        case .nowhereALPN: nowhereALPN = value
        case .trojanPassword: trojanPassword = value
        case .trojanSNI: trojanSNI = value
        case .trojanALPN: trojanALPN = value
        case .trojanECHEnabled: trojanECHEnabled = value == "true"
        case .trojanECH: trojanECH = value
        case .trojanFingerprint:
            if let fingerprint = TLSFingerprint(rawValue: value) { trojanFingerprint = fingerprint }
        case .anytlsPassword: anytlsPassword = value
        case .anytlsSNI: anytlsSNI = value
        case .anytlsALPN: anytlsALPN = value
        case .anytlsECHEnabled: anytlsECHEnabled = value == "true"
        case .anytlsECH: anytlsECH = value
        case .anytlsFingerprint:
            if let fingerprint = TLSFingerprint(rawValue: value) { anytlsFingerprint = fingerprint }
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
        if case .vless(let vlessUUID, let vlessEncryption, let vlessFlow, _, _) = configuration.outbound {
            self.vlessUUID = vlessUUID.uuidString
            self.vlessEncryption = vlessEncryption
            self.vlessFlow = vlessFlow ?? ""
        } else {
            vlessUUID = configuration.id.uuidString
            vlessEncryption = "none"
            vlessFlow = ""
        }
        if isVLESS {
            vlessTransport = configuration.xrayTransportLayer.tag
            vlessSecurity = configuration.xraySecurityLayer.tag

            if case .ws(let ws) = configuration.xrayTransportLayer {
                vlessWebSocketHost = ws.host
                vlessWebSocketPath = ws.path
            }
            if case .httpUpgrade(let httpUpgrade) = configuration.xrayTransportLayer {
                vlessHTTPUpgradeHost = httpUpgrade.host
                vlessHTTPUpgradePath = httpUpgrade.path
            }
            if case .grpc(let grpc) = configuration.xrayTransportLayer {
                vlessGRPCServiceName = grpc.serviceName
                vlessGRPCAuthority = grpc.authority
                vlessGRPCMode = grpc.multiMode ? "multi" : "gun"
                vlessGRPCUserAgent = grpc.userAgent
            }
            if case .xhttp(let xhttp) = configuration.xrayTransportLayer {
                vlessXHTTPHost = xhttp.host
                vlessXHTTPPath = xhttp.path
                vlessXHTTPMode = xhttp.mode.rawValue
                vlessXHTTPExtra = xhttp.encodedExtra
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
            if case .tls(let tls) = configuration.xraySecurityLayer {
                vlessTLSSNI = tls.serverName
                vlessTLSALPN = tls.alpn?.joined(separator: ",") ?? ""
                vlessFingerprint = tls.fingerprint
                vlessTLSECHEnabled = tls.echEnabled
                vlessTLSECH = tls.echConfig ?? ""
            }
            if case .reality(let reality) = configuration.xraySecurityLayer {
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
        case .nowhere(let key, let spec, let net, let pool, let tls):
            nowhereKey = key
            nowhereSpec = spec ?? ""
            nowhereNetwork = net
            nowherePool = pool
            if pool > 0 { nowhereLastPool = pool }
            nowhereSNI = tls.serverName
            nowhereALPN = tls.alpn?.first ?? ""
        case .trojan(let password, let tls):
            trojanPassword = password
            trojanSNI = tls.serverName
            trojanALPN = tls.alpn?.joined(separator: ",") ?? ""
            trojanECHEnabled = tls.echEnabled
            trojanECH = tls.echConfig ?? ""
            trojanFingerprint = tls.fingerprint
        case .anytls(let password, _, _, _, let tls):
            anytlsPassword = password
            anytlsSNI = tls.serverName
            anytlsALPN = tls.alpn?.joined(separator: ",") ?? ""
            anytlsECHEnabled = tls.echEnabled
            anytlsECH = tls.echConfig ?? ""
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

    /// Keys must match what `XHTTPConfiguration.parse` reads back. Returns nil when detach is off or address/port are missing.
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

    private func save() {
        guard let port = UInt16(serverPort) else { return }
        let parsedUUID: UUID
        if isHysteria || isNowhere || isTrojan || isAnyTLS || isShadowsocks || isSOCKS5 || isSudoku || isNaive {
            parsedUUID = existingConfiguration?.id ?? UUID()
        } else {
            guard let parsed = UUID(uuidString: vlessUUID) else { return }
            parsedUUID = parsed
        }

        var vlessTLSConfiguration: TLSConfiguration?
        if isVLESSTLS {
            let sni = vlessTLSSNI.isEmpty ? serverAddress : vlessTLSSNI
            let alpn: [String]? = vlessTLSALPN.isEmpty ? nil : vlessTLSALPN.split(separator: ",").map { String($0) }
            let ech = vlessTLSECH.trimmingCharacters(in: .whitespacesAndNewlines)
            vlessTLSConfiguration = TLSConfiguration(serverName: sni, alpn: alpn, echEnabled: vlessTLSECHEnabled, echConfig: vlessTLSECHEnabled && !ech.isEmpty ? ech : nil, fingerprint: vlessFingerprint)
        }

        var vlessRealityConfiguration: RealityConfiguration?
        if isVLESSReality {
            guard let publicKey = Data(base64URLEncoded: vlessRealityPublicKey) else { return }
            let shortId = Data(hexString: vlessRealityShortId) ?? Data()
            vlessRealityConfiguration = RealityConfiguration(serverName: vlessRealitySNI, publicKey: publicKey, shortId: shortId, fingerprint: vlessFingerprint)
        }

        var vlessWebSocketConfiguration: WebSocketConfiguration?
        if vlessTransport == "ws" {
            vlessWebSocketConfiguration = WebSocketConfiguration(host: vlessWebSocketHost.isEmpty ? serverAddress : vlessWebSocketHost, path: vlessWebSocketPath.isEmpty ? "/" : vlessWebSocketPath)
        }

        var vlessHTTPUpgradeConfiguration: HTTPUpgradeConfiguration?
        if vlessTransport == "httpupgrade" {
            vlessHTTPUpgradeConfiguration = HTTPUpgradeConfiguration(host: vlessHTTPUpgradeHost.isEmpty ? serverAddress : vlessHTTPUpgradeHost, path: vlessHTTPUpgradePath.isEmpty ? "/" : vlessHTTPUpgradePath)
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

        var vlessXHTTPConfiguration: XHTTPConfiguration?
        if vlessTransport == "xhttp" {
            let host = vlessXHTTPHost.isEmpty ? serverAddress : vlessXHTTPHost
            let mode = XHTTPMode(rawValue: vlessXHTTPMode) ?? .auto
            var parameters: [String: String] = ["host": host, "path": vlessXHTTPPath, "mode": mode.rawValue]
            // Merge advanced fields (vlessXHTTPExtra) with the detached download source so neither clobbers the other.
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
                parameters["extra"] = json
            }
            vlessXHTTPConfiguration = XHTTPConfiguration.parse(from: parameters, serverAddress: serverAddress)
        }

        let bareAddress = serverAddress.hasPrefix("[") && serverAddress.hasSuffix("]")
            ? String(serverAddress.dropFirst().dropLast()) : serverAddress

        let outbound: Outbound
        switch selectedProtocol {
        case .vless:
            let vlessXrayTransportLayer: XrayTransportLayer
            if let vlessWebSocketConfiguration { vlessXrayTransportLayer = .ws(vlessWebSocketConfiguration) }
            else if let vlessHTTPUpgradeConfiguration { vlessXrayTransportLayer = .httpUpgrade(vlessHTTPUpgradeConfiguration) }
            else if let vlessGRPCConfiguration { vlessXrayTransportLayer = .grpc(vlessGRPCConfiguration) }
            else if let vlessXHTTPConfiguration { vlessXrayTransportLayer = .xhttp(vlessXHTTPConfiguration) }
            else { vlessXrayTransportLayer = .tcp }

            let vlessXraySecurityLayer: XraySecurityLayer
            if let vlessRealityConfiguration { vlessXraySecurityLayer = .reality(vlessRealityConfiguration) }
            else if let vlessTLSConfiguration { vlessXraySecurityLayer = .tls(vlessTLSConfiguration) }
            else { vlessXraySecurityLayer = .none }

            outbound = .vless(
                uuid: parsedUUID,
                encryption: vlessEncryption,
                flow: vlessFlow.isEmpty ? nil : vlessFlow,
                transport: vlessXrayTransportLayer,
                security: vlessXraySecurityLayer
            )
        case .hysteria:
            let uploadMbps = HysteriaCongestionControl.clampUploadMbps(Int(hysteriaUploadMbpsText) ?? HysteriaCongestionControl.uploadMbpsDefault)
            let downloadMbps = HysteriaCongestionControl.clampDownloadMbps(Int(hysteriaDownloadMbpsText) ?? HysteriaCongestionControl.downloadMbpsDefault)
            let portHopping = HysteriaPortHopping.make(
                spec: hysteriaPortsSpec,
                intervalSeconds: Int(hysteriaHopIntervalText)
            )
            let sni = hysteriaSNI.isEmpty ? bareAddress : hysteriaSNI
            outbound = .hysteria(
                password: hysteriaPassword,
                congestionControl: hysteriaCC,
                uploadMbps: uploadMbps,
                downloadMbps: downloadMbps,
                portHopping: portHopping,
                sni: sni
            )
        case .nowhere:
            let sni = nowhereSNI.isEmpty ? bareAddress : nowhereSNI
            let spec = nowhereSpec.isEmpty ? nil : nowhereSpec
            let alpn: [String]? = nowhereALPN.isEmpty ? nil : [nowhereALPN]
            outbound = .nowhere(
                key: nowhereKey,
                spec: spec,
                net: nowhereNetwork,
                pool: nowherePool,
                tls: TLSConfiguration(serverName: sni, alpn: alpn)
            )
        case .trojan:
            let sni = trojanSNI.isEmpty ? bareAddress : trojanSNI
            let alpn: [String]? = trojanALPN.isEmpty ? nil : trojanALPN.split(separator: ",").map { String($0) }
            let ech = trojanECH.trimmingCharacters(in: .whitespacesAndNewlines)
            outbound = .trojan(
                password: trojanPassword,
                tls: TLSConfiguration(serverName: sni, alpn: alpn, echEnabled: trojanECHEnabled, echConfig: trojanECHEnabled && !ech.isEmpty ? ech : nil, fingerprint: trojanFingerprint)
            )
        case .anytls:
            let sni = anytlsSNI.isEmpty ? bareAddress : anytlsSNI
            let alpn: [String]? = anytlsALPN.isEmpty ? nil : anytlsALPN.split(separator: ",").map { String($0) }
            let idleCheckInterval: Int
            let idleTimeout: Int
            let minIdleSession: Int
            if let existing = existingConfiguration, case .anytls(_, let c, let t, let m, _) = existing.outbound {
                idleCheckInterval = c; idleTimeout = t; minIdleSession = m
            } else {
                idleCheckInterval = 30; idleTimeout = 30; minIdleSession = 0
            }
            let ech = anytlsECH.trimmingCharacters(in: .whitespacesAndNewlines)
            outbound = .anytls(
                password: anytlsPassword,
                idleCheckInterval: idleCheckInterval,
                idleTimeout: idleTimeout,
                minIdleSession: minIdleSession,
                tls: TLSConfiguration(serverName: sni, alpn: alpn, echEnabled: anytlsECHEnabled, echConfig: anytlsECHEnabled && !ech.isEmpty ? ech : nil, fingerprint: anytlsFingerprint)
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
