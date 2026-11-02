//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

nonisolated enum XHTTPMode: String, Codable, CaseIterable, Hashable {
    case auto
    case streamOne = "stream-one"
    case streamUp = "stream-up"
    case packetUp = "packet-up"

    var displayName: String {
        switch self {
        case .auto: return "Auto"
        case .streamOne: return "Stream One"
        case .streamUp: return "Stream Up"
        case .packetUp: return "Packet Up"
        }
    }
}

nonisolated enum XHTTPPlacement: String, Codable, Equatable, Hashable {
    case path
    case query
    case header
    case cookie
    case queryInHeader
    case body
}

nonisolated enum XHTTPPaddingMethod: String, Codable, Equatable, Hashable {
    case repeatX = "repeat-x"
    case tokenish
}

nonisolated struct XHTTPXMUXMultiplexerRange: Codable, Equatable, Hashable {
    var from: Int
    var to: Int

    static let zero = XHTTPXMUXMultiplexerRange(from: 0, to: 0)
    var isZero: Bool { from == 0 && to == 0 }
    
    func random() -> Int { to <= from ? from : Int.random(in: from..<to) }
    
    static func parse(_ value: Any?) -> XHTTPXMUXMultiplexerRange {
        switch value {
        case let i as Int:
            return XHTTPXMUXMultiplexerRange(from: i, to: i)
        case let d as [String: Any]:
            let f = d["from"] as? Int ?? 0
            let t = d["to"] as? Int ?? f
            return XHTTPXMUXMultiplexerRange(from: f, to: max(f, t))
        case let s as String:
            let trimmed = s.trimmingCharacters(in: .whitespaces)
            if let dash = trimmed.firstIndex(of: "-"), dash != trimmed.startIndex {
                let lo = trimmed[trimmed.startIndex..<dash].trimmingCharacters(in: .whitespaces)
                let hi = trimmed[trimmed.index(after: dash)...].trimmingCharacters(in: .whitespaces)
                if let f = Int(lo), let t = Int(hi) { return XHTTPXMUXMultiplexerRange(from: f, to: max(f, t)) }
            }
            if let v = Int(trimmed) { return XHTTPXMUXMultiplexerRange(from: v, to: v) }
            return .zero
        default:
            return .zero
        }
    }
    
    var jsonValue: Any { from == to ? from : "\(from)-\(to)" }
}

nonisolated struct XHTTPXMUXMultiplexerConfiguration: Codable, Equatable, Hashable {
    var maxConcurrency: XHTTPXMUXMultiplexerRange
    var maxConnections: XHTTPXMUXMultiplexerRange
    var cMaxReuseTimes: XHTTPXMUXMultiplexerRange
    var hMaxRequestTimes: XHTTPXMUXMultiplexerRange
    var hMaxReusableSecs: XHTTPXMUXMultiplexerRange
    var hKeepAlivePeriod: Int

    static let disabled = XHTTPXMUXMultiplexerConfiguration(
        maxConcurrency: .zero, maxConnections: .zero, cMaxReuseTimes: .zero,
        hMaxRequestTimes: .zero, hMaxReusableSecs: .zero, hKeepAlivePeriod: 0
    )
    
    static let connectionSpreadDefault = XHTTPXMUXMultiplexerConfiguration(
        maxConcurrency: .zero,
        maxConnections: XHTTPXMUXMultiplexerRange(from: 3, to: 3),
        cMaxReuseTimes: .zero,
        hMaxRequestTimes: XHTTPXMUXMultiplexerRange(from: 600, to: 900),
        hMaxReusableSecs: XHTTPXMUXMultiplexerRange(from: 1800, to: 3000),
        hKeepAlivePeriod: 0
    )
    
    var isEnabled: Bool {
        !(maxConcurrency.isZero && maxConnections.isZero && cMaxReuseTimes.isZero
          && hMaxRequestTimes.isZero && hMaxReusableSecs.isZero && hKeepAlivePeriod == 0)
    }
    
    static func parse(from json: [String: Any]) -> XHTTPXMUXMultiplexerConfiguration {
        XHTTPXMUXMultiplexerConfiguration(
            maxConcurrency: XHTTPXMUXMultiplexerRange.parse(json["maxConcurrency"]),
            maxConnections: XHTTPXMUXMultiplexerRange.parse(json["maxConnections"]),
            cMaxReuseTimes: XHTTPXMUXMultiplexerRange.parse(json["cMaxReuseTimes"]),
            hMaxRequestTimes: XHTTPXMUXMultiplexerRange.parse(json["hMaxRequestTimes"]),
            hMaxReusableSecs: XHTTPXMUXMultiplexerRange.parse(json["hMaxReusableSecs"]),
            hKeepAlivePeriod: (json["hKeepAlivePeriod"] as? Int) ?? 0
        )
    }
    
    var jsonObject: [String: Any] {
        var json: [String: Any] = [:]
        if !maxConcurrency.isZero { json["maxConcurrency"] = maxConcurrency.jsonValue }
        if !maxConnections.isZero { json["maxConnections"] = maxConnections.jsonValue }
        if !cMaxReuseTimes.isZero { json["cMaxReuseTimes"] = cMaxReuseTimes.jsonValue }
        if !hMaxRequestTimes.isZero { json["hMaxRequestTimes"] = hMaxRequestTimes.jsonValue }
        if !hMaxReusableSecs.isZero { json["hMaxReusableSecs"] = hMaxReusableSecs.jsonValue }
        if hKeepAlivePeriod != 0 { json["hKeepAlivePeriod"] = hKeepAlivePeriod }
        return json
    }
}

nonisolated struct XHTTPConfiguration: Codable, Equatable, Hashable {
    let host: String
    let path: String
    let mode: XHTTPMode
    let headers: [String: String]
    let noGRPCHeader: Bool
    let scMaxEachPostBytes: Int
    let scMinPostsIntervalMs: Int
    
    let xPaddingBytesFrom: Int
    let xPaddingBytesTo: Int
    let xPaddingObfsMode: Bool
    let xPaddingKey: String
    let xPaddingHeader: String
    let xPaddingPlacement: XHTTPPlacement
    let xPaddingMethod: XHTTPPaddingMethod
    
    let uplinkHTTPMethod: String
    
    let sessionIDPlacement: XHTTPPlacement
    let sessionIDKey: String
    let seqPlacement: XHTTPPlacement
    let seqKey: String
    
    let sessionIDTable: String
    let sessionIDLengthFrom: Int
    let sessionIDLengthTo: Int
    
    let uplinkDataPlacement: XHTTPPlacement
    let uplinkDataKey: String
    let uplinkChunkSize: Int
    
    private let _downloadSettings: XHTTPDownloadSettingsBox?
    
    var downloadSettings: XHTTPDownloadSettings? { _downloadSettings?.value }
    
    let xmux: XHTTPXMUXMultiplexerConfiguration?

    init(
        host: String,
        path: String = "/",
        mode: XHTTPMode = .auto,
        headers: [String: String] = [:],
        noGRPCHeader: Bool = false,
        scMaxEachPostBytes: Int = 1_000_000,
        scMinPostsIntervalMs: Int = 30,
        xPaddingBytesFrom: Int = 100,
        xPaddingBytesTo: Int = 1000,
        xPaddingObfsMode: Bool = false,
        xPaddingKey: String = "x_padding",
        xPaddingHeader: String = "X-Padding",
        xPaddingPlacement: XHTTPPlacement = .queryInHeader,
        xPaddingMethod: XHTTPPaddingMethod = .repeatX,
        uplinkHTTPMethod: String = "POST",
        sessionIDPlacement: XHTTPPlacement = .path,
        sessionIDKey: String = "",
        seqPlacement: XHTTPPlacement = .path,
        seqKey: String = "",
        sessionIDTable: String = "",
        sessionIDLengthFrom: Int = 0,
        sessionIDLengthTo: Int = 0,
        uplinkDataPlacement: XHTTPPlacement = .body,
        uplinkDataKey: String = "",
        uplinkChunkSize: Int = 0,
        downloadSettings: XHTTPDownloadSettings? = nil,
        xmux: XHTTPXMUXMultiplexerConfiguration? = nil
    ) {
        self.host = host
        self.path = path
        self.mode = mode
        self.headers = headers
        self.noGRPCHeader = noGRPCHeader
        self.scMaxEachPostBytes = scMaxEachPostBytes
        self.scMinPostsIntervalMs = scMinPostsIntervalMs
        self.xPaddingBytesFrom = xPaddingBytesFrom
        self.xPaddingBytesTo = xPaddingBytesTo
        self.xPaddingObfsMode = xPaddingObfsMode
        self.xPaddingKey = xPaddingKey
        self.xPaddingHeader = xPaddingHeader
        self.xPaddingPlacement = xPaddingPlacement
        self.xPaddingMethod = xPaddingMethod
        self.uplinkHTTPMethod = uplinkHTTPMethod
        self.sessionIDPlacement = sessionIDPlacement
        self.sessionIDKey = sessionIDKey
        self.seqPlacement = seqPlacement
        self.seqKey = seqKey
        self.sessionIDTable = sessionIDTable
        self.sessionIDLengthFrom = sessionIDLengthFrom
        self.sessionIDLengthTo = sessionIDLengthTo
        self.uplinkDataPlacement = uplinkDataPlacement
        self.uplinkDataKey = uplinkDataKey
        self.uplinkChunkSize = uplinkChunkSize
        self._downloadSettings = downloadSettings.map(XHTTPDownloadSettingsBox.init)
        self.xmux = xmux
    }
    
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        host = try c.decode(String.self, forKey: .host)
        path = try c.decode(String.self, forKey: .path)
        mode = try c.decode(XHTTPMode.self, forKey: .mode)
        headers = try c.decode([String: String].self, forKey: .headers)
        noGRPCHeader = try c.decode(Bool.self, forKey: .noGRPCHeader)
        scMaxEachPostBytes = try c.decode(Int.self, forKey: .scMaxEachPostBytes)
        scMinPostsIntervalMs = try c.decode(Int.self, forKey: .scMinPostsIntervalMs)
        xPaddingBytesFrom = try c.decodeIfPresent(Int.self, forKey: .xPaddingBytesFrom) ?? 100
        xPaddingBytesTo = try c.decodeIfPresent(Int.self, forKey: .xPaddingBytesTo) ?? 1000
        xPaddingObfsMode = try c.decodeIfPresent(Bool.self, forKey: .xPaddingObfsMode) ?? false
        xPaddingKey = try c.decodeIfPresent(String.self, forKey: .xPaddingKey) ?? "x_padding"
        xPaddingHeader = try c.decodeIfPresent(String.self, forKey: .xPaddingHeader) ?? "X-Padding"
        xPaddingPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .xPaddingPlacement) ?? .queryInHeader
        xPaddingMethod = try c.decodeIfPresent(XHTTPPaddingMethod.self, forKey: .xPaddingMethod) ?? .repeatX
        uplinkHTTPMethod = try c.decodeIfPresent(String.self, forKey: .uplinkHTTPMethod) ?? "POST"
        sessionIDPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .sessionIDPlacement) ?? .path
        sessionIDKey = try c.decodeIfPresent(String.self, forKey: .sessionIDKey) ?? ""
        seqPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .seqPlacement) ?? .path
        seqKey = try c.decodeIfPresent(String.self, forKey: .seqKey) ?? ""
        sessionIDTable = try c.decodeIfPresent(String.self, forKey: .sessionIDTable) ?? ""
        sessionIDLengthFrom = try c.decodeIfPresent(Int.self, forKey: .sessionIDLengthFrom) ?? 0
        sessionIDLengthTo = try c.decodeIfPresent(Int.self, forKey: .sessionIDLengthTo) ?? 0
        uplinkDataPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .uplinkDataPlacement) ?? .body
        uplinkDataKey = try c.decodeIfPresent(String.self, forKey: .uplinkDataKey) ?? ""
        uplinkChunkSize = try c.decodeIfPresent(Int.self, forKey: .uplinkChunkSize) ?? 0
        _downloadSettings = try c.decodeIfPresent(XHTTPDownloadSettingsBox.self, forKey: ._downloadSettings)
        xmux = try c.decodeIfPresent(XHTTPXMUXMultiplexerConfiguration.self, forKey: .xmux)
    }
    
    var effectiveXMUX: XHTTPXMUXMultiplexerConfiguration {
        if let xmux, xmux.isEnabled { return xmux }
        return .connectionSpreadDefault
    }
    
    var normalizedPath: String {
        let pathOnly = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
        var p = pathOnly
        if !p.hasPrefix("/") {
            p = "/" + p
        }
        if sessionIDPlacement == .path || seqPlacement == .path {
            if !p.hasSuffix("/") {
                p = p + "/"
            }
        }
        return p
    }
    
    var normalizedQuery: String {
        let parts = path.split(separator: "?", maxSplits: 1)
        if parts.count > 1 {
            return String(parts[1])
        }
        return ""
    }
    
    var normalizedSessionIDKey: String {
        if !sessionIDKey.isEmpty { return sessionIDKey }
        switch sessionIDPlacement {
        case .header: return "X-Session"
        case .cookie, .query: return "x_session"
        default: return ""
        }
    }
    
    var normalizedSeqKey: String {
        if !seqKey.isEmpty { return seqKey }
        switch seqPlacement {
        case .header: return "X-Seq"
        case .cookie, .query: return "x_seq"
        default: return ""
        }
    }
    
    nonisolated static let predefinedSessionIDTables: [String: String] = [
        "ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "BASE36": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "Base62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "HEX": "0123456789ABCDEF",
        "alphabet": "abcdefghijklmnopqrstuvwxyz",
        "base36": "0123456789abcdefghijklmnopqrstuvwxyz",
        "hex": "0123456789abcdef",
        "number": "0123456789",
    ]
    
    nonisolated func generateSessionID() -> String {
        var table = sessionIDTable
        if let predefined = XHTTPConfiguration.predefinedSessionIDTables[table] {
            table = predefined
        }
        let length: Int
        if sessionIDLengthTo <= sessionIDLengthFrom {
            length = sessionIDLengthFrom
        } else {
            length = Int.random(in: sessionIDLengthFrom..<sessionIDLengthTo)
        }
        guard !table.isEmpty, length > 0 else {
            return UUID().uuidString.lowercased()
        }
        let characters = Array(table)
        var id = ""
        id.reserveCapacity(length)
        for _ in 0..<length {
            id.append(characters[Int.random(in: 0..<characters.count)])
        }
        return id
    }

    func generatePadding() -> String {
        let lower = max(0, xPaddingBytesFrom)
        let length = Int.random(in: lower...max(lower, xPaddingBytesTo))
        switch xPaddingMethod {
        case .repeatX:
            return String(repeating: "X", count: length)
        case .tokenish:
            return generateTokenishPadding(targetBytes: length)
        }
    }
    
    private func generateTokenishPadding(targetBytes: Int) -> String {
        let charset = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        let n = max(1, Int(ceil(Double(targetBytes) / 0.8)))
        var characters = (0..<n).map { _ in charset[Int.random(in: 0..<charset.count)] }
        var adjust: Character = "X"
        for _ in 0..<150 {
            let diff = HPACKHuffman.encodedByteLength(String(characters)) - targetBytes
            if abs(diff) <= 2 { break }
            if diff < 0 {
                characters.append(adjust)
                adjust = (adjust == "X") ? "Z" : "X"
            } else if characters.count > 1 {
                characters.removeLast()
            } else {
                break
            }
        }
        return String(characters)
    }
    
    static func parse(from params: [String: String], serverAddress: String, tlsServerName: String? = nil, realityServerName: String? = nil) -> XHTTPConfiguration? {
        let host = params["host"] ?? tlsServerName ?? realityServerName ?? serverAddress
        let path = (params["path"] ?? "/").removingPercentEncoding ?? "/"
        let modeStr = params["mode"] ?? "auto"
        let mode = XHTTPMode(rawValue: modeStr) ?? .auto

        var extra: [String: Any] = [:]
        if let extraStr = params["extra"],
           let decoded = extraStr.removingPercentEncoding,
           let data = decoded.data(using: .utf8),
           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            extra = json
        }

        let downloadSettings = parseDownloadSettings(from: extra["downloadSettings"] as? [String: Any], parentExtra: extra)
        return build(host: host, path: path, mode: mode, extra: extra, downloadSettings: downloadSettings)
    }
    
    static func parse(fromJSON json: [String: Any], serverAddress: String, tlsServerName: String? = nil, realityServerName: String? = nil, downloadSettings: XHTTPDownloadSettings? = nil) -> XHTTPConfiguration {
        let host = (json["host"] as? String) ?? tlsServerName ?? realityServerName ?? serverAddress
        let path = (json["path"] as? String) ?? "/"
        let mode = XHTTPMode(rawValue: (json["mode"] as? String) ?? "auto") ?? .auto
        return build(host: host, path: path, mode: mode, extra: json, downloadSettings: downloadSettings)
    }
    
    static func parseDownloadSettings(from json: [String: Any]?, parentExtra: [String: Any] = [:]) -> XHTTPDownloadSettings? {
        guard let json else { return nil }
        guard let address = ((json["address"] as? String) ?? (json["server"] as? String)), !address.isEmpty else {
            return nil
        }
        let port: UInt16
        if let p = json["port"] as? Int, p > 0, p <= 65535 {
            port = UInt16(p)
        } else if let ps = json["port"] as? String, let p = UInt16(ps) {
            port = p
        } else {
            return nil
        }
        
        let securityRaw = (json["security"] as? String ?? "none").lowercased()
        var security = securityRaw.isEmpty ? "none" : securityRaw

        var tls: TLSConfiguration? = nil
        var reality: RealityConfiguration? = nil
        switch security {
        case "tls":
            tls = mapDownloadTLS(json["tlsSettings"] as? [String: Any], serverAddress: address)
        case "reality":
            guard let r = mapDownloadReality(json["realitySettings"] as? [String: Any], serverAddress: address) else {
                return nil
            }
            reality = r
        default:
            if json["security"] == nil,
               let sni = [json["servername"], json["serverName"], json["sni"]]
                   .compactMap({ $0 as? String })
                   .first(where: { !$0.isEmpty }) {
                security = "tls"
                tls = mapDownloadTLS(["serverName": sni], serverAddress: address)
            }
        }
        
        var mergedExtra = parentExtra
        mergedExtra.removeValue(forKey: "xmux")
        mergedExtra.removeValue(forKey: "downloadSettings")
        if let compactPath = json["path"] as? String, !compactPath.isEmpty { mergedExtra["path"] = compactPath }
        if let compactHost = json["host"] as? String, !compactHost.isEmpty { mergedExtra["host"] = compactHost }
        let ownXhttpJSON = (json["xhttpSettings"] as? [String: Any])
            ?? (json["splithttpSettings"] as? [String: Any])
            ?? [:]
        for (key, value) in ownXhttpJSON { mergedExtra[key] = value }
        let xhttp = parse(
            fromJSON: mergedExtra,
            serverAddress: address,
            tlsServerName: tls?.serverName,
            realityServerName: reality?.serverName
        )

        return XHTTPDownloadSettings(
            serverAddress: address,
            serverPort: port,
            security: security,
            tls: tls,
            reality: reality,
            xhttp: xhttp
        )
    }

    private static func mapDownloadTLS(_ json: [String: Any]?, serverAddress: String) -> TLSConfiguration {
        let serverName = (json?["serverName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? serverAddress
        var alpn: [String]? = nil
        if let arr = json?["alpn"] as? [String], !arr.isEmpty {
            alpn = arr
        } else if let s = json?["alpn"] as? String, !s.isEmpty {
            alpn = s.split(separator: ",").map(String.init)
        }
        let fingerprint = TLSFingerprint(linkValue: json?["fingerprint"] as? String)
        let ech = (json?["ech"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return TLSConfiguration(serverName: serverName, alpn: alpn, echConfig: ech, fingerprint: fingerprint)
    }
    
    private static func mapDownloadReality(_ json: [String: Any]?, serverAddress: String) -> RealityConfiguration? {
        guard let json, let publicKeyString = json["publicKey"] as? String, !publicKeyString.isEmpty else { return nil }
        guard let publicKey = (Data(base64URLEncoded: publicKeyString) ?? Data(base64Encoded: publicKeyString)),
              publicKey.count == 32 else { return nil }
        let serverName = (json["serverName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? serverAddress
        let shortId = Data(hexString: (json["shortId"] as? String) ?? "") ?? Data()
        let fp = TLSFingerprint(linkValue: json["fingerprint"] as? String)
        return RealityConfiguration(serverName: serverName, publicKey: publicKey, shortId: shortId, fingerprint: fp)
    }
    
    private static func build(host: String, path: String, mode: XHTTPMode, extra: [String: Any], downloadSettings: XHTTPDownloadSettings?) -> XHTTPConfiguration {
        var headers: [String: String] = [:]
        if let extraHeaders = extra["headers"] as? [String: String] {
            headers = extraHeaders
        }

        let noGRPCHeader = extra["noGRPCHeader"] as? Bool ?? false
        
        var scMaxEachPostBytes = 1_000_000
        if let range = extra["scMaxEachPostBytes"] as? [String: Any] {
            scMaxEachPostBytes = range["to"] as? Int ?? 1_000_000
        } else if let value = extra["scMaxEachPostBytes"] as? Int {
            scMaxEachPostBytes = value
        }
        
        var scMinPostsIntervalMs = 30
        if let range = extra["scMinPostsIntervalMs"] as? [String: Any] {
            scMinPostsIntervalMs = range["to"] as? Int ?? 30
        } else if let value = extra["scMinPostsIntervalMs"] as? Int {
            scMinPostsIntervalMs = value
        }
        
        var xPaddingFrom = 100
        var xPaddingTo = 1000
        let xPaddingRange = XHTTPXMUXMultiplexerRange.parse(extra["xPaddingBytes"])
        if !xPaddingRange.isZero {
            xPaddingFrom = xPaddingRange.from
            xPaddingTo = xPaddingRange.to
        }

        let xPaddingObfsMode = extra["xPaddingObfsMode"] as? Bool ?? false
        let xPaddingKey = extra["xPaddingKey"] as? String ?? "x_padding"
        let xPaddingHeader = extra["xPaddingHeader"] as? String ?? "X-Padding"
        let xPaddingPlacement = XHTTPPlacement(rawValue: extra["xPaddingPlacement"] as? String ?? "queryInHeader") ?? .queryInHeader
        let xPaddingMethod = XHTTPPaddingMethod(rawValue: extra["xPaddingMethod"] as? String ?? "repeat-x") ?? .repeatX

        let uplinkHTTPMethod = extra["uplinkHTTPMethod"] as? String ?? "POST"
        
        let sessionIDPlacementRaw = (extra["sessionIDPlacement"] ?? extra["sessionPlacement"]) as? String ?? "path"
        let sessionIDPlacement = XHTTPPlacement(rawValue: sessionIDPlacementRaw) ?? .path
        let sessionIDKey = (extra["sessionIDKey"] ?? extra["sessionKey"]) as? String ?? ""
        let seqPlacement = XHTTPPlacement(rawValue: extra["seqPlacement"] as? String ?? "path") ?? .path
        let seqKey = extra["seqKey"] as? String ?? ""

        let sessionIDTable = extra["sessionIDTable"] as? String ?? ""
        var sessionIDLengthFrom = 0
        var sessionIDLengthTo = 0
        if let range = extra["sessionIDLength"] as? [String: Any] {
            sessionIDLengthFrom = range["from"] as? Int ?? 0
            sessionIDLengthTo = range["to"] as? Int ?? 0
        } else if let value = extra["sessionIDLength"] as? Int {
            sessionIDLengthFrom = value
            sessionIDLengthTo = value
        }

        let uplinkDataPlacement = XHTTPPlacement(rawValue: extra["uplinkDataPlacement"] as? String ?? "body") ?? .body

        let defaultUplinkDataKey: String
        switch uplinkDataPlacement {
        case .header: defaultUplinkDataKey = "X-Data"
        case .cookie: defaultUplinkDataKey = "x_data"
        default: defaultUplinkDataKey = ""
        }
        let uplinkDataKey = extra["uplinkDataKey"] as? String ?? defaultUplinkDataKey

        let defaultUplinkChunkSize: Int
        switch uplinkDataPlacement {
        case .header: defaultUplinkChunkSize = 4096
        case .cookie: defaultUplinkChunkSize = 3072
        default: defaultUplinkChunkSize = 0
        }
        let uplinkChunkSize = extra["uplinkChunkSize"] as? Int ?? defaultUplinkChunkSize

        let xmux = (extra["xmux"] as? [String: Any]).map(XHTTPXMUXMultiplexerConfiguration.parse)

        return XHTTPConfiguration(
            host: host,
            path: path,
            mode: mode,
            headers: headers,
            noGRPCHeader: noGRPCHeader,
            scMaxEachPostBytes: scMaxEachPostBytes,
            scMinPostsIntervalMs: scMinPostsIntervalMs,
            xPaddingBytesFrom: xPaddingFrom,
            xPaddingBytesTo: xPaddingTo,
            xPaddingObfsMode: xPaddingObfsMode,
            xPaddingKey: xPaddingKey,
            xPaddingHeader: xPaddingHeader,
            xPaddingPlacement: xPaddingPlacement,
            xPaddingMethod: xPaddingMethod,
            uplinkHTTPMethod: uplinkHTTPMethod,
            sessionIDPlacement: sessionIDPlacement,
            sessionIDKey: sessionIDKey,
            seqPlacement: seqPlacement,
            seqKey: seqKey,
            sessionIDTable: sessionIDTable,
            sessionIDLengthFrom: sessionIDLengthFrom,
            sessionIDLengthTo: sessionIDLengthTo,
            uplinkDataPlacement: uplinkDataPlacement,
            uplinkDataKey: uplinkDataKey,
            uplinkChunkSize: uplinkChunkSize,
            downloadSettings: downloadSettings,
            xmux: xmux
        )
    }
}

// MARK: - Editor Export

nonisolated extension XHTTPConfiguration {
    var advancedExtraJSON: [String: Any] {
        var dictionary: [String: Any] = [:]

        if !headers.isEmpty { dictionary["headers"] = headers }
        if noGRPCHeader { dictionary["noGRPCHeader"] = true }
        if scMaxEachPostBytes != 1_000_000 { dictionary["scMaxEachPostBytes"] = scMaxEachPostBytes }
        if scMinPostsIntervalMs != 30 { dictionary["scMinPostsIntervalMs"] = scMinPostsIntervalMs }
        if xPaddingBytesFrom != 100 || xPaddingBytesTo != 1000 {
            dictionary["xPaddingBytes"] = ["from": xPaddingBytesFrom, "to": xPaddingBytesTo]
        }
        if xPaddingObfsMode { dictionary["xPaddingObfsMode"] = true }
        if xPaddingKey != "x_padding" { dictionary["xPaddingKey"] = xPaddingKey }
        if xPaddingHeader != "X-Padding" { dictionary["xPaddingHeader"] = xPaddingHeader }
        if xPaddingPlacement != .queryInHeader { dictionary["xPaddingPlacement"] = xPaddingPlacement.rawValue }
        if xPaddingMethod != .repeatX { dictionary["xPaddingMethod"] = xPaddingMethod.rawValue }
        if uplinkHTTPMethod != "POST" { dictionary["uplinkHTTPMethod"] = uplinkHTTPMethod }
        if sessionIDPlacement != .path { dictionary["sessionIDPlacement"] = sessionIDPlacement.rawValue }
        if !sessionIDKey.isEmpty { dictionary["sessionIDKey"] = sessionIDKey }
        if seqPlacement != .path { dictionary["seqPlacement"] = seqPlacement.rawValue }
        if !seqKey.isEmpty { dictionary["seqKey"] = seqKey }
        if !sessionIDTable.isEmpty { dictionary["sessionIDTable"] = sessionIDTable }
        if sessionIDLengthFrom != 0 || sessionIDLengthTo != 0 {
            dictionary["sessionIDLength"] = ["from": sessionIDLengthFrom, "to": sessionIDLengthTo]
        }
        if uplinkDataPlacement != .body { dictionary["uplinkDataPlacement"] = uplinkDataPlacement.rawValue }
        let defaultDataKey: String
        let defaultChunkSize: Int
        switch uplinkDataPlacement {
        case .header: defaultDataKey = "X-Data"; defaultChunkSize = 4096
        case .cookie: defaultDataKey = "x_data"; defaultChunkSize = 3072
        default: defaultDataKey = ""; defaultChunkSize = 0
        }
        if uplinkDataKey != defaultDataKey { dictionary["uplinkDataKey"] = uplinkDataKey }
        if uplinkChunkSize != defaultChunkSize { dictionary["uplinkChunkSize"] = uplinkChunkSize }
        if let xmux, xmux.isEnabled { dictionary["xmux"] = xmux.jsonObject }

        return dictionary
    }
    
    var encodedExtra: String {
        let dictionary = advancedExtraJSON
        guard !dictionary.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: dictionary, options: [.sortedKeys, .prettyPrinted]),
              let string = String(data: data, encoding: .utf8) else {
            return ""
        }
        return string
    }
}

// MARK: - XHTTP Download Settings (up/download detach)

nonisolated struct XHTTPDownloadSettings: Codable, Equatable, Hashable {
    let serverAddress: String
    let serverPort: UInt16
    let security: String
    let tls: TLSConfiguration?
    let reality: RealityConfiguration?
    let xhttp: XHTTPConfiguration

    init(serverAddress: String, serverPort: UInt16, security: String,
         tls: TLSConfiguration? = nil, reality: RealityConfiguration? = nil,
         xhttp: XHTTPConfiguration) {
        self.serverAddress = serverAddress
        self.serverPort = serverPort
        self.security = security
        self.tls = tls
        self.reality = reality
        self.xhttp = xhttp
    }
    
    var xraySecurityLayer: XraySecurityLayer {
        switch security {
        case "tls":     return tls.map(XraySecurityLayer.tls) ?? .none
        case "reality": return reality.map(XraySecurityLayer.reality) ?? .none
        default:        return .none
        }
    }
}

// MARK: - URL Export

nonisolated extension XHTTPConfiguration {
    var urlSettingsJSON: [String: Any] {
        var j: [String: Any] = ["host": host]
        if path != "/" { j["path"] = path }
        if mode != .auto { j["mode"] = mode.rawValue }
        if !headers.isEmpty { j["headers"] = headers }
        if noGRPCHeader { j["noGRPCHeader"] = true }
        return j
    }
    
    var urlExtraParam: String? {
        var extra = advancedExtraJSON
        if let downloadSettings { extra["downloadSettings"] = downloadSettings.urlDownloadJSON }
        guard !extra.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: extra, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return nil }
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+#")
        return json.addingPercentEncoding(withAllowedCharacters: allowed) ?? json
    }
}

nonisolated extension XHTTPDownloadSettings {
    var urlDownloadJSON: [String: Any] {
        var dl: [String: Any] = [
            "address": serverAddress,
            "port": Int(serverPort),
            "security": security,
        ]
        if let tls {
            var t: [String: Any] = [
                "serverName": tls.serverName,
                "fingerprint": tls.fingerprint.rawValue,
            ]
            if let alpn = tls.alpn, !alpn.isEmpty { t["alpn"] = alpn }
            dl["tlsSettings"] = t
        }
        if let reality {
            dl["realitySettings"] = [
                "serverName": reality.serverName,
                "publicKey": reality.publicKey.base64URLEncodedString(),
                "shortId": reality.shortId.hexEncodedString(),
                "fingerprint": reality.fingerprint.rawValue,
            ]
        }
        dl["xhttpSettings"] = xhttp.urlSettingsJSON
        return dl
    }
}

nonisolated final class XHTTPDownloadSettingsBox: Codable, Equatable, Hashable, Sendable {
    let value: XHTTPDownloadSettings

    init(_ value: XHTTPDownloadSettings) { self.value = value }

    init(from decoder: Decoder) throws {
        value = try XHTTPDownloadSettings(from: decoder)
    }

    func encode(to encoder: Encoder) throws {
        try value.encode(to: encoder)
    }

    static func == (lhs: XHTTPDownloadSettingsBox, rhs: XHTTPDownloadSettingsBox) -> Bool {
        lhs.value == rhs.value
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(value)
    }
}
