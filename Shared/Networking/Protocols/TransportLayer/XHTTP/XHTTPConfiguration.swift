//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

/// XHTTP transfer mode: how the upload and download legs map onto HTTP requests.
enum XHTTPMode: String, Codable, CaseIterable, Hashable {
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

/// Where XHTTP carries a piece of metadata or payload in the HTTP request.
enum XHTTPPlacement: String, Codable, Equatable, Hashable {
    case path
    case query
    case header
    case cookie
    case queryInHeader
    case body
}

/// How X-Padding filler is generated.
enum XHTTPPaddingMethod: String, Codable, Equatable, Hashable {
    case repeatX = "repeat-x"
    case tokenish
}

/// A `from`/`to` integer range; a single value when `from == to`.
struct XMUXRange: Codable, Equatable, Hashable {
    var from: Int
    var to: Int

    static let zero = XMUXRange(from: 0, to: 0)
    var isZero: Bool { from == 0 && to == 0 }

    /// Random value in `[from, to)` (upper bound exclusive); `to <= from` collapses to `from`.
    func random() -> Int { to <= from ? from : Int.random(in: from..<to) }

    /// Parses an int, `{"from":a,"to":b}` object, `"a-b"`/`"a"` string, or nil → `.zero`.
    static func parse(_ value: Any?) -> XMUXRange {
        switch value {
        case let i as Int:
            return XMUXRange(from: i, to: i)
        case let d as [String: Any]:
            let f = d["from"] as? Int ?? 0
            let t = d["to"] as? Int ?? f
            return XMUXRange(from: f, to: max(f, t))
        case let s as String:
            let trimmed = s.trimmingCharacters(in: .whitespaces)
            if let dash = trimmed.firstIndex(of: "-"), dash != trimmed.startIndex {
                let lo = trimmed[trimmed.startIndex..<dash].trimmingCharacters(in: .whitespaces)
                let hi = trimmed[trimmed.index(after: dash)...].trimmingCharacters(in: .whitespaces)
                if let f = Int(lo), let t = Int(hi) { return XMUXRange(from: f, to: max(f, t)) }
            }
            if let v = Int(trimmed) { return XMUXRange(from: v, to: v) }
            return .zero
        default:
            return .zero
        }
    }

    /// JSON form for export: a bare int when `from == to`, else `"from-to"`.
    var jsonValue: Any { from == to ? from : "\(from)-\(to)" }
}

/// Connection-pool sizing and rotation for XHTTP. Ranges are `.zero` when unset (0 = no limit).
struct XMUXConfiguration: Codable, Equatable, Hashable {
    /// Max concurrent XHTTP sessions multiplexed over one connection (0 = unlimited).
    var maxConcurrency: XMUXRange
    /// Underlying connections opened per destination before existing ones are reused (0 = unlimited).
    var maxConnections: XMUXRange
    /// Max times a connection is handed to a new session before retirement (0 = unlimited).
    var cMaxReuseTimes: XMUXRange
    /// Max HTTP requests over a connection before retirement (0 = unlimited).
    var hMaxRequestTimes: XMUXRange
    /// Max wall-clock lifetime of a connection, seconds (0 = unlimited).
    var hMaxReusableSecs: XMUXRange
    /// HTTP/2 & HTTP/3 keep-alive period, seconds (0 = default, <0 = disabled).
    var hKeepAlivePeriod: Int

    static let disabled = XMUXConfiguration(
        maxConcurrency: .zero, maxConnections: .zero, cMaxReuseTimes: .zero,
        hMaxRequestTimes: .zero, hMaxReusableSecs: .zero, hKeepAlivePeriod: 0
    )

    /// Default applied when XHTTP omits `xmux`: serial connection reuse (`maxConcurrency` 1)
    /// with rotation after 600–900 requests / 1800–3000 s. `maxConnections`, `cMaxReuseTimes`,
    /// and `hKeepAlivePeriod` stay unset.
    static let serialReuseDefault = XMUXConfiguration(
        maxConcurrency: XMUXRange(from: 1, to: 1),
        maxConnections: .zero,
        cMaxReuseTimes: .zero,
        hMaxRequestTimes: XMUXRange(from: 600, to: 900),
        hMaxReusableSecs: XMUXRange(from: 1800, to: 3000),
        hKeepAlivePeriod: 0
    )

    /// True when any field departs from its unset default, so pooling should engage.
    var isEnabled: Bool {
        !(maxConcurrency.isZero && maxConnections.isZero && cMaxReuseTimes.isZero
          && hMaxRequestTimes.isZero && hMaxReusableSecs.isZero && hKeepAlivePeriod == 0)
    }

    /// Parses an `xmux` JSON object (each range as int / `{from,to}` / `"a-b"`).
    static func parse(from json: [String: Any]) -> XMUXConfiguration {
        XMUXConfiguration(
            maxConcurrency: XMUXRange.parse(json["maxConcurrency"]),
            maxConnections: XMUXRange.parse(json["maxConnections"]),
            cMaxReuseTimes: XMUXRange.parse(json["cMaxReuseTimes"]),
            hMaxRequestTimes: XMUXRange.parse(json["hMaxRequestTimes"]),
            hMaxReusableSecs: XMUXRange.parse(json["hMaxReusableSecs"]),
            hKeepAlivePeriod: (json["hKeepAlivePeriod"] as? Int) ?? 0
        )
    }

    /// JSON object for the `extra`/`xhttpSettings` blob, emitting only non-zero fields.
    var jsonObject: [String: Any] {
        var j: [String: Any] = [:]
        if !maxConcurrency.isZero { j["maxConcurrency"] = maxConcurrency.jsonValue }
        if !maxConnections.isZero { j["maxConnections"] = maxConnections.jsonValue }
        if !cMaxReuseTimes.isZero { j["cMaxReuseTimes"] = cMaxReuseTimes.jsonValue }
        if !hMaxRequestTimes.isZero { j["hMaxRequestTimes"] = hMaxRequestTimes.jsonValue }
        if !hMaxReusableSecs.isZero { j["hMaxReusableSecs"] = hMaxReusableSecs.jsonValue }
        if hKeepAlivePeriod != 0 { j["hKeepAlivePeriod"] = hKeepAlivePeriod }
        return j
    }
}

/// XHTTP transport settings; advanced fields come from the `extra` JSON blob in VLESS share links.
struct XHTTPConfiguration: Codable, Equatable, Hashable {
    let host: String
    let path: String
    let mode: XHTTPMode
    let headers: [String: String]
    /// When false, adds `Content-Type: application/grpc` header.
    let noGRPCHeader: Bool
    let scMaxEachPostBytes: Int
    let scMinPostsIntervalMs: Int

    // X-Padding settings (from extra)
    let xPaddingBytesFrom: Int
    let xPaddingBytesTo: Int
    /// When false, uses Referer-based padding instead.
    let xPaddingObfsMode: Bool
    let xPaddingKey: String
    let xPaddingHeader: String
    let xPaddingPlacement: XHTTPPlacement
    let xPaddingMethod: XHTTPPaddingMethod

    // Uplink settings (from extra)
    let uplinkHTTPMethod: String

    // Session/seq placement (from extra)
    let sessionPlacement: XHTTPPlacement
    /// Auto-determined by placement if empty.
    let sessionKey: String
    let seqPlacement: XHTTPPlacement
    /// Auto-determined by placement if empty.
    let seqKey: String

    // Session ID generation (from extra)
    let sessionIDTable: String
    /// Length range (half-open from/to); 0 → random UUID.
    let sessionIDLengthFrom: Int
    let sessionIDLengthTo: Int

    // Uplink data placement (from extra)
    let uplinkDataPlacement: XHTTPPlacement
    let uplinkDataKey: String
    /// 0 = no chunking.
    let uplinkChunkSize: Int

    /// Boxed to break the value-type recursion through `XHTTPDownloadSettings.xhttp`.
    private let _downloadSettings: XHTTPDownloadSettingsBox?

    /// `nil` when up/download are not detached.
    var downloadSettings: XHTTPDownloadSettings? { _downloadSettings?.value }

    /// Connection-pool/rotation settings (`xmux`); `nil` → default per-stream behavior.
    let xmux: XMUXConfiguration?

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
        sessionPlacement: XHTTPPlacement = .path,
        sessionKey: String = "",
        seqPlacement: XHTTPPlacement = .path,
        seqKey: String = "",
        sessionIDTable: String = "",
        sessionIDLengthFrom: Int = 0,
        sessionIDLengthTo: Int = 0,
        uplinkDataPlacement: XHTTPPlacement = .body,
        uplinkDataKey: String = "",
        uplinkChunkSize: Int = 0,
        downloadSettings: XHTTPDownloadSettings? = nil,
        xmux: XMUXConfiguration? = nil
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
        self.sessionPlacement = sessionPlacement
        self.sessionKey = sessionKey
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
        sessionPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .sessionPlacement) ?? .path
        sessionKey = try c.decodeIfPresent(String.self, forKey: .sessionKey) ?? ""
        seqPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .seqPlacement) ?? .path
        seqKey = try c.decodeIfPresent(String.self, forKey: .seqKey) ?? ""
        sessionIDTable = try c.decodeIfPresent(String.self, forKey: .sessionIDTable) ?? ""
        sessionIDLengthFrom = try c.decodeIfPresent(Int.self, forKey: .sessionIDLengthFrom) ?? 0
        sessionIDLengthTo = try c.decodeIfPresent(Int.self, forKey: .sessionIDLengthTo) ?? 0
        uplinkDataPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .uplinkDataPlacement) ?? .body
        uplinkDataKey = try c.decodeIfPresent(String.self, forKey: .uplinkDataKey) ?? ""
        uplinkChunkSize = try c.decodeIfPresent(Int.self, forKey: .uplinkChunkSize) ?? 0
        _downloadSettings = try c.decodeIfPresent(XHTTPDownloadSettingsBox.self, forKey: ._downloadSettings)
        xmux = try c.decodeIfPresent(XMUXConfiguration.self, forKey: .xmux)
    }

    /// xmux settings used at runtime: the configured values, or the serial-reuse + rotation
    /// default when XHTTP omits xmux. The default applies only when xmux is entirely unset;
    /// a partial xmux is used verbatim.
    var effectiveXMUX: XMUXConfiguration {
        if let xmux, xmux.isEnabled { return xmux }
        return .serialReuseDefault
    }

    /// Normalized path: ensure leading "/" and trailing "/".
    var normalizedPath: String {
        let pathOnly = path.split(separator: "?", maxSplits: 1).first.map(String.init) ?? path
        var p = pathOnly
        if !p.hasPrefix("/") {
            p = "/" + p
        }
        if !p.hasSuffix("/") {
            p = p + "/"
        }
        return p
    }

    /// Query string extracted from path (the part after "?").
    var normalizedQuery: String {
        let parts = path.split(separator: "?", maxSplits: 1)
        if parts.count > 1 {
            return String(parts[1])
        }
        return ""
    }

    /// Auto-determined by placement when unset.
    var normalizedSessionKey: String {
        if !sessionKey.isEmpty { return sessionKey }
        switch sessionPlacement {
        case .header: return "X-Session"
        case .cookie, .query: return "x_session"
        default: return ""
        }
    }

    /// Auto-determined by placement when unset (distinct default from the session key).
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
        // Half-open range [from, to); from == to → from.
        let length: Int
        if sessionIDLengthTo <= sessionIDLengthFrom {
            length = sessionIDLengthFrom
        } else {
            length = Int.random(in: sessionIDLengthFrom..<sessionIDLengthTo)
        }
        guard !table.isEmpty, length > 0 else {
            return UUID().uuidString.lowercased()
        }
        let chars = Array(table)
        var id = ""
        id.reserveCapacity(length)
        for _ in 0..<length {
            id.append(chars[Int.random(in: 0..<chars.count)])
        }
        return id
    }

    func generatePadding() -> String {
        let length = Int.random(in: xPaddingBytesFrom...max(xPaddingBytesFrom, xPaddingBytesTo))
        switch xPaddingMethod {
        case .repeatX:
            return String(repeating: "X", count: length)
        case .tokenish:
            return generateTokenishPadding(targetBytes: length)
        }
    }

    /// Generates base62 "tokenish" padding of approximately `targetBytes` bytes.
    private func generateTokenishPadding(targetBytes: Int) -> String {
        // base62 chars average ~0.8 bytes per char in Huffman encoding
        let n = max(1, Int(ceil(Double(targetBytes) / 0.8)))
        let charset = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
        var result = ""
        result.reserveCapacity(n)
        for _ in 0..<n {
            result.append(charset[Int.random(in: 0..<charset.count)])
        }
        return result
    }

    /// Parses XHTTP parameters from VLESS URL query parameters. Host fallback order:
    /// `host` param → TLS SNI → Reality serverName → server address.
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

        let downloadSettings = parseDownloadSettings(from: extra["downloadSettings"] as? [String: Any])
        return build(host: host, path: path, mode: mode, extra: extra, downloadSettings: downloadSettings)
    }

    /// Builds from an `xhttpSettings`/`splithttpSettings` JSON object (advanced
    /// fields are top-level, not under `extra`); never produces its own nested detach.
    static func parse(fromJSON json: [String: Any], serverAddress: String, tlsServerName: String? = nil, realityServerName: String? = nil) -> XHTTPConfiguration {
        let host = (json["host"] as? String) ?? tlsServerName ?? realityServerName ?? serverAddress
        let path = (json["path"] as? String) ?? "/"
        let mode = XHTTPMode(rawValue: (json["mode"] as? String) ?? "auto") ?? .auto
        return build(host: host, path: path, mode: mode, extra: json, downloadSettings: nil)
    }

    /// Parses `downloadSettings` from `extra`; returns nil when absent or unusable
    /// so callers fall back to a normal single-server connection.
    static func parseDownloadSettings(from json: [String: Any]?) -> XHTTPDownloadSettings? {
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

        // The wire format treats "" (or an absent key) and "none" the same.
        let securityRaw = (json["security"] as? String ?? "none").lowercased()
        let security = securityRaw.isEmpty ? "none" : securityRaw

        var tls: TLSConfiguration? = nil
        var reality: RealityConfiguration? = nil
        switch security {
        case "tls":
            tls = mapDownloadTLS(json["tlsSettings"] as? [String: Any], serverAddress: address)
        case "reality":
            guard let r = mapDownloadReality(json["realitySettings"] as? [String: Any], serverAddress: address) else {
                // Public key missing/invalid — drop detach, fall back to main server.
                return nil
            }
            reality = r
        default:
            break
        }

        let xhttpJSON = (json["xhttpSettings"] as? [String: Any])
            ?? (json["splithttpSettings"] as? [String: Any])
            ?? [:]
        let xhttp = parse(fromJSON: xhttpJSON, serverAddress: address,
                          tlsServerName: tls?.serverName, realityServerName: reality?.serverName)

        return XHTTPDownloadSettings(serverAddress: address, serverPort: port,
                                     security: security, tls: tls, reality: reality, xhttp: xhttp)
    }

    private static func mapDownloadTLS(_ json: [String: Any]?, serverAddress: String) -> TLSConfiguration {
        let serverName = (json?["serverName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? serverAddress
        var alpn: [String]? = nil
        if let arr = json?["alpn"] as? [String], !arr.isEmpty {
            alpn = arr
        } else if let s = json?["alpn"] as? String, !s.isEmpty {
            alpn = s.split(separator: ",").map(String.init)
        }
        let fp = (json?["fingerprint"] as? String).flatMap { TLSFingerprint(rawValue: $0) } ?? .chrome120
        let ech = (json?["ech"] as? String).flatMap { $0.isEmpty ? nil : $0 }
        return TLSConfiguration(serverName: serverName, alpn: alpn, echConfig: ech, fingerprint: fp)
    }

    /// Returns nil when the public key is missing or not a valid 32-byte key (base64url or base64).
    private static func mapDownloadReality(_ json: [String: Any]?, serverAddress: String) -> RealityConfiguration? {
        guard let json, let pbkString = json["publicKey"] as? String, !pbkString.isEmpty else { return nil }
        guard let publicKey = (Data(base64URLEncoded: pbkString) ?? Data(base64Encoded: pbkString)),
              publicKey.count == 32 else { return nil }
        let serverName = (json["serverName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? serverAddress
        let shortId = Data(hexString: (json["shortId"] as? String) ?? "") ?? Data()
        let fp = (json["fingerprint"] as? String).flatMap { TLSFingerprint(rawValue: $0) } ?? .chrome120
        return RealityConfiguration(serverName: serverName, publicKey: publicKey, shortId: shortId, fingerprint: fp)
    }

    /// Core builder shared by URL-param and JSON parsing; reads advanced fields from `extra`.
    private static func build(host: String, path: String, mode: XHTTPMode, extra: [String: Any], downloadSettings: XHTTPDownloadSettings?) -> XHTTPConfiguration {
        var headers: [String: String] = [:]
        if let extraHeaders = extra["headers"] as? [String: String] {
            headers = extraHeaders
        }

        let noGRPCHeader = extra["noGRPCHeader"] as? Bool ?? false

        // scMaxEachPostBytes can be an int or {"from":N,"to":N}; use "to" as the max.
        var scMaxEachPostBytes = 1_000_000
        if let range = extra["scMaxEachPostBytes"] as? [String: Any] {
            scMaxEachPostBytes = range["to"] as? Int ?? 1_000_000
        } else if let val = extra["scMaxEachPostBytes"] as? Int {
            scMaxEachPostBytes = val
        }

        // scMinPostsIntervalMs likewise.
        var scMinPostsIntervalMs = 30
        if let range = extra["scMinPostsIntervalMs"] as? [String: Any] {
            scMinPostsIntervalMs = range["to"] as? Int ?? 30
        } else if let val = extra["scMinPostsIntervalMs"] as? Int {
            scMinPostsIntervalMs = val
        }

        var xPaddingFrom = 100
        var xPaddingTo = 1000
        if let range = extra["xPaddingBytes"] as? [String: Any] {
            xPaddingFrom = range["from"] as? Int ?? 100
            xPaddingTo = range["to"] as? Int ?? 1000
        } else if let val = extra["xPaddingBytes"] as? Int {
            xPaddingFrom = val
            xPaddingTo = val
        }

        let xPaddingObfsMode = extra["xPaddingObfsMode"] as? Bool ?? false
        let xPaddingKey = extra["xPaddingKey"] as? String ?? "x_padding"
        let xPaddingHeader = extra["xPaddingHeader"] as? String ?? "X-Padding"
        let xPaddingPlacement = XHTTPPlacement(rawValue: extra["xPaddingPlacement"] as? String ?? "queryInHeader") ?? .queryInHeader
        let xPaddingMethod = XHTTPPaddingMethod(rawValue: extra["xPaddingMethod"] as? String ?? "repeat-x") ?? .repeatX

        let uplinkHTTPMethod = extra["uplinkHTTPMethod"] as? String ?? "POST"

        let sessionPlacement = XHTTPPlacement(rawValue: extra["sessionPlacement"] as? String ?? "path") ?? .path
        let sessionKey = extra["sessionKey"] as? String ?? ""
        let seqPlacement = XHTTPPlacement(rawValue: extra["seqPlacement"] as? String ?? "path") ?? .path
        let seqKey = extra["seqKey"] as? String ?? ""

        let sessionIDTable = extra["sessionIDTable"] as? String ?? ""
        var sessionIDLengthFrom = 0
        var sessionIDLengthTo = 0
        if let range = extra["sessionIDLength"] as? [String: Any] {
            sessionIDLengthFrom = range["from"] as? Int ?? 0
            sessionIDLengthTo = range["to"] as? Int ?? 0
        } else if let val = extra["sessionIDLength"] as? Int {
            sessionIDLengthFrom = val
            sessionIDLengthTo = val
        }

        let uplinkDataPlacement = XHTTPPlacement(rawValue: extra["uplinkDataPlacement"] as? String ?? "body") ?? .body

        // Defaults depend on placement.
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

        let xmux = (extra["xmux"] as? [String: Any]).map(XMUXConfiguration.parse)

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
            sessionPlacement: sessionPlacement,
            sessionKey: sessionKey,
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

extension XHTTPConfiguration {

    /// Encodes the non-default "extra" fields back to the JSON string the proxy editor's
    /// advanced-settings field displays. Empty when every field is at its default.
    var encodedExtra: String {
        var dict: [String: Any] = [:]

        if !headers.isEmpty { dict["headers"] = headers }
        if noGRPCHeader { dict["noGRPCHeader"] = true }
        if scMaxEachPostBytes != 1_000_000 { dict["scMaxEachPostBytes"] = scMaxEachPostBytes }
        if scMinPostsIntervalMs != 30 { dict["scMinPostsIntervalMs"] = scMinPostsIntervalMs }
        if xPaddingBytesFrom != 100 || xPaddingBytesTo != 1000 {
            dict["xPaddingBytes"] = ["from": xPaddingBytesFrom, "to": xPaddingBytesTo]
        }
        if xPaddingObfsMode { dict["xPaddingObfsMode"] = true }
        if xPaddingKey != "x_padding" { dict["xPaddingKey"] = xPaddingKey }
        if xPaddingHeader != "X-Padding" { dict["xPaddingHeader"] = xPaddingHeader }
        if xPaddingPlacement != .queryInHeader { dict["xPaddingPlacement"] = xPaddingPlacement.rawValue }
        if xPaddingMethod != .repeatX { dict["xPaddingMethod"] = xPaddingMethod.rawValue }
        if uplinkHTTPMethod != "POST" { dict["uplinkHTTPMethod"] = uplinkHTTPMethod }
        if sessionPlacement != .path { dict["sessionPlacement"] = sessionPlacement.rawValue }
        if !sessionKey.isEmpty { dict["sessionKey"] = sessionKey }
        if seqPlacement != .path { dict["seqPlacement"] = seqPlacement.rawValue }
        if !seqKey.isEmpty { dict["seqKey"] = seqKey }
        if uplinkDataPlacement != .body { dict["uplinkDataPlacement"] = uplinkDataPlacement.rawValue }
        // Data key and chunk size have placement-dependent defaults.
        let defaultDataKey: String
        let defaultChunkSize: Int
        switch uplinkDataPlacement {
        case .header: defaultDataKey = "X-Data"; defaultChunkSize = 4096
        case .cookie: defaultDataKey = "x_data"; defaultChunkSize = 3072
        default: defaultDataKey = ""; defaultChunkSize = 0
        }
        if uplinkDataKey != defaultDataKey { dict["uplinkDataKey"] = uplinkDataKey }
        if uplinkChunkSize != defaultChunkSize { dict["uplinkChunkSize"] = uplinkChunkSize }
        if let xmux, xmux.isEnabled { dict["xmux"] = xmux.jsonObject }

        guard !dict.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys, .prettyPrinted]),
              let str = String(data: data, encoding: .utf8) else {
            return ""
        }
        return str
    }
}

// MARK: - XHTTP Download Settings (up/download detach)

/// Separate download source: the GET leg dials this server while the POST leg
/// stays on the main node, correlated by a shared session ID.
struct XHTTPDownloadSettings: Codable, Equatable, Hashable {
    let serverAddress: String
    let serverPort: UInt16
    /// `"none"`, `"tls"`, or `"reality"`.
    let security: String
    let tls: TLSConfiguration?
    let reality: RealityConfiguration?
    /// Never carries its own nested `downloadSettings`.
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

    /// The download leg's security layer reconstructed from the flattened fields.
    var securityLayer: SecurityLayer {
        switch security {
        case "tls":     return tls.map(SecurityLayer.tls) ?? .none
        case "reality": return reality.map(SecurityLayer.reality) ?? .none
        default:        return .none
        }
    }
}

// MARK: - URL Export

extension XHTTPConfiguration {
    /// XHTTP `xhttpSettings` object for a `vless://` URL's `extra` blob; emits only non-default fields.
    var urlSettingsJSON: [String: Any] {
        var j: [String: Any] = ["host": host]
        if path != "/" { j["path"] = path }
        if mode != .auto { j["mode"] = mode.rawValue }
        if !headers.isEmpty { j["headers"] = headers }
        if noGRPCHeader { j["noGRPCHeader"] = true }
        return j
    }
}

extension XHTTPDownloadSettings {
    /// The URL-encoded `extra` query value carrying the up/download detach settings,
    /// or nil when it can't be serialized.
    var urlExtraParam: String? {
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

        let extra: [String: Any] = ["downloadSettings": dl]
        guard let data = try? JSONSerialization.data(withJSONObject: extra, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return nil }
        // Escape only the characters that would break query-param splitting (& = + #).
        var allowed = CharacterSet.urlQueryAllowed
        allowed.remove(charactersIn: "&=+#")
        return json.addingPercentEncoding(withAllowedCharacters: allowed) ?? json
    }
}

/// Immutable reference box breaking the value-type recursion; conformances
/// delegate to the wrapped value, so the box never appears in JSON or affects equality.
final class XHTTPDownloadSettingsBox: Codable, Equatable, Hashable {
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

enum XHTTPError: Error, LocalizedError {
    case setupFailed(String)
    case httpError(String)
    case connectionClosed

    var errorDescription: String? {
        switch self {
        case .setupFailed(let reason):
            return "XHTTP setup failed: \(reason)"
        case .httpError(let reason):
            return "XHTTP HTTP error: \(reason)"
        case .connectionClosed:
            return "XHTTP connection closed"
        }
    }
}
