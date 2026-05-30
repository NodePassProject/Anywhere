//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

/// XHTTP transport mode.
///
/// Matches Xray-core's `XmuxMode` enum in `splithttp/config.go`.
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

/// Metadata placement for session ID, sequence numbers, and padding.
///
/// Matches Xray-core placement constants in `splithttp/common.go`.
enum XHTTPPlacement: String, Codable, Equatable, Hashable {
    case path
    case query
    case header
    case cookie
    case queryInHeader
    case body
}

/// X-Padding generation method.
///
/// Matches Xray-core `PaddingMethod` in `splithttp/xpadding.go`.
enum XHTTPPaddingMethod: String, Codable, Equatable, Hashable {
    case repeatX = "repeat-x"
    case tokenish
}

/// XHTTP transport configuration.
///
/// Matches Xray-core's `splithttp.Config` protobuf definition.
/// Advanced fields are populated from the `extra` JSON blob in VLESS share links.
struct XHTTPConfiguration: Codable, Equatable, Hashable {
    /// Host header value (defaults to server address).
    let host: String
    /// URL path (default "/").
    let path: String
    /// Transport mode (default `.auto`).
    let mode: XHTTPMode
    /// Custom HTTP headers.
    let headers: [String: String]
    /// When false, adds `Content-Type: application/grpc` header (default false).
    let noGRPCHeader: Bool
    /// Maximum bytes per POST body in packet-up mode (default 1,000,000).
    let scMaxEachPostBytes: Int
    /// Minimum interval between consecutive POSTs in ms (default 30).
    let scMinPostsIntervalMs: Int

    // X-Padding settings (from extra)
    /// Range for padding bytes. Default 100-1000.
    let xPaddingBytesFrom: Int
    let xPaddingBytesTo: Int
    /// Enable custom padding obfuscation mode (default false → uses Referer-based padding).
    let xPaddingObfsMode: Bool
    /// Padding parameter key (default "x_padding"). Only used when xPaddingObfsMode=true.
    let xPaddingKey: String
    /// Padding header name (default "X-Padding"). Only used when xPaddingObfsMode=true.
    let xPaddingHeader: String
    /// Padding placement (default "queryInHeader"). Only used when xPaddingObfsMode=true.
    let xPaddingPlacement: XHTTPPlacement
    /// Padding method (default "repeat-x").
    let xPaddingMethod: XHTTPPaddingMethod

    // Uplink settings (from extra)
    /// HTTP method for uplink requests (default "POST").
    let uplinkHTTPMethod: String

    // Session/seq placement (from extra)
    /// Where to place session ID (default "path").
    let sessionPlacement: XHTTPPlacement
    /// Parameter key for session ID. Auto-determined by placement if empty.
    let sessionKey: String
    /// Where to place sequence number (default "path").
    let seqPlacement: XHTTPPlacement
    /// Parameter key for sequence number. Auto-determined by placement if empty.
    let seqKey: String

    // Uplink data placement (from extra)
    /// Where to place uplink data in POST (default "body").
    let uplinkDataPlacement: XHTTPPlacement
    /// Parameter key for uplink data chunks (default "x_data").
    let uplinkDataKey: String
    /// Chunk size for data in headers/cookies (default 0 = no chunking).
    let uplinkChunkSize: Int

    /// Separate download source for XHTTP up/download detach. When set, the GET
    /// (download) stream is dialed to a different server with its own
    /// security/transport while the POST (upload) stays on this node, the two
    /// correlated by a shared session ID.
    ///
    /// Boxed in a reference type to break the value-type recursion this would
    /// otherwise create (``XHTTPConfiguration`` → settings → download-side
    /// `xhttp:` ``XHTTPConfiguration``). Access via ``downloadSettings``.
    private let _downloadSettings: XHTTPDownloadSettingsBox?

    /// Separate download source, or `nil` when up/download are not detached.
    var downloadSettings: XHTTPDownloadSettings? { _downloadSettings?.value }

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
        uplinkDataPlacement: XHTTPPlacement = .body,
        uplinkDataKey: String = "",
        uplinkChunkSize: Int = 0,
        downloadSettings: XHTTPDownloadSettings? = nil
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
        self.uplinkDataPlacement = uplinkDataPlacement
        self.uplinkDataKey = uplinkDataKey
        self.uplinkChunkSize = uplinkChunkSize
        self._downloadSettings = downloadSettings.map(XHTTPDownloadSettingsBox.init)
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
        uplinkDataPlacement = try c.decodeIfPresent(XHTTPPlacement.self, forKey: .uplinkDataPlacement) ?? .body
        uplinkDataKey = try c.decodeIfPresent(String.self, forKey: .uplinkDataKey) ?? ""
        uplinkChunkSize = try c.decodeIfPresent(Int.self, forKey: .uplinkChunkSize) ?? 0
        _downloadSettings = try c.decodeIfPresent(XHTTPDownloadSettingsBox.self, forKey: ._downloadSettings)
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

    /// Normalized query string extracted from path (portion after "?").
    /// Matches Xray-core `GetNormalizedQuery()` in `config.go`.
    var normalizedQuery: String {
        let parts = path.split(separator: "?", maxSplits: 1)
        if parts.count > 1 {
            return String(parts[1])
        }
        return ""
    }

    /// Normalized session key, auto-determined by placement if not set.
    /// Matches Xray-core `GetNormalizedSessionKey()` in `config.go`.
    var normalizedSessionKey: String {
        if !sessionKey.isEmpty { return sessionKey }
        switch sessionPlacement {
        case .header: return "X-Session"
        case .cookie, .query: return "x_session"
        default: return ""
        }
    }

    /// Normalized seq key, auto-determined by placement if not set.
    /// Matches Xray-core `GetNormalizedSeqKey()` in `config.go`.
    var normalizedSeqKey: String {
        if !seqKey.isEmpty { return seqKey }
        switch seqPlacement {
        case .header: return "X-Seq"
        case .cookie, .query: return "x_seq"
        default: return ""
        }
    }

    /// Generate padding value using configured method and random length.
    func generatePadding() -> String {
        let length = Int.random(in: xPaddingBytesFrom...max(xPaddingBytesFrom, xPaddingBytesTo))
        switch xPaddingMethod {
        case .repeatX:
            return String(repeating: "X", count: length)
        case .tokenish:
            return generateTokenishPadding(targetBytes: length)
        }
    }

    /// Generates tokenish padding (base62 random string targeting a Huffman byte length).
    /// Simplified version of Xray-core `GenerateTokenishPaddingBase62` in `xpadding.go`.
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

    /// Parse XHTTP parameters from VLESS URL query parameters.
    ///
    /// Expected parameters: `type=xhttp&host=example.com&path=/xhttp&mode=packet-up&extra={...}`
    ///
    /// Host fallback chain matches Xray-core `dialer.go:264-273`:
    /// 1. Explicit `host` URL parameter
    /// 2. TLS ServerName (SNI)
    /// 3. Reality ServerName
    /// 4. Server address (IP/hostname from URL authority)
    static func parse(from params: [String: String], serverAddress: String, tlsServerName: String? = nil, realityServerName: String? = nil) -> XHTTPConfiguration? {
        let host = params["host"] ?? tlsServerName ?? realityServerName ?? serverAddress
        let path = (params["path"] ?? "/").removingPercentEncoding ?? "/"
        let modeStr = params["mode"] ?? "auto"
        let mode = XHTTPMode(rawValue: modeStr) ?? .auto

        // Parse extra JSON blob if present
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

    /// Builds an ``XHTTPConfiguration`` from an `xhttpSettings` /
    /// `splithttpSettings` JSON object (the download leg's transport block),
    /// where the advanced fields live at the top level rather than under a
    /// nested `extra`. Never produces its own nested detach.
    static func parse(fromJSON json: [String: Any], serverAddress: String, tlsServerName: String? = nil, realityServerName: String? = nil) -> XHTTPConfiguration {
        let host = (json["host"] as? String) ?? tlsServerName ?? realityServerName ?? serverAddress
        let path = (json["path"] as? String) ?? "/"
        let mode = XHTTPMode(rawValue: (json["mode"] as? String) ?? "auto") ?? .auto
        return build(host: host, path: path, mode: mode, extra: json, downloadSettings: nil)
    }

    /// Parses the `downloadSettings` object from the `extra` blob into a separate
    /// download source. Returns `nil` when absent or unusable (missing
    /// address/port, or an invalid Reality key), so the node falls back to a
    /// normal single-server connection. Field names match the share-link JSON.
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
                // Reality requested but the public key is missing/invalid — drop the
                // detach entirely so the node still connects on its main server.
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

    /// Maps a `tlsSettings` JSON object to a ``TLSConfiguration``.
    private static func mapDownloadTLS(_ json: [String: Any]?, serverAddress: String) -> TLSConfiguration {
        let serverName = (json?["serverName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? serverAddress
        var alpn: [String]? = nil
        if let arr = json?["alpn"] as? [String], !arr.isEmpty {
            alpn = arr
        } else if let s = json?["alpn"] as? String, !s.isEmpty {
            alpn = s.split(separator: ",").map(String.init)
        }
        let fp = (json?["fingerprint"] as? String).flatMap { TLSFingerprint(rawValue: $0) } ?? .chrome133
        return TLSConfiguration(serverName: serverName, alpn: alpn, fingerprint: fp)
    }

    /// Maps a `realitySettings` JSON object to a ``RealityConfiguration``.
    /// Returns `nil` when the public key is missing or not a valid 32-byte key
    /// (base64url or standard base64).
    private static func mapDownloadReality(_ json: [String: Any]?, serverAddress: String) -> RealityConfiguration? {
        guard let json, let pbkString = json["publicKey"] as? String, !pbkString.isEmpty else { return nil }
        guard let publicKey = (Data(base64URLEncoded: pbkString) ?? Data(base64Encoded: pbkString)),
              publicKey.count == 32 else { return nil }
        let serverName = (json["serverName"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? serverAddress
        let shortId = Data(hexString: (json["shortId"] as? String) ?? "") ?? Data()
        let fp = (json["fingerprint"] as? String).flatMap { TLSFingerprint(rawValue: $0) } ?? .chrome133
        return RealityConfiguration(serverName: serverName, publicKey: publicKey, shortId: shortId, fingerprint: fp)
    }

    /// Core builder shared by URL-param parsing and download-leg JSON parsing.
    /// Reads the advanced fields from `extra` — either the share-link `extra`
    /// blob, or an `xhttpSettings` object whose advanced fields are top-level.
    private static func build(host: String, path: String, mode: XHTTPMode, extra: [String: Any], downloadSettings: XHTTPDownloadSettings?) -> XHTTPConfiguration {
        // Headers from extra
        var headers: [String: String] = [:]
        if let extraHeaders = extra["headers"] as? [String: String] {
            headers = extraHeaders
        }

        let noGRPCHeader = extra["noGRPCHeader"] as? Bool ?? false

        // scMaxEachPostBytes: can be int or {"from":N,"to":N}
        // We use the "to" value as the max (client picks random within range)
        var scMaxEachPostBytes = 1_000_000
        if let range = extra["scMaxEachPostBytes"] as? [String: Any] {
            scMaxEachPostBytes = range["to"] as? Int ?? 1_000_000
        } else if let val = extra["scMaxEachPostBytes"] as? Int {
            scMaxEachPostBytes = val
        }

        // scMinPostsIntervalMs: can be int or {"from":N,"to":N}
        var scMinPostsIntervalMs = 30
        if let range = extra["scMinPostsIntervalMs"] as? [String: Any] {
            scMinPostsIntervalMs = range["to"] as? Int ?? 30
        } else if let val = extra["scMinPostsIntervalMs"] as? Int {
            scMinPostsIntervalMs = val
        }

        // xPaddingBytes
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

        let uplinkDataPlacement = XHTTPPlacement(rawValue: extra["uplinkDataPlacement"] as? String ?? "body") ?? .body

        // uplinkDataKey defaults depend on placement (Xray-core Build() in transport_internet.go)
        let defaultUplinkDataKey: String
        switch uplinkDataPlacement {
        case .header: defaultUplinkDataKey = "X-Data"
        case .cookie: defaultUplinkDataKey = "x_data"
        default: defaultUplinkDataKey = ""
        }
        let uplinkDataKey = extra["uplinkDataKey"] as? String ?? defaultUplinkDataKey

        // uplinkChunkSize defaults depend on placement (Xray-core Build() in transport_internet.go)
        let defaultUplinkChunkSize: Int
        switch uplinkDataPlacement {
        case .header: defaultUplinkChunkSize = 4096
        case .cookie: defaultUplinkChunkSize = 3072
        default: defaultUplinkChunkSize = 0
        }
        let uplinkChunkSize = extra["uplinkChunkSize"] as? Int ?? defaultUplinkChunkSize

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
            uplinkDataPlacement: uplinkDataPlacement,
            uplinkDataKey: uplinkDataKey,
            uplinkChunkSize: uplinkChunkSize,
            downloadSettings: downloadSettings
        )
    }
}

// MARK: - XHTTP Download Settings (up/download detach)

/// A separate download source for XHTTP: the GET (download) stream is dialed to
/// this server with these settings while the POST (upload) stream stays on the
/// main node, the two correlated by a shared session ID. Holds the subset of a
/// stream's settings that `downloadSettings` carries in a VLESS share link.
struct XHTTPDownloadSettings: Codable, Equatable, Hashable {
    /// Download server address.
    let serverAddress: String
    /// Download server port.
    let serverPort: UInt16
    /// Security tag for the download leg: `"none"`, `"tls"`, or `"reality"`.
    let security: String
    /// TLS settings when `security == "tls"`.
    let tls: TLSConfiguration?
    /// Reality settings when `security == "reality"`.
    let reality: RealityConfiguration?
    /// Download-side XHTTP request config (its own host/path/headers/padding).
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

/// Reference box that lets ``XHTTPConfiguration`` (a value type) hold a
/// ``XHTTPDownloadSettings`` whose `xhttp` is itself an ``XHTTPConfiguration``,
/// without becoming infinitely sized. Immutable, so value semantics are
/// preserved; `Codable`/`Equatable`/`Hashable` delegate transparently to the
/// wrapped value so the box never appears in JSON or affects equality.
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

/// XHTTP transport errors.
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
