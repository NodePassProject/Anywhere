//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
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
        uplinkChunkSize: Int = 0
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
    static func parse(from params: [String: String], serverAddress: String) -> XHTTPConfiguration? {
        let host = params["host"] ?? serverAddress
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
            uplinkChunkSize: uplinkChunkSize
        )
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
