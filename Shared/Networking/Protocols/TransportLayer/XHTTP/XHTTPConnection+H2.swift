//
//  XHTTPConnection+H2.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

// MARK: - HTTP/2 Support (RFC 7540) — Frame Layer & HPACK

extension XHTTPConnection {

    // MARK: HTTP/2 Constants

    /// HTTP/2 connection preface (RFC 7540 §3.5).
    static let h2Preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    static let h2FrameData: UInt8 = 0x00
    static let h2FrameHeaders: UInt8 = 0x01
    static let h2FrameSettings: UInt8 = 0x04
    static let h2FramePing: UInt8 = 0x06
    static let h2FrameGoaway: UInt8 = 0x07
    static let h2FrameWindowUpdate: UInt8 = 0x08
    static let h2FrameRstStream: UInt8 = 0x03

    static let h2FlagEndStream: UInt8 = 0x01
    static let h2FlagEndHeaders: UInt8 = 0x04
    static let h2FlagAck: UInt8 = 0x01

    static let h2SettingsEnablePush: UInt16 = 0x02
    static let h2SettingsInitialWindowSize: UInt16 = 0x04

    static let h2StreamWindowSize: UInt32 = 4_194_304  // 4MB
    static let h2ConnectionWindowSize: UInt32 = 1_073_741_824  // 1GB

    // MARK: HTTP/2 Frame I/O

    func buildH2Frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        H2Framing.frame(type: type, flags: flags, streamId: streamId, payload: payload)
    }

    // MARK: HTTP/2 HPACK Encoder (simplified, no Huffman)

    /// Encodes an integer with the given prefix bit width (RFC 7541 §5.1).
    static func hpackEncodeInteger(_ value: Int, prefixBits: Int) -> [UInt8] {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            return [UInt8(value)]
        }
        var bytes: [UInt8] = [UInt8(maxPrefix)]
        var remaining = value - maxPrefix
        while remaining >= 128 {
            bytes.append(UInt8(remaining & 0x7F) | 0x80)
            remaining >>= 7
        }
        bytes.append(UInt8(remaining))
        return bytes
    }

    /// Encodes a plain (non-Huffman) string (RFC 7541 §5.2).
    static func hpackEncodeString(_ string: String) -> [UInt8] {
        let bytes = Array(string.utf8)
        // H=0 (no Huffman), length with 7-bit prefix
        var result = hpackEncodeInteger(bytes.count, prefixBits: 7)
        result[0] &= 0x7F
        result.append(contentsOf: bytes)
        return result
    }

    /// Encodes a request header block for HTTP/2 HEADERS; `includeMeta` adds the session ID per placement.
    func encodeH2RequestHeaders(method: String = "POST", includeMeta: Bool = false) -> Data {
        var block = Data()

        // Pseudo-header order: :authority, :method, :path, :scheme

        // :authority — literal without indexing, name index 1
        var authBytes = Self.hpackEncodeInteger(1, prefixBits: 6)
        authBytes[0] |= 0x40
        block.append(contentsOf: authBytes)
        block.append(contentsOf: Self.hpackEncodeString(configuration.host))

        if method == "GET" {
            block.append(0x82) // GET = index 2
        } else {
            block.append(0x83) // POST = index 3
        }

        // :path — RequestURI form (path + query)
        var path = configuration.normalizedPath
        if includeMeta && !sessionId.isEmpty && configuration.sessionPlacement == .path {
            path = appendToPath(path, sessionId)
        }
        var queryParts: [String] = []
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            queryParts.append(configQuery)
        }
        if includeMeta {
            if !sessionId.isEmpty && configuration.sessionPlacement == .query {
                queryParts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
            }
        }
        if !queryParts.isEmpty {
            path += "?" + queryParts.joined(separator: "&")
        }

        if path == "/" {
            block.append(0x84) // Indexed: :path / (index 4)
        } else {
            var pathBytes = Self.hpackEncodeInteger(4, prefixBits: 6)
            pathBytes[0] |= 0x40
            block.append(contentsOf: pathBytes)
            block.append(contentsOf: Self.hpackEncodeString(path))
        }

        // :scheme https — static table index 7
        block.append(0x87)

        if method != "GET" && !configuration.noGRPCHeader {
            // content-type name index 31
            var ctBytes = Self.hpackEncodeInteger(31, prefixBits: 6)
            ctBytes[0] |= 0x40
            block.append(contentsOf: ctBytes)
            block.append(contentsOf: Self.hpackEncodeString("application/grpc"))
        }

        // Session metadata — non-path placements
        if includeMeta && !sessionId.isEmpty {
            switch configuration.sessionPlacement {
            case .header:
                block.append(0x40)
                block.append(contentsOf: Self.hpackEncodeString(configuration.normalizedSessionKey.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(sessionId))
            case .cookie:
                var cookieBytes = Self.hpackEncodeInteger(32, prefixBits: 6)
                cookieBytes[0] |= 0x40
                block.append(contentsOf: cookieBytes)
                block.append(contentsOf: Self.hpackEncodeString("\(configuration.normalizedSessionKey)=\(sessionId)"))
            default:
                break // path and query handled above
            }
        }

        appendH2CommonHeaders(to: &block, path: path)

        return block
    }

    /// Encodes HEADERS for an upload POST stream; `seq` is nil for stream-up, set per batch for packet-up.
    /// `uplinkData` carries a packet-up payload in headers/cookies under non-body placement.
    func encodeH2UploadHeaders(seq: Int64?, contentLength: Int? = nil, uplinkData: [UplinkDataField] = []) -> Data {
        var block = Data()

        // Pseudo-header order: :authority, :method, :path, :scheme

        // :authority — literal without indexing, name index 1
        var authBytes = Self.hpackEncodeInteger(1, prefixBits: 6)
        authBytes[0] |= 0x40
        block.append(contentsOf: authBytes)
        block.append(contentsOf: Self.hpackEncodeString(configuration.host))

        let method = configuration.uplinkHTTPMethod
        if method == "POST" {
            block.append(0x83) // POST = index 3
        } else if method == "GET" {
            block.append(0x82) // GET = index 2
        } else {
            var methodBytes = Self.hpackEncodeInteger(2, prefixBits: 6)
            methodBytes[0] |= 0x40
            block.append(contentsOf: methodBytes)
            block.append(contentsOf: Self.hpackEncodeString(method))
        }

        var path = configuration.normalizedPath
        if !sessionId.isEmpty && configuration.sessionPlacement == .path {
            path = appendToPath(path, sessionId)
        }
        if let seq, configuration.seqPlacement == .path {
            path = appendToPath(path, "\(seq)")
        }
        var queryParts: [String] = []
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            queryParts.append(configQuery)
        }
        if !sessionId.isEmpty && configuration.sessionPlacement == .query {
            queryParts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
        }
        if let seq, configuration.seqPlacement == .query {
            queryParts.append("\(configuration.normalizedSeqKey)=\(seq)")
        }
        if !queryParts.isEmpty {
            path += "?" + queryParts.joined(separator: "&")
        }

        var pathBytes = Self.hpackEncodeInteger(4, prefixBits: 6)
        pathBytes[0] |= 0x40
        block.append(contentsOf: pathBytes)
        block.append(contentsOf: Self.hpackEncodeString(path))

        // :scheme https — static table index 7
        block.append(0x87)

        // packet-up omits Content-Type; only stream-up sends application/grpc.
        if seq == nil, !configuration.noGRPCHeader {
            var ctBytes = Self.hpackEncodeInteger(31, prefixBits: 6)
            ctBytes[0] |= 0x40
            block.append(contentsOf: ctBytes)
            block.append(contentsOf: Self.hpackEncodeString("application/grpc"))
        }

        if let contentLength {
            var clBytes = Self.hpackEncodeInteger(28, prefixBits: 6)
            clBytes[0] |= 0x40
            block.append(contentsOf: clBytes)
            block.append(contentsOf: Self.hpackEncodeString("\(contentLength)"))
        }

        // Session metadata — non-path placements
        if !sessionId.isEmpty {
            switch configuration.sessionPlacement {
            case .header:
                block.append(0x40)
                block.append(contentsOf: Self.hpackEncodeString(configuration.normalizedSessionKey.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(sessionId))
            case .cookie:
                var cookieBytes = Self.hpackEncodeInteger(32, prefixBits: 6)
                cookieBytes[0] |= 0x40
                block.append(contentsOf: cookieBytes)
                block.append(contentsOf: Self.hpackEncodeString("\(configuration.normalizedSessionKey)=\(sessionId)"))
            default:
                break
            }
        }

        // Seq metadata — non-path placements
        if let seq {
            switch configuration.seqPlacement {
            case .header:
                block.append(0x40)
                block.append(contentsOf: Self.hpackEncodeString(configuration.normalizedSeqKey.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString("\(seq)"))
            case .cookie:
                var cookieBytes = Self.hpackEncodeInteger(32, prefixBits: 6)
                cookieBytes[0] |= 0x40
                block.append(contentsOf: cookieBytes)
                block.append(contentsOf: Self.hpackEncodeString("\(configuration.normalizedSeqKey)=\(seq)"))
            default:
                break
            }
        }

        // Uplink data placement — packet-up payload carried in headers or cookies.
        // Encoded "without indexing" since these are large, single-use values.
        for field in uplinkData {
            switch field {
            case .header(let name, let value):
                block.append(0x00) // literal header field without indexing, new name
                block.append(contentsOf: Self.hpackEncodeString(name.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(value))
            case .cookie(let pair):
                // cookie (static index 32) without indexing → 4-bit prefix, high nibble 0.
                block.append(contentsOf: Self.hpackEncodeInteger(32, prefixBits: 4))
                block.append(contentsOf: Self.hpackEncodeString(pair))
            }
        }

        appendH2CommonHeaders(to: &block, path: path)

        return block
    }

    /// Appends user-agent, padding, and custom headers to a HPACK header block.
    private func appendH2CommonHeaders(to block: inout Data, path: String) {
        // user-agent — name index 58 (RFC 7541 Appendix A)
        let ua = configuration.headers["User-Agent"] ?? ProxyUserAgent.default
        var uaBytes = Self.hpackEncodeInteger(58, prefixBits: 6)
        uaBytes[0] |= 0x40
        block.append(contentsOf: uaBytes)
        block.append(contentsOf: Self.hpackEncodeString(ua))

        let padding = configuration.generatePadding()
        let paddingPath = configuration.normalizedPath
        if !configuration.xPaddingObfsMode {
            let referer = "https://\(configuration.host)\(paddingPath)?x_padding=\(padding)"
            var refBytes = Self.hpackEncodeInteger(51, prefixBits: 6)
            refBytes[0] |= 0x40
            block.append(contentsOf: refBytes)
            block.append(contentsOf: Self.hpackEncodeString(referer))
        } else {
            switch configuration.xPaddingPlacement {
            case .header:
                block.append(0x40)
                block.append(contentsOf: Self.hpackEncodeString(configuration.xPaddingHeader.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(padding))
            case .queryInHeader:
                let headerValue = "https://\(configuration.host)\(paddingPath)?\(configuration.xPaddingKey)=\(padding)"
                block.append(0x40)
                block.append(contentsOf: Self.hpackEncodeString(configuration.xPaddingHeader.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(headerValue))
            case .cookie:
                var cookieBytes = Self.hpackEncodeInteger(32, prefixBits: 6)
                cookieBytes[0] |= 0x40
                block.append(contentsOf: cookieBytes)
                block.append(contentsOf: Self.hpackEncodeString("\(configuration.xPaddingKey)=\(padding)"))
            default:
                break
            }
        }

        // Custom headers (literal, new names), skipping hop-by-hop headers
        // forbidden in HTTP/2.
        let h2ForbiddenHeaders: Set<String> = [
            "host", "connection", "proxy-connection", "transfer-encoding",
            "upgrade", "keep-alive", "content-length", "user-agent"
        ]
        for (key, value) in configuration.headers {
            let lk = key.lowercased()
            if h2ForbiddenHeaders.contains(lk) { continue }
            block.append(0x40)
            block.append(contentsOf: Self.hpackEncodeString(lk))
            block.append(contentsOf: Self.hpackEncodeString(value))
        }
    }

    // MARK: HTTP/2 Response Status

    /// Returns nil if the HEADERS block's :status is 200, else an error description.
    func checkH2ResponseStatus(_ headerBlock: Data) -> String? {
        guard !headerBlock.isEmpty else { return "empty header block" }

        // Skip HPACK dynamic table size updates (prefix 001xxxxx, RFC 7541 §6.3).
        var offset = headerBlock.startIndex
        while offset < headerBlock.endIndex, headerBlock[offset] & 0xE0 == 0x20 {
            let initial = headerBlock[offset] & 0x1F
            offset += 1
            if initial == 0x1F {
                // Multi-byte integer: skip continuation bytes (high bit set)
                while offset < headerBlock.endIndex, headerBlock[offset] & 0x80 != 0 {
                    offset += 1
                }
                offset += 1  // final byte (high bit clear)
            }
        }
        guard offset < headerBlock.endIndex else { return "empty header block (only table size updates)" }

        let first = headerBlock[offset]
        let remaining = headerBlock[offset...]

        // Indexed representation (top bit set): static table index
        // 0x88=200, 0x89=204, 0x8a=206, 0x8b=304, 0x8c=400, 0x8d=404, 0x8e=500
        if first & 0x80 != 0 {
            if first == 0x88 { return nil } // 200 OK
            let indexedStatus: [UInt8: String] = [0x89: "204", 0x8a: "206", 0x8b: "304", 0x8c: "400", 0x8d: "404", 0x8e: "500"]
            if let status = indexedStatus[first] { return "status \(status)" }
            return "status (indexed \(first & 0x7F))"
        }

        // Literal representations with a :status name index (static entries 8-14).
        let nameIndex: UInt8
        if first & 0xF0 == 0x00 {       // Literal without indexing (0000 NNNN)
            nameIndex = first & 0x0F
        } else if first & 0xF0 == 0x10 { // Literal never indexed (0001 NNNN)
            nameIndex = first & 0x0F
        } else if first & 0xC0 == 0x40 { // Literal with incremental indexing (01NN NNNN)
            nameIndex = first & 0x3F
        } else {
            let hex = remaining.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            return "unknown status (HPACK: \(hex))"
        }

        // Static table indices 8-14 all have name ":status" (RFC 7541 Appendix A)
        guard (8...14).contains(nameIndex), remaining.count >= 2 else {
            let hex = remaining.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            return "unknown status (HPACK: \(hex))"
        }

        let valueMeta = remaining[remaining.startIndex + 1]
        let isHuffman = (valueMeta & 0x80) != 0
        let valueLen = Int(valueMeta & 0x7F)
        let valueStart = remaining.startIndex + 2

        guard remaining.count >= 2 + valueLen, valueLen > 0 else {
            return "status (?)"
        }

        let valueData = Data(remaining[valueStart..<(valueStart + valueLen)])

        if !isHuffman {
            let status = String(data: valueData, encoding: .ascii) ?? "?"
            return status == "200" ? nil : "status \(status)"
        }

        let status = Self.huffmanDecodeDigits(valueData)
        if status.isEmpty {
            let hex = valueData.map { String(format: "%02x", $0) }.joined(separator: " ")
            return "status (huffman: \(hex))"
        }
        return status == "200" ? nil : "status \(status)"
    }

    /// Huffman-decodes a byte sequence containing only ASCII digits (RFC 7541 Appendix B).
    private static func huffmanDecodeDigits(_ data: Data) -> String {
        var result = ""
        var bits: UInt32 = 0
        var numBits = 0

        for byte in data {
            bits = (bits << 8) | UInt32(byte)
            numBits += 8
        }

        while numBits >= 5 {
            let top5 = Int((bits >> (numBits - 5)) & 0x1F)
            // 5-bit codes: '0'=0x00, '1'=0x01, '2'=0x02
            if top5 <= 0x02 {
                result.append(Character(UnicodeScalar(48 + top5)!))
                numBits -= 5
                continue
            }
            // 6-bit codes: '3'=0x19...'9'=0x1f
            guard numBits >= 6 else { break }
            let top6 = Int((bits >> (numBits - 6)) & 0x3F)
            if top6 >= 0x19 && top6 <= 0x1F {
                let digit = top6 - 0x19 + 3 // '3'..'9'
                result.append(Character(UnicodeScalar(48 + digit)!))
                numBits -= 6
                continue
            }
            break // Unknown code or EOS padding
        }
        return result
    }

    // MARK: HTTP/2 Settings

    /// Parses server SETTINGS payload to extract initial window size and max frame size.
    func parseH2Settings(_ payload: Data) {
        // Each setting is 6 bytes: 2-byte ID + 4-byte value
        var offset = payload.startIndex
        while offset + 6 <= payload.endIndex {
            let id = (UInt16(payload[offset]) << 8) | UInt16(payload[offset + 1])
            let value = (UInt32(payload[offset + 2]) << 24) | (UInt32(payload[offset + 3]) << 16) | (UInt32(payload[offset + 4]) << 8) | UInt32(payload[offset + 5])
            offset += 6

            switch id {
            case 0x04: // INITIAL_WINDOW_SIZE (RFC 7540 §6.9.2: affects stream windows only)
                lock.lock()
                let delta = Int(value) - h2PeerInitialWindowSize
                h2PeerInitialWindowSize = Int(value)
                h2PeerStreamSendWindow += delta
                lock.unlock()
            case 0x05: // MAX_FRAME_SIZE
                lock.lock()
                h2MaxFrameSize = Int(value)
                lock.unlock()
            default:
                break
            }
        }
    }
}
