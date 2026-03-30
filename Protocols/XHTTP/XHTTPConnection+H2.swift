//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

// MARK: - HTTP/2 Support (RFC 7540) — Frame Layer & HPACK

extension XHTTPConnection {

    // MARK: HTTP/2 Constants

    /// HTTP/2 connection preface (RFC 7540 §3.5).
    static let h2Preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// HTTP/2 frame header size.
    static let h2FrameHeaderSize = 9

    // Frame types
    static let h2FrameData: UInt8 = 0x00
    static let h2FrameHeaders: UInt8 = 0x01
    static let h2FrameSettings: UInt8 = 0x04
    static let h2FramePing: UInt8 = 0x06
    static let h2FrameGoaway: UInt8 = 0x07
    static let h2FrameWindowUpdate: UInt8 = 0x08
    static let h2FrameRstStream: UInt8 = 0x03

    // Flags
    static let h2FlagEndStream: UInt8 = 0x01
    static let h2FlagEndHeaders: UInt8 = 0x04
    static let h2FlagAck: UInt8 = 0x01

    // Settings IDs
    static let h2SettingsEnablePush: UInt16 = 0x02
    static let h2SettingsInitialWindowSize: UInt16 = 0x04

    // Go http2 transport defaults
    static let h2StreamWindowSize: UInt32 = 4_194_304  // 4MB
    static let h2ConnectionWindowSize: UInt32 = 1_073_741_824  // 1GB

    // MARK: HTTP/2 Frame I/O

    /// Builds an HTTP/2 frame.
    func buildH2Frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        var frame = Data(capacity: Self.h2FrameHeaderSize + payload.count)
        // Length (24-bit)
        let len = UInt32(payload.count)
        frame.append(UInt8((len >> 16) & 0xFF))
        frame.append(UInt8((len >> 8) & 0xFF))
        frame.append(UInt8(len & 0xFF))
        // Type
        frame.append(type)
        // Flags
        frame.append(flags)
        // Stream ID (31-bit, R=0)
        let sid = streamId & 0x7FFFFFFF
        frame.append(UInt8((sid >> 24) & 0xFF))
        frame.append(UInt8((sid >> 16) & 0xFF))
        frame.append(UInt8((sid >> 8) & 0xFF))
        frame.append(UInt8(sid & 0xFF))
        // Payload
        frame.append(payload)
        return frame
    }

    /// Attempts to parse one complete frame from h2ReadBuffer.
    /// Returns (type, flags, streamId, payload) or nil if not enough data.
    private func parseH2Frame() -> (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)? {
        guard h2ReadBuffer.count >= Self.h2FrameHeaderSize else { return nil }

        let b = h2ReadBuffer
        let length = (UInt32(b[b.startIndex]) << 16) | (UInt32(b[b.startIndex + 1]) << 8) | UInt32(b[b.startIndex + 2])
        let type = b[b.startIndex + 3]
        let flags = b[b.startIndex + 4]
        let streamId = (UInt32(b[b.startIndex + 5]) << 24) | (UInt32(b[b.startIndex + 6]) << 16) | (UInt32(b[b.startIndex + 7]) << 8) | UInt32(b[b.startIndex + 8])
        let sid = streamId & 0x7FFFFFFF

        let totalSize = Self.h2FrameHeaderSize + Int(length)
        guard h2ReadBuffer.count >= totalSize else { return nil }

        let payload = h2ReadBuffer.subdata(in: h2ReadBuffer.startIndex + Self.h2FrameHeaderSize ..< h2ReadBuffer.startIndex + totalSize)
        h2ReadBuffer.removeFirst(totalSize)
        if h2ReadBuffer.isEmpty {
            h2ReadBuffer = Data()
        } else {
            h2ReadBuffer = Data(h2ReadBuffer)
        }

        return (type, flags, sid, payload)
    }

    /// Reads from transport into h2ReadBuffer until at least one full frame is available,
    /// then parses and returns it.
    func readH2Frame(completion: @escaping (Result<(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data), Error>) -> Void) {
        lock.lock()
        if let frame = parseH2Frame() {
            // Trampoline every 16th consecutive synchronous parse to prevent
            // stack overflow, while keeping inline dispatch for normal cases.
            h2ReadDepth += 1
            let needsTrampoline = h2ReadDepth >= 16
            if needsTrampoline { h2ReadDepth = 0 }
            lock.unlock()
            if needsTrampoline {
                DispatchQueue.global().async { completion(.success(frame)) }
            } else {
                completion(.success(frame))
            }
            return
        }
        h2ReadDepth = 0  // Reset on actual I/O
        lock.unlock()

        downloadReceive { [weak self] data, _, error in
            guard let self else {
                completion(.failure(XHTTPError.connectionClosed))
                return
            }
            if let error {
                completion(.failure(error))
                return
            }
            guard let data, !data.isEmpty else {
                completion(.failure(XHTTPError.connectionClosed))
                return
            }

            self.lock.lock()
            self.h2ReadBuffer.append(data)
            if self.h2ReadBuffer.count > Self.maxH2ReadBufferSize {
                self.h2ReadBuffer.removeAll()
                self.lock.unlock()
                completion(.failure(XHTTPError.connectionClosed))
                return
            }
            self.lock.unlock()

            // Recurse to try parsing again
            self.readH2Frame(completion: completion)
        }
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
        // Clear the H bit (it's already 0 since we're setting it explicitly)
        result[0] &= 0x7F
        result.append(contentsOf: bytes)
        return result
    }

    /// Encodes a request header block for HTTP/2 HEADERS.
    ///
    /// - Parameters:
    ///   - method: HTTP method ("GET" or "POST")
    ///   - includeMeta: Whether to include session ID in path/headers (for stream-up/packet-up download)
    func encodeH2RequestHeaders(method: String = "POST", includeMeta: Bool = false) -> Data {
        var block = Data()

        // Pseudo-header order matches Go's http2.Transport (h2_bundle.go writeHeaders):
        // :authority, :method, :path, :scheme

        // :authority — literal without indexing, name index 1
        var authBytes = Self.hpackEncodeInteger(1, prefixBits: 6)
        authBytes[0] |= 0x40
        block.append(contentsOf: authBytes)
        block.append(contentsOf: Self.hpackEncodeString(configuration.host))

        // :method — static table indexed
        if method == "GET" {
            block.append(0x82) // GET = index 2
        } else {
            block.append(0x83) // POST = index 3
        }

        // :path — build with optional session ID metadata and query string
        // Matches Go's http2.Transport which uses req.URL.RequestURI() (path + query)
        var path = configuration.normalizedPath
        if includeMeta && !sessionId.isEmpty && configuration.sessionPlacement == .path {
            path = appendToPath(path, sessionId)
        }
        // Append query string: start with config's normalizedQuery, then add metadata
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
            // 0000 NNNN format: name index in 4-bit prefix
            var pathBytes = Self.hpackEncodeInteger(4, prefixBits: 6)
            pathBytes[0] |= 0x40
            block.append(contentsOf: pathBytes)
            block.append(contentsOf: Self.hpackEncodeString(path))
        }

        // :scheme https — static table index 7 (exact match)
        block.append(0x87)

        // content-type: application/grpc (only for POST methods, if enabled)
        if method != "GET" && !configuration.noGRPCHeader {
            // name index 31
            var ctBytes = Self.hpackEncodeInteger(31, prefixBits: 6)
            ctBytes[0] |= 0x40
            block.append(contentsOf: ctBytes)
            block.append(contentsOf: Self.hpackEncodeString("application/grpc"))
        }

        // Session metadata in headers/cookies (non-path placements)
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

    /// Encodes HEADERS for an upload POST stream (stream-up or packet-up).
    ///
    /// - Parameter seq: Sequence number for packet-up (nil for stream-up).
    func encodeH2UploadHeaders(seq: Int64?, contentLength: Int? = nil) -> Data {
        var block = Data()

        // Pseudo-header order matches Go's http2.Transport:
        // :authority, :method, :path, :scheme

        // :authority
        var authBytes = Self.hpackEncodeInteger(1, prefixBits: 6)
        authBytes[0] |= 0x40
        block.append(contentsOf: authBytes)
        block.append(contentsOf: Self.hpackEncodeString(configuration.host))

        // :method POST (or configured method)
        let method = configuration.uplinkHTTPMethod
        if method == "POST" {
            block.append(0x83) // POST = index 3
        } else if method == "GET" {
            block.append(0x82) // GET = index 2
        } else {
            // Literal :method
            var methodBytes = Self.hpackEncodeInteger(2, prefixBits: 6)
            methodBytes[0] |= 0x40
            block.append(contentsOf: methodBytes)
            block.append(contentsOf: Self.hpackEncodeString(method))
        }

        // :path — with session ID, optional seq, and config query string
        var path = configuration.normalizedPath
        if !sessionId.isEmpty && configuration.sessionPlacement == .path {
            path = appendToPath(path, sessionId)
        }
        if let seq, configuration.seqPlacement == .path {
            path = appendToPath(path, "\(seq)")
        }
        // Append query string: start with config's normalizedQuery, then add metadata
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

        // :scheme https
        block.append(0x87)

        // Xray-core's packet-up PostPacket does not send Content-Type.
        // Only stream-up uploads carry application/grpc here.
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

        // Session metadata in headers/cookies (non-path placements)
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

        // Seq metadata in headers/cookies (non-path placements)
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

        appendH2CommonHeaders(to: &block, path: path)

        return block
    }

    /// Appends common HPACK headers (user-agent, padding, custom headers) to a header block.
    private func appendH2CommonHeaders(to block: inout Data, path: String) {
        // user-agent — name index 58 (RFC 7541 Appendix A)
        let ua = configuration.headers["User-Agent"] ?? defaultUserAgent
        var uaBytes = Self.hpackEncodeInteger(58, prefixBits: 6)
        uaBytes[0] |= 0x40
        block.append(contentsOf: uaBytes)
        block.append(contentsOf: Self.hpackEncodeString(ua))

        // X-Padding — applied based on configuration
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

        // Custom headers (literal, new names)
        // Filter hop-by-hop headers forbidden in HTTP/2 (matching Go's http2.Transport behavior:
        // h2_bundle.go encodeHeaders skips connection, proxy-connection, transfer-encoding,
        // upgrade, keep-alive, host, and content-length)
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

    /// Checks if the HEADERS response block starts with :status 200.
    /// Returns nil if status is 200 OK, or an error description string otherwise.
    func checkH2ResponseStatus(_ headerBlock: Data) -> String? {
        guard !headerBlock.isEmpty else { return "empty header block" }

        // Skip HPACK dynamic table size updates (prefix 001xxxxx, RFC 7541 §6.3).
        // Servers may send these at the start of a header block after a SETTINGS change.
        var offset = headerBlock.startIndex
        while offset < headerBlock.endIndex, headerBlock[offset] & 0xE0 == 0x20 {
            // Decode the 5-bit prefixed integer to find the entry's length
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

        // 1. Indexed representation (top bit set): static table index
        //    0x88=200, 0x89=204, 0x8a=206, 0x8b=304, 0x8c=400, 0x8d=404, 0x8e=500
        if first & 0x80 != 0 {
            if first == 0x88 { return nil } // 200 OK
            let indexedStatus: [UInt8: String] = [0x89: "204", 0x8a: "206", 0x8b: "304", 0x8c: "400", 0x8d: "404", 0x8e: "500"]
            if let status = indexedStatus[first] { return "status \(status)" }
            return "status (indexed \(first & 0x7F))"
        }

        // 2. Literal representations with :status name index
        //    HPACK static table entries 8-14 all have name ":status"
        //    0x08 = without indexing, 0x18 = never indexed, 0x48 = incremental indexing
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

        // Huffman-decode digits for status code (RFC 7541 Appendix B)
        // '0'=00000(5), '1'=00001(5), '2'=00010(5),
        // '3'=011000(6), '4'=011001(6), '5'=011010(6), '6'=011011(6),
        // '7'=011100(6), '8'=011101(6), '9'=011110(6)
        let status = Self.huffmanDecodeDigits(valueData)
        if status.isEmpty {
            let hex = valueData.map { String(format: "%02x", $0) }.joined(separator: " ")
            return "status (huffman: \(hex))"
        }
        return status == "200" ? nil : "status \(status)"
    }

    /// Huffman-decodes a byte sequence containing only ASCII digits (for HTTP status codes).
    ///
    /// RFC 7541 Appendix B / Go hpack/tables.go huffmanCodes:
    /// '0'=0x00(5), '1'=0x01(5), '2'=0x02(5),
    /// '3'=0x19(6), '4'=0x1a(6), '5'=0x1b(6), '6'=0x1c(6),
    /// '7'=0x1d(6), '8'=0x1e(6), '9'=0x1f(6)
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
