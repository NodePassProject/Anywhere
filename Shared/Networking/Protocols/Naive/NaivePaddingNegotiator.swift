//
//  NaivePaddingNegotiator.swift
//  Anywhere
//
//  Created by NodePassProject on 3/9/26.
//

import Foundation

enum NaivePaddingNegotiator {

    enum PaddingType: Int {
        case none = 0
        case variant1 = 1
    }

    // MARK: - Non-Indexed HPACK Characters

    /// The 17 printable ASCII characters with HPACK Huffman codes >= 8 bits; values built from them resist HPACK static indexing.
    private static let nonIndexCodes: [UInt8] = [
        0x21, // '!'
        0x22, // '"'
        0x23, // '#'
        0x24, // '$'
        0x26, // '&'
        0x27, // '''
        0x28, // '('
        0x29, // ')'
        0x2A, // '*'
        0x2B, // '+'
        0x2C, // ','
        0x3B, // ';'
        0x3C, // '<'
        0x3E, // '>'
        0x3F, // '?'
        0x40, // '@'
        0x58, // 'X'
    ]

    /// Generates a random padding header value of 16–32 non-indexed characters.
    static func generatePaddingValue() -> String {
        let length = Int.random(in: 16...32)
        var uniqueBits = UInt64.random(in: 0...UInt64.max)
        var chars = [UInt8](repeating: 0, count: length)

        let first = min(length, 16)
        for i in 0..<first {
            chars[i] = nonIndexCodes[Int(uniqueBits & 0b1111)]
            uniqueBits >>= 4
        }
        for i in first..<length {
            chars[i] = nonIndexCodes[16]
        }

        return String(bytes: chars, encoding: .ascii)!
    }

    // MARK: - Request Headers

    /// Padding headers for a CONNECT request; `fastOpen` adds `fastopen: 1` to skip negotiation when the padding type is cached.
    static func requestHeaders(fastOpen: Bool = false) -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = []
        headers.append((name: "padding", value: generatePaddingValue()))
        headers.append((name: "padding-type-request", value: "1, 0"))
        if fastOpen {
            headers.append((name: "fastopen", value: "1"))
        }
        return headers
    }

    // MARK: - Padding Type Cache

    /// Negotiated padding type per server, enabling `fastopen` to skip the round-trip on reuse.
    private static let cacheLock = UnfairLock()
    private static var paddingTypeCache: [String: PaddingType] = [:]

    static func cachedPaddingType(host: String, port: UInt16, sni: String) -> PaddingType? {
        let key = "\(host):\(port):\(sni)"
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return paddingTypeCache[key]
    }

    static func cachePaddingType(_ type: PaddingType, host: String, port: UInt16, sni: String) {
        let key = "\(host):\(port):\(sni)"
        cacheLock.lock()
        paddingTypeCache[key] = type
        cacheLock.unlock()
    }

    // MARK: - Response Parsing

    /// Parses the negotiated padding type from response headers; a bare `padding` header implies `.variant1` (backward compatibility, matching the C++ reference).
    static func parseResponse(headers: [(name: String, value: String)]) -> PaddingType {
        if let replyHeader = headers.first(where: { $0.name.lowercased() == "padding-type-reply" }) {
            let trimmed = replyHeader.value.trimmingCharacters(in: .whitespaces)
            if let rawValue = Int(trimmed), let type = PaddingType(rawValue: rawValue) {
                return type
            }
        }

        if headers.contains(where: { $0.name.lowercased() == "padding" }) {
            return .variant1
        }

        return .none
    }
}
