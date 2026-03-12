//
//  NaivePaddingNegotiator.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation

/// Handles NaiveProxy padding header generation and response parsing.
enum NaivePaddingNegotiator {

    /// Negotiated padding type.
    enum PaddingType: Int {
        case none = 0
        case variant1 = 1
    }

    // MARK: - Non-Indexed HPACK Characters

    /// The 17 printable ASCII characters (0x20–0x7f) whose HPACK Huffman codes are >= 8 bits,
    /// iterated in Huffman table order. These are used to generate padding header values
    /// that cannot be compactly indexed by HPACK, making them indistinguishable from real headers.
    ///
    /// Characters: ! " # $ & ' ( ) * + , ; < > ? @ X
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
    ///
    /// The first 16 characters are selected using 4-bit chunks from a random 64-bit value
    /// (indexing into the first 16 entries of `nonIndexCodes`). Remaining characters use
    /// the 17th entry ('X').
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

    /// Generates the padding-related headers for a CONNECT request.
    ///
    /// - Parameter fastOpen: If `true`, includes the `fastopen: 1` header (used when
    ///   the server's padding type is already known from a previous connection).
    /// - Returns: An array of (name, value) header pairs.
    static func requestHeaders(fastOpen: Bool = false) -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = []
        headers.append((name: "padding", value: generatePaddingValue()))
        headers.append((name: "padding-type-request", value: "1, 0"))
        if fastOpen {
            headers.append((name: "fastopen", value: "1"))
        }
        return headers
    }

    // MARK: - Response Parsing

    /// Parses the server's response headers to determine the negotiated padding type.
    ///
    /// Logic (matching the C++ reference implementation):
    /// 1. If `padding-type-reply` header exists, parse its value as a padding type.
    /// 2. Otherwise, if `padding` header exists, assume `.variant1` (backward compatibility).
    /// 3. Otherwise, `.none`.
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
