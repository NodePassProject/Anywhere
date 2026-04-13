//
//  HysteriaHTTP3Codec.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

enum HysteriaHTTP3Codec {

    // MARK: - Static table (RFC 9204 Appendix A — subset we care about)

    /// Full (name, value) entries for "Indexed Field Line" (pattern `1 T=1`).
    /// Covers only rows that can plausibly appear on a /auth response — the
    /// rest aren't relevant to Hysteria and would be dropped silently anyway.
    private static let entryByIndex: [Int: (name: String, value: String)] = [
        4:  ("content-length", "0"),
        24: (":status", "103"),
        25: (":status", "200"),
        26: (":status", "304"),
        27: (":status", "404"),
        28: (":status", "503"),
        63: (":status", "100"),
        64: (":status", "204"),
        65: (":status", "206"),
        66: (":status", "302"),
        67: (":status", "400"),
        68: (":status", "403"),
        69: (":status", "421"),
        70: (":status", "425"),
        71: (":status", "500"),
    ]

    /// Static-table names referenced via "Literal Field Line with Name Reference"
    /// (pattern `01 N T=1`). The server may pick ANY index whose canonical
    /// name matches the header it wants to send, then override the value — e.g.
    /// `:status = "233"` for Hysteria `AuthOK` lands on one of indices 24-28
    /// or 63-71, not a specific one.
    private static let nameByIndex: [Int: String] = {
        var m: [Int: String] = [
            0: ":authority",
            1: ":path",
            4: "content-length",
            6: "date",
            // QPACK Appendix A also includes "hysteria-*" as literal names,
            // not via the static table.
        ]
        for i in [24, 25, 26, 27, 28, 63, 64, 65, 66, 67, 68, 69, 70, 71] {
            m[i] = ":status"
        }
        return m
    }()

    // MARK: - Request encoding

    /// Builds a complete HTTP/3 HEADERS frame carrying a POST /auth request.
    ///
    /// The wire layout is:
    ///   varint(type=0x01) | varint(len) | headerBlock
    ///
    /// `headerBlock` is:
    ///   0x00 0x00                                  (Required Insert Count + Delta Base, both 0)
    ///   indexed(:method = POST)                    (static table index 20)
    ///   indexed(:scheme = https)                   (static table index 23)
    ///   literalWithNameRef(:authority, authority)  (static index 0)
    ///   literalWithNameRef(:path, path)            (static index 1)
    ///   literalFieldLine(name, value)              (one per extra header)
    static func encodeAuthRequestFrame(
        authority: String,
        path: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()
        block.append(0x00) // Required Insert Count = 0
        block.append(0x00) // S = 0, Delta Base = 0

        // :method = POST  — static table index 20
        block.append(contentsOf: indexedField(staticIndex: 20))
        // :scheme = https — static table index 23
        block.append(contentsOf: indexedField(staticIndex: 23))
        // :authority / :path — literal with static name ref
        block.append(contentsOf: literalWithNameRef(staticIndex: 0, value: authority))
        block.append(contentsOf: literalWithNameRef(staticIndex: 1, value: path))

        for h in extraHeaders {
            block.append(contentsOf: literalFieldLine(name: h.name, value: h.value))
        }

        // Wrap in an HTTP/3 HEADERS frame.
        var frame = Data()
        frame.append(contentsOf: encodeQUICVarInt(0x01)) // type = HEADERS
        frame.append(contentsOf: encodeQUICVarInt(UInt64(block.count)))
        frame.append(block)
        return frame
    }

    // MARK: - Response decoding

    /// Decodes a QPACK-encoded header block into `(name, value)` pairs, or
    /// returns nil if the block is malformed. Works correctly on both
    /// zero-indexed and sliced `Data` inputs.
    static func decodeHeaderBlock(_ data: Data) -> [(name: String, value: String)]? {
        guard data.count >= 2 else { return nil }
        let base = data.startIndex
        var offset = 0

        // Required Insert Count (8-bit prefix). We advertise dynamic table = 0,
        // so a compliant peer MUST send 0.
        guard let (ric, ricLen) = decodePrefixedInt(data, offset: offset, prefixBits: 8) else { return nil }
        guard ric == 0 else { return nil }
        offset += ricLen

        // Delta Base: sign bit + 7-bit prefix.
        guard offset < data.count else { return nil }
        guard let (_, dbLen) = decodePrefixedInt(data, offset: offset, prefixBits: 7) else { return nil }
        offset += dbLen

        var headers: [(name: String, value: String)] = []

        while offset < data.count {
            let byte = data[base + offset]

            if byte & 0x80 != 0 {
                // 1 T=? index  — Indexed field line (dynamic references rejected).
                let isStatic = (byte & 0x40) != 0
                guard isStatic else { return nil }
                guard let (index, len) = decodePrefixedInt(data, offset: offset, prefixBits: 6) else { return nil }
                offset += len
                if let entry = entryByIndex[Int(index)] {
                    headers.append(entry)
                }
                // Any other pre-indexed field is irrelevant for /auth; drop silently.

            } else if byte & 0x40 != 0 {
                // 01 N T=? index  — Literal with name reference.
                let isStatic = (byte & 0x10) != 0
                guard isStatic else { return nil }
                guard let (nameIdx, nameLen) = decodePrefixedInt(data, offset: offset, prefixBits: 4) else { return nil }
                offset += nameLen
                guard let (value, valueLen) = decodeString(data, offset: offset) else { return nil }
                offset += valueLen
                if let name = nameByIndex[Int(nameIdx)] {
                    headers.append((name: name, value: value))
                }

            } else if byte & 0x20 != 0 {
                // 001 N H — Literal field line with literal name.
                // Go's net/http (used by the reference Hysteria server)
                // Huffman-encodes both name and value by default.
                let isHuffmanName = (byte & 0x08) != 0
                guard let (nameLen, nameLenBytes) = decodePrefixedInt(data, offset: offset, prefixBits: 3) else { return nil }
                offset += nameLenBytes
                guard offset + Int(nameLen) <= data.count else { return nil }
                let nameStart = base + offset
                let nameEnd = nameStart + Int(nameLen)
                let nameBytes = Data(data[nameStart..<nameEnd])
                offset += Int(nameLen)
                let name: String?
                if isHuffmanName {
                    name = HPACKHuffman.decode(nameBytes).flatMap { String(bytes: $0, encoding: .utf8) }
                } else {
                    name = String(data: nameBytes, encoding: .utf8)
                }
                guard let decodedName = name else { return nil }

                guard let (value, valueLen) = decodeString(data, offset: offset) else { return nil }
                offset += valueLen
                headers.append((name: decodedName.lowercased(), value: value))

            } else {
                // Post-base patterns reference the dynamic table. We advertised 0,
                // so this is a peer protocol error.
                return nil
            }
        }

        return headers
    }

    // MARK: - Encoding helpers

    /// Indexed field line pointing into the static table.
    /// Pattern: `1 T=1 Index(6+)`.
    private static func indexedField(staticIndex: Int) -> Data {
        var out = Data()
        appendPrefixedInt(&out, value: UInt64(staticIndex), prefixBits: 6, prefix: 0b1100_0000)
        return out
    }

    /// Literal field line with static name reference.
    /// Pattern: `01 N=0 T=1 NameIndex(4+)` then encoded value string.
    private static func literalWithNameRef(staticIndex: Int, value: String) -> Data {
        var out = Data()
        appendPrefixedInt(&out, value: UInt64(staticIndex), prefixBits: 4, prefix: 0b0101_0000)
        appendString(&out, value)
        return out
    }

    /// Literal field line with literal name.
    /// Pattern: `001 N=0 H=0 NameLen(3+)` name `ValueLen(7+)` value (Huffman=0).
    private static func literalFieldLine(name: String, value: String) -> Data {
        var out = Data()
        let nameBytes = Data(name.utf8)
        appendPrefixedInt(&out, value: UInt64(nameBytes.count), prefixBits: 3, prefix: 0b0010_0000)
        out.append(nameBytes)
        appendString(&out, value)
        return out
    }

    /// Appends an integer encoded with the QPACK N-bit prefix form (RFC 7541 §5.1).
    private static func appendPrefixedInt(
        _ out: inout Data,
        value: UInt64,
        prefixBits: Int,
        prefix: UInt8
    ) {
        let max = UInt64((1 << prefixBits) - 1)
        if value < max {
            out.append(prefix | UInt8(value))
            return
        }
        out.append(prefix | UInt8(max))
        var remaining = value - max
        while remaining >= 128 {
            out.append(UInt8(remaining & 0x7F) | 0x80)
            remaining >>= 7
        }
        out.append(UInt8(remaining))
    }

    /// Appends a raw (non-Huffman) length-prefixed string.
    /// Pattern: `H=0 Len(7+)` then UTF-8 bytes.
    private static func appendString(_ out: inout Data, _ value: String) {
        let bytes = Data(value.utf8)
        appendPrefixedInt(&out, value: UInt64(bytes.count), prefixBits: 7, prefix: 0x00)
        out.append(bytes)
    }

    // MARK: - Decoding helpers (slice-safe)

    /// Decodes an N-bit prefixed integer. `offset` is relative to
    /// `data.startIndex` so slices don't trap.
    private static func decodePrefixedInt(
        _ data: Data,
        offset: Int,
        prefixBits: Int
    ) -> (value: UInt64, bytesConsumed: Int)? {
        let base = data.startIndex
        guard offset < data.count else { return nil }
        let mask = UInt8((1 << prefixBits) - 1)
        let first = data[base + offset] & mask

        if first < mask {
            return (UInt64(first), 1)
        }

        var value = UInt64(mask)
        var shift: UInt64 = 0
        var pos = offset + 1
        while pos < data.count {
            let byte = data[base + pos]
            value += UInt64(byte & 0x7F) << shift
            pos += 1
            if byte & 0x80 == 0 {
                return (value, pos - offset)
            }
            shift += 7
            if shift > 63 { return nil } // overflow guard
        }
        return nil
    }

    /// Decodes a length-prefixed string. Handles both raw UTF-8 and Huffman
    /// (RFC 7541 Appendix B, shared between HPACK and QPACK) since Go's
    /// net/http — the reference Hysteria server — Huffman-encodes responses
    /// by default.
    private static func decodeString(_ data: Data, offset: Int) -> (value: String, bytesConsumed: Int)? {
        let base = data.startIndex
        guard offset < data.count else { return nil }
        let isHuffman = (data[base + offset] & 0x80) != 0
        guard let (length, lenBytes) = decodePrefixedInt(data, offset: offset, prefixBits: 7) else { return nil }

        let strStart = offset + lenBytes
        guard strStart + Int(length) <= data.count else { return nil }
        let dataStart = base + strStart
        let dataEnd = dataStart + Int(length)
        let bytes = Data(data[dataStart..<dataEnd])
        let str: String?
        if isHuffman {
            str = HPACKHuffman.decode(bytes).flatMap { String(bytes: $0, encoding: .utf8) }
        } else {
            str = String(data: bytes, encoding: .utf8)
        }
        guard let str else { return nil }
        return (str, lenBytes + Int(length))
    }

    // MARK: - QUIC varint

    /// Encodes a varint per RFC 9000 §16. Traps on overflow; 62-bit cap is
    /// enforced by callers (header block lengths never approach it).
    private static func encodeQUICVarInt(_ value: UInt64) -> Data {
        if value < (1 << 6) {
            return Data([UInt8(value)])
        }
        if value < (1 << 14) {
            let v = value | (UInt64(0b01) << 14)
            return Data([UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)])
        }
        if value < (1 << 30) {
            let v = value | (UInt64(0b10) << 30)
            return Data([
                UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
                UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF),
            ])
        }
        let v = value | (UInt64(0b11) << 62)
        return Data([
            UInt8((v >> 56) & 0xFF), UInt8((v >> 48) & 0xFF),
            UInt8((v >> 40) & 0xFF), UInt8((v >> 32) & 0xFF),
            UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
            UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF),
        ])
    }
}
