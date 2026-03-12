//
//  HPACKEncoder.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/9/26.
//

import Foundation

/// Minimal HPACK encoder/decoder for the NaiveProxy CONNECT tunnel.
///
/// Only implements the subset needed for a single CONNECT request/response:
/// - Integer encoding/decoding (RFC 7541 §5.1)
/// - String encoding (raw only) and decoding (raw + Huffman)
/// - Indexed header field (1xxxxxxx)
/// - Literal without indexing (0000xxxx)
/// - Literal with incremental indexing (01xxxxxx) — decode only
/// - Static table lookup
enum HPACKEncoder {

    // MARK: - CONNECT Request Encoding

    /// Encodes an HTTP/2 CONNECT request header block.
    ///
    /// Produces HPACK-encoded headers:
    /// - `:method = CONNECT` (literal with indexed name, static index 2)
    /// - `:authority = <authority>` (literal with indexed name, static index 1)
    /// - Extra headers (proxy-authorization, padding, etc.)
    static func encodeConnectRequest(
        authority: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()
        // :method = CONNECT — literal without indexing, name index 2 (:method)
        encodeLiteralWithoutIndexing(nameIndex: 2, value: "CONNECT", into: &block)
        // :authority = host:port — literal without indexing, name index 1 (:authority)
        encodeLiteralWithoutIndexing(nameIndex: 1, value: authority, into: &block)
        // Extra headers
        for header in extraHeaders {
            if let nameIdx = staticTableNameIndex(header.name) {
                encodeLiteralWithoutIndexing(nameIndex: nameIdx, value: header.value, into: &block)
            } else {
                encodeLiteralWithoutIndexing(name: header.name, value: header.value, into: &block)
            }
        }
        return block
    }

    // MARK: - Response Decoding

    /// Decodes an HPACK header block into name-value pairs.
    ///
    /// Handles indexed, literal with/without indexing, and dynamic table size updates.
    /// Maintains a local dynamic table for the duration of the decode.
    static func decodeHeaders(from data: Data) -> [(name: String, value: String)]? {
        var headers: [(name: String, value: String)] = []
        var offset = data.startIndex
        var dynamicTable: [(name: String, value: String)] = []

        while offset < data.endIndex {
            let byte = data[offset]

            if byte & 0x80 != 0 {
                // §6.1 Indexed Header Field (1xxxxxxx)
                let index = decodeInteger(from: data, at: &offset, prefixBits: 7)
                guard let index, let entry = lookupEntry(index, dynamicTable: dynamicTable) else {
                    return nil
                }
                headers.append(entry)

            } else if byte & 0xC0 == 0x40 {
                // §6.2.1 Literal with Incremental Indexing (01xxxxxx)
                guard let (name, value) = decodeLiteral(from: data, at: &offset, prefixBits: 6,
                                                        dynamicTable: dynamicTable) else { return nil }
                headers.append((name, value))
                dynamicTable.insert((name, value), at: 0)

            } else if byte & 0xF0 == 0x00 || byte & 0xF0 == 0x10 {
                // §6.2.2/§6.2.3 Literal without Indexing / Never Indexed (0000xxxx / 0001xxxx)
                guard let (name, value) = decodeLiteral(from: data, at: &offset, prefixBits: 4,
                                                        dynamicTable: dynamicTable) else { return nil }
                headers.append((name, value))

            } else if byte & 0xE0 == 0x20 {
                // §6.3 Dynamic Table Size Update (001xxxxx)
                let _ = decodeInteger(from: data, at: &offset, prefixBits: 5)
                // We don't need to enforce table size for our minimal client
            } else {
                return nil  // Unknown representation
            }
        }

        return headers
    }

    // MARK: - Integer Encoding (RFC 7541 §5.1)

    /// Encodes an integer with the given prefix bit width, appending to `data`.
    ///
    /// The first byte written shares bits with a `prefix` byte — caller must OR in the high bits.
    static func encodeInteger(_ value: Int, prefixBits: Int, into data: inout Data) {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            data.append(UInt8(value))
        } else {
            data.append(UInt8(maxPrefix))
            var remaining = value - maxPrefix
            while remaining >= 128 {
                data.append(UInt8(remaining % 128 + 128))
                remaining /= 128
            }
            data.append(UInt8(remaining))
        }
    }

    /// Decodes an integer with the given prefix bit width from `data` at `offset`.
    /// Advances `offset` past the consumed bytes.
    static func decodeInteger(from data: Data, at offset: inout Int, prefixBits: Int) -> Int? {
        guard offset < data.endIndex else { return nil }
        let maxPrefix = (1 << prefixBits) - 1
        var value = Int(data[offset] & UInt8(maxPrefix))
        offset += 1

        if value < maxPrefix {
            return value
        }

        var m = 0
        repeat {
            guard offset < data.endIndex else { return nil }
            let b = data[offset]
            offset += 1
            value += Int(b & 0x7F) << m
            m += 7
            if b & 0x80 == 0 { break }
        } while true

        return value
    }

    // MARK: - String Encoding (RFC 7541 §5.2)

    /// Encodes a string in raw (non-Huffman) format.
    static func encodeString(_ string: String, into data: inout Data) {
        let bytes = [UInt8](string.utf8)
        // H=0 (raw), length
        var lengthData = Data()
        encodeInteger(bytes.count, prefixBits: 7, into: &lengthData)
        lengthData[lengthData.startIndex] &= 0x7F  // Clear H bit
        data.append(lengthData)
        data.append(contentsOf: bytes)
    }

    /// Decodes a string (raw or Huffman) from `data` at `offset`.
    static func decodeString(from data: Data, at offset: inout Int) -> String? {
        guard offset < data.endIndex else { return nil }
        let huffman = data[offset] & 0x80 != 0
        guard let length = decodeInteger(from: data, at: &offset, prefixBits: 7) else { return nil }
        guard offset + length <= data.endIndex else { return nil }

        let stringData = data[offset..<(offset + length)]
        offset += length

        if huffman {
            guard let decoded = HPACKHuffman.decode(stringData) else { return nil }
            return String(bytes: decoded, encoding: .utf8)
        } else {
            return String(bytes: stringData, encoding: .utf8)
        }
    }

    // MARK: - Literal Header Encoding

    /// Encodes a literal header without indexing, using an indexed name from the static table.
    private static func encodeLiteralWithoutIndexing(nameIndex: Int, value: String, into data: inout Data) {
        // 0000xxxx prefix + name index
        var indexData = Data()
        encodeInteger(nameIndex, prefixBits: 4, into: &indexData)
        indexData[indexData.startIndex] &= 0x0F  // Ensure 0000 prefix
        data.append(indexData)
        encodeString(value, into: &data)
    }

    /// Encodes a literal header without indexing, using a literal name.
    private static func encodeLiteralWithoutIndexing(name: String, value: String, into data: inout Data) {
        data.append(0x00)  // 0000 0000 — literal name, no indexing
        encodeString(name, into: &data)
        encodeString(value, into: &data)
    }

    // MARK: - Literal Header Decoding

    /// Decodes a literal header field from `data` at `offset`.
    private static func decodeLiteral(
        from data: Data,
        at offset: inout Int,
        prefixBits: Int,
        dynamicTable: [(name: String, value: String)]
    ) -> (name: String, value: String)? {
        guard let nameIndex = decodeInteger(from: data, at: &offset, prefixBits: prefixBits) else {
            return nil
        }

        let name: String
        if nameIndex == 0 {
            guard let n = decodeString(from: data, at: &offset) else { return nil }
            name = n
        } else {
            guard let entry = lookupEntry(nameIndex, dynamicTable: dynamicTable) else { return nil }
            name = entry.name
        }

        guard let value = decodeString(from: data, at: &offset) else { return nil }
        return (name, value)
    }

    // MARK: - Table Lookup

    /// Looks up a header by index (1-based). Static table is indices 1–61,
    /// dynamic table starts at 62.
    private static func lookupEntry(
        _ index: Int,
        dynamicTable: [(name: String, value: String)]
    ) -> (name: String, value: String)? {
        guard index >= 1 else { return nil }
        if index <= staticTable.count {
            return staticTable[index - 1]
        }
        let dynIndex = index - staticTable.count - 1
        guard dynIndex < dynamicTable.count else { return nil }
        return dynamicTable[dynIndex]
    }

    /// Returns the first static table index whose name matches (case-insensitive), or `nil`.
    private static func staticTableNameIndex(_ name: String) -> Int? {
        let lower = name.lowercased()
        for (i, entry) in staticTable.enumerated() {
            if entry.name == lower { return i + 1 }  // 1-based
        }
        return nil
    }

    // MARK: - HPACK Static Table (RFC 7541 Appendix A)

    private static let staticTable: [(name: String, value: String)] = [
        (":authority", ""),                          // 1
        (":method", "GET"),                          // 2
        (":method", "POST"),                         // 3
        (":path", "/"),                              // 4
        (":path", "/index.html"),                    // 5
        (":scheme", "http"),                         // 6
        (":scheme", "https"),                        // 7
        (":status", "200"),                          // 8
        (":status", "204"),                          // 9
        (":status", "206"),                          // 10
        (":status", "304"),                          // 11
        (":status", "400"),                          // 12
        (":status", "404"),                          // 13
        (":status", "500"),                          // 14
        ("accept-charset", ""),                      // 15
        ("accept-encoding", "gzip, deflate"),        // 16
        ("accept-language", ""),                     // 17
        ("accept-ranges", ""),                       // 18
        ("accept", ""),                              // 19
        ("access-control-allow-origin", ""),         // 20
        ("age", ""),                                 // 21
        ("allow", ""),                               // 22
        ("authorization", ""),                       // 23
        ("cache-control", ""),                       // 24
        ("content-disposition", ""),                 // 25
        ("content-encoding", ""),                    // 26
        ("content-language", ""),                    // 27
        ("content-length", ""),                      // 28
        ("content-location", ""),                    // 29
        ("content-range", ""),                       // 30
        ("content-type", ""),                        // 31
        ("cookie", ""),                              // 32
        ("date", ""),                                // 33
        ("etag", ""),                                // 34
        ("expect", ""),                              // 35
        ("expires", ""),                             // 36
        ("from", ""),                                // 37
        ("host", ""),                                // 38
        ("if-match", ""),                            // 39
        ("if-modified-since", ""),                   // 40
        ("if-none-match", ""),                       // 41
        ("if-range", ""),                            // 42
        ("if-unmodified-since", ""),                 // 43
        ("last-modified", ""),                       // 44
        ("link", ""),                                // 45
        ("location", ""),                            // 46
        ("max-forwards", ""),                        // 47
        ("proxy-authenticate", ""),                  // 48
        ("proxy-authorization", ""),                 // 49
        ("range", ""),                               // 50
        ("referer", ""),                             // 51
        ("refresh", ""),                             // 52
        ("retry-after", ""),                         // 53
        ("server", ""),                              // 54
        ("set-cookie", ""),                          // 55
        ("strict-transport-security", ""),           // 56
        ("transfer-encoding", ""),                   // 57
        ("user-agent", ""),                          // 58
        ("vary", ""),                                // 59
        ("via", ""),                                 // 60
        ("www-authenticate", ""),                    // 61
    ]
}

// MARK: - HPACK Huffman Decoder

/// Huffman decoder for HPACK string literals (RFC 7541 Appendix B).
private enum HPACKHuffman {

    /// Trie node for Huffman decoding. Children are array indices; -1 = no child.
    private struct Node {
        var left: Int32 = -1
        var right: Int32 = -1
        var symbol: Int16 = -1  // >= 0 for leaf nodes, 256 = EOS
    }

    /// Lazily-built decode trie.
    private static let tree: [Node] = {
        var nodes = [Node()]
        for (sym, entry) in huffmanTable.enumerated() {
            let (code, bits) = entry
            var idx = 0
            for bitPos in 0..<Int(bits) {
                let bit = (code >> (31 - UInt32(bitPos))) & 1
                if bit == 0 {
                    if nodes[idx].left < 0 {
                        nodes.append(Node())
                        nodes[idx].left = Int32(nodes.count - 1)
                    }
                    idx = Int(nodes[idx].left)
                } else {
                    if nodes[idx].right < 0 {
                        nodes.append(Node())
                        nodes[idx].right = Int32(nodes.count - 1)
                    }
                    idx = Int(nodes[idx].right)
                }
            }
            nodes[idx].symbol = Int16(sym)
        }
        return nodes
    }()

    /// Decodes Huffman-encoded bytes into raw bytes.
    static func decode(_ data: some Collection<UInt8>) -> [UInt8]? {
        var result: [UInt8] = []
        var nodeIdx = 0

        for byte in data {
            for bitPos in stride(from: 7, through: 0, by: -1) {
                let bit = (byte >> bitPos) & 1
                let next = bit == 0 ? tree[nodeIdx].left : tree[nodeIdx].right
                guard next >= 0 else { return nil }
                nodeIdx = Int(next)

                let sym = tree[nodeIdx].symbol
                if sym >= 0 {
                    if sym == 256 { return result }  // EOS
                    result.append(UInt8(sym))
                    nodeIdx = 0
                }
            }
        }

        // Remaining bits must be padding (all 1-bits, < 8 bits).
        // If we're at root, no padding needed.
        // If we're partway through, it's valid if we're on an all-1s path.
        return result
    }

    // MARK: - Huffman Code Table (RFC 7541 Appendix B)

    /// Each entry is (code: UInt32 left-aligned, bitLength: UInt8).
    /// Indexed by symbol value 0–256 (256 = EOS).
    // swiftlint:disable:next function_body_length
    private static let huffmanTable: [(UInt32, UInt8)] = [
        (0xffc00000, 13), (0xffffb000, 23), (0xfffffe20, 28), (0xfffffe30, 28),
        (0xfffffe40, 28), (0xfffffe50, 28), (0xfffffe60, 28), (0xfffffe70, 28),
        (0xfffffe80, 28), (0xffffea00, 24), (0xfffffff0, 30), (0xfffffe90, 28),
        (0xfffffea0, 28), (0xfffffff4, 30), (0xfffffeb0, 28), (0xfffffec0, 28),
        (0xfffffed0, 28), (0xfffffee0, 28), (0xfffffef0, 28), (0xffffff00, 28),
        (0xffffff10, 28), (0xffffff20, 28), (0xfffffff8, 30), (0xffffff30, 28),
        (0xffffff40, 28), (0xffffff50, 28), (0xffffff60, 28), (0xffffff70, 28),
        (0xffffff80, 28), (0xffffff90, 28), (0xffffffa0, 28), (0xffffffb0, 28),
        // 32–63: printable ASCII
        (0x50000000,  6), (0xfe000000, 10), (0xfe400000, 10), (0xffa00000, 12),
        (0xffc80000, 13), (0x54000000,  6), (0xf8000000,  8), (0xff400000, 11),
        (0xfe800000, 10), (0xfec00000, 10), (0xf9000000,  8), (0xff600000, 11),
        (0xfa000000,  8), (0x58000000,  6), (0x5c000000,  6), (0x60000000,  6),
        (0x00000000,  5), (0x08000000,  5), (0x10000000,  5), (0x64000000,  6),
        (0x68000000,  6), (0x6c000000,  6), (0x70000000,  6), (0x74000000,  6),
        (0x78000000,  6), (0x7c000000,  6), (0xb8000000,  7), (0xfb000000,  8),
        (0xfff80000, 15), (0x80000000,  6), (0xffb00000, 12), (0xff000000, 10),
        // 64–95
        (0xffd00000, 13), (0x84000000,  6), (0xba000000,  7), (0xbc000000,  7),
        (0xbe000000,  7), (0xc0000000,  7), (0xc2000000,  7), (0xc4000000,  7),
        (0xc6000000,  7), (0xc8000000,  7), (0xca000000,  7), (0xcc000000,  7),
        (0xce000000,  7), (0xd0000000,  7), (0xd2000000,  7), (0xd4000000,  7),
        (0xd6000000,  7), (0xd8000000,  7), (0xda000000,  7), (0xdc000000,  7),
        (0xde000000,  7), (0xe0000000,  7), (0xe2000000,  7), (0xe4000000,  7),
        (0xfc000000,  8), (0xe6000000,  7), (0xfd000000,  8), (0xffd80000, 13),
        (0xfffe0000, 19), (0xffe00000, 13), (0xfff00000, 14), (0x88000000,  6),
        // 96–127
        (0xfffa0000, 15), (0x18000000,  5), (0x8c000000,  6), (0x20000000,  5),
        (0x90000000,  6), (0x28000000,  5), (0x94000000,  6), (0x98000000,  6),
        (0x9c000000,  6), (0x30000000,  5), (0xe8000000,  7), (0xea000000,  7),
        (0xa0000000,  6), (0xa4000000,  6), (0xa8000000,  6), (0x38000000,  5),
        (0xac000000,  6), (0xec000000,  7), (0xb0000000,  6), (0x40000000,  5),
        (0x48000000,  5), (0xb4000000,  6), (0xee000000,  7), (0xf0000000,  7),
        (0xf2000000,  7), (0xf4000000,  7), (0xf6000000,  7), (0xfffc0000, 15),
        (0xff800000, 11), (0xfff40000, 14), (0xffe80000, 13), (0xffffffc0, 28),
        // 128–159
        (0xfffe6000, 20), (0xffff4800, 22), (0xfffe7000, 20), (0xfffe8000, 20),
        (0xffff4c00, 22), (0xffff5000, 22), (0xffff5400, 22), (0xffffb200, 23),
        (0xffff5800, 22), (0xffffb400, 23), (0xffffb600, 23), (0xffffb800, 23),
        (0xffffba00, 23), (0xffffbc00, 23), (0xffffeb00, 24), (0xffffbe00, 23),
        (0xffffec00, 24), (0xffffed00, 24), (0xffff5c00, 22), (0xffffc000, 23),
        (0xffffee00, 24), (0xffffc200, 23), (0xffffc400, 23), (0xffffc600, 23),
        (0xffffc800, 23), (0xfffee000, 21), (0xffff6000, 22), (0xffffca00, 23),
        (0xffff6400, 22), (0xffffcc00, 23), (0xffffce00, 23), (0xffffef00, 24),
        // 160–191
        (0xffff6800, 22), (0xfffee800, 21), (0xfffe9000, 20), (0xffff6c00, 22),
        (0xffff7000, 22), (0xffffd000, 23), (0xffffd200, 23), (0xfffef000, 21),
        (0xffffd400, 23), (0xffff7400, 22), (0xffff7800, 22), (0xfffff000, 24),
        (0xfffef800, 21), (0xffff7c00, 22), (0xffffd600, 23), (0xffffd800, 23),
        (0xffff0000, 21), (0xffff0800, 21), (0xffff8000, 22), (0xffff1000, 21),
        (0xffffda00, 23), (0xffff8400, 22), (0xffffdc00, 23), (0xffffde00, 23),
        (0xfffea000, 20), (0xffff8800, 22), (0xffff8c00, 22), (0xffff9000, 22),
        (0xffffe000, 23), (0xffff9400, 22), (0xffff9800, 22), (0xffffe200, 23),
        // 192–223
        (0xfffff800, 26), (0xfffff840, 26), (0xfffeb000, 20), (0xfffe2000, 19),
        (0xffff9c00, 22), (0xffffe400, 23), (0xffffa000, 22), (0xfffff600, 25),
        (0xfffff880, 26), (0xfffff8c0, 26), (0xfffff900, 26), (0xfffffbc0, 27),
        (0xfffffbe0, 27), (0xfffff940, 26), (0xfffff100, 24), (0xfffff680, 25),
        (0xfffe4000, 19), (0xffff1800, 21), (0xfffff980, 26), (0xfffffc00, 27),
        (0xfffffc20, 27), (0xfffff9c0, 26), (0xfffffc40, 27), (0xfffff200, 24),
        (0xffff2000, 21), (0xffff2800, 21), (0xfffffa00, 26), (0xfffffa40, 26),
        (0xffffffd0, 28), (0xfffffc60, 27), (0xfffffc80, 27), (0xfffffca0, 27),
        // 224–256 (256 = EOS)
        (0xfffec000, 20), (0xfffff300, 24), (0xfffed000, 20), (0xffff3000, 21),
        (0xffffa400, 22), (0xffff3800, 21), (0xffff4000, 21), (0xffffe600, 23),
        (0xffffa800, 22), (0xffffac00, 22), (0xfffff700, 25), (0xfffff780, 25),
        (0xfffff400, 24), (0xfffff500, 24), (0xfffffa80, 26), (0xffffe800, 23),
        (0xfffffac0, 26), (0xfffffcc0, 27), (0xfffffb00, 26), (0xfffffb40, 26),
        (0xfffffce0, 27), (0xfffffd00, 27), (0xfffffd20, 27), (0xfffffd40, 27),
        (0xfffffd60, 27), (0xffffffe0, 28), (0xfffffd80, 27), (0xfffffda0, 27),
        (0xfffffdc0, 27), (0xfffffde0, 27), (0xfffffe00, 27), (0xfffffb80, 26),
        (0xfffffffc, 30),  // 256 = EOS
    ]
}
