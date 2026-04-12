//
//  QPACKEncoder.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/11/26.
//

import Foundation

// MARK: - QPACK Static Table (Subset)

/// Indices into the QPACK static table (RFC 9204, Appendix A).
private enum QPACKStaticIndex: Int {
    case methodConnect  = 15  // :method = CONNECT
    case status200      = 25  // :status = 200
}

// MARK: - QPACKEncoder

enum QPACKEncoder {

    /// Encodes HTTP/3 CONNECT headers into a QPACK header block.
    ///
    /// For a CONNECT request, the pseudo-headers are:
    /// - `:method` = CONNECT (static table index 15)
    /// - `:authority` = host:port (literal with name reference)
    ///
    /// No `:scheme` or `:path` headers for CONNECT (RFC 9114 §4.4).
    ///
    /// - Parameters:
    ///   - authority: The target `host:port`.
    ///   - extraHeaders: Additional headers (User-Agent, padding, auth, etc.).
    /// - Returns: QPACK-encoded header block (with required prefix bytes).
    static func encodeConnectHeaders(
        authority: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()

        // QPACK header block prefix: Required Insert Count (0) + Delta Base (0)
        // Both are 0 since we don't use the dynamic table.
        block.append(0x00) // Required Insert Count = 0
        block.append(0x00) // S=0, Delta Base = 0

        // :method = CONNECT (indexed field line, static table)
        // Prefix 1xxxxxxx, T=1 (static), index 15
        block.append(contentsOf: encodeIndexedFieldLine(QPACKStaticIndex.methodConnect.rawValue))

        // :authority = <authority> (literal with name reference)
        // :authority is static table index 0
        block.append(contentsOf: encodeLiteralWithNameRef(
            staticIndex: 0, value: authority
        ))

        // Extra headers as literal field lines
        for header in extraHeaders {
            block.append(contentsOf: encodeLiteralFieldLine(
                name: header.name, value: header.value
            ))
        }

        return block
    }

    /// Decodes QPACK-encoded headers from a response header block.
    ///
    /// Returns an array of (name, value) pairs, or nil if the block is malformed
    /// or references the dynamic table. We advertise `QPACK_MAX_TABLE_CAPACITY=0`
    /// in SETTINGS, so a compliant server must not emit dynamic references; treat
    /// any such reference as a protocol violation rather than silently dropping
    /// the field.
    static func decodeHeaders(from data: Data) -> [(name: String, value: String)]? {
        var headers: [(name: String, value: String)] = []
        guard data.count >= 2 else { return nil }

        var offset = 0

        // QPACK header block prefix: Required Insert Count + Delta Base.
        // With a disabled dynamic table, Required Insert Count MUST be 0.
        guard let (requiredInsertCount, ricLen) =
                decodeVarIntPrefix(from: data, offset: offset, prefixBits: 8) else { return nil }
        offset += ricLen
        guard requiredInsertCount == 0 else { return nil }

        guard offset < data.count else { return nil }
        // Delta Base uses 7-bit prefix after the sign bit
        guard let (_, dbLen) = decodeVarIntPrefix(from: data, offset: offset, prefixBits: 7) else {
            return nil
        }
        offset += dbLen

        // Decode field lines
        while offset < data.count {
            let byte = data[offset]

            if byte & 0x80 != 0 {
                // Indexed field line (1 T=static index).
                // Dynamic table (T=0) is not supported.
                let isStatic = (byte & 0x40) != 0
                guard isStatic else { return nil }
                guard let (index, len) =
                        decodeVarIntPrefix(from: data, offset: offset, prefixBits: 6) else { return nil }
                offset += len
                // Our static table is a subset of RFC 9204 Appendix A. Indices
                // we don't recognise belong to the canonical static table too
                // (e.g. "content-type") — skip them rather than fail, matching
                // how the previous silent-drop behaviour interoperated with
                // real origin servers.
                if let entry = staticTableEntry(Int(index)) {
                    headers.append(entry)
                }
            } else if byte & 0x40 != 0 {
                // Literal with name reference (01 N T=static name-index).
                // Dynamic table name references (T=0) are not supported.
                let isStatic = (byte & 0x10) != 0
                guard isStatic else { return nil }
                guard let (nameIdx, nameLen) =
                        decodeVarIntPrefix(from: data, offset: offset, prefixBits: 4) else { return nil }
                offset += nameLen
                guard let (value, valueLen) = decodeString(from: data, offset: offset) else { return nil }
                offset += valueLen
                if let name = staticTableName(Int(nameIdx)) {
                    headers.append((name: name, value: value))
                }
            } else if byte & 0x20 != 0 {
                // Literal field line with literal name: 001 N H NameLen(3+) Name Value
                let nameHuffman = (byte & 0x08) != 0
                guard let (nameLen, nameLenBytes) =
                        decodeVarIntPrefix(from: data, offset: offset, prefixBits: 3) else { return nil }
                offset += nameLenBytes
                guard offset + Int(nameLen) <= data.count else { return nil }
                let nameData = Data(data[offset..<(offset + Int(nameLen))])
                offset += Int(nameLen)
                let nameStr: String?
                if nameHuffman {
                    if let decoded = HPACKHuffman.decode(nameData) {
                        nameStr = String(bytes: decoded, encoding: .utf8)
                    } else { nameStr = nil }
                } else {
                    nameStr = String(data: nameData, encoding: .utf8)
                }
                guard let name = nameStr else { return nil }

                guard let (value, vLen) = decodeString(from: data, offset: offset) else { return nil }
                offset += vLen
                headers.append((name: name, value: value))
            } else {
                // Remaining patterns are Indexed field line with post-base index
                // (0001xxxx) and Literal with post-base name reference (0000xxxx),
                // both of which reference the dynamic table.
                return nil
            }
        }

        return headers
    }

    /// Encodes HTTP/3 POST request headers into a QPACK header block.
    ///
    /// For a regular (non-CONNECT) request:
    /// - `:method`    = POST   (static table index 20)
    /// - `:scheme`    = https  (static table index 23)
    /// - `:authority`          (literal with name ref, static index 0)
    /// - `:path`               (literal with name ref, static index 1)
    ///
    /// - Parameters:
    ///   - authority: The target host (e.g. "hysteria").
    ///   - path: The request path (e.g. "/auth").
    ///   - extraHeaders: Additional headers.
    /// - Returns: QPACK-encoded header block.
    static func encodePostHeaders(
        authority: String,
        path: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()
        block.append(0x00) // Required Insert Count = 0
        block.append(0x00) // S=0, Delta Base = 0

        // :method = POST (static table index 20)
        block.append(contentsOf: encodeIndexedFieldLine(20))
        // :scheme = https (static table index 23)
        block.append(contentsOf: encodeIndexedFieldLine(23))
        // :authority = <authority> (static index 0)
        block.append(contentsOf: encodeLiteralWithNameRef(staticIndex: 0, value: authority))
        // :path = <path> (static index 1)
        block.append(contentsOf: encodeLiteralWithNameRef(staticIndex: 1, value: path))

        for header in extraHeaders {
            block.append(contentsOf: encodeLiteralFieldLine(name: header.name, value: header.value))
        }
        return block
    }

    // MARK: - Encoding Helpers

    /// Indexed field line: 1 T(1) Index(6+)
    private static func encodeIndexedFieldLine(_ index: Int) -> Data {
        // T=1 (static), so first byte = 11xxxxxx
        return encodeVarIntWithPrefix(UInt64(index), prefixBits: 6, prefix: 0xC0)
    }

    /// Literal field line with name reference: 01 N(1) T(1) NameIndex(4+) Value(8+)
    private static func encodeLiteralWithNameRef(staticIndex: Int, value: String) -> Data {
        var data = Data()
        // 01 N=0 T=1 (static) → 0101xxxx = 0x50 + index
        data.append(contentsOf: encodeVarIntWithPrefix(UInt64(staticIndex), prefixBits: 4, prefix: 0x50))
        // Value: no Huffman (H=0), length + string
        data.append(contentsOf: encodeStringLiteral(value))
        return data
    }

    /// Literal field line with literal name: 001 N(1) Name(3+) Value(8+)
    private static func encodeLiteralFieldLine(name: String, value: String) -> Data {
        var data = Data()
        // 001 N=0 → 0010xxxx = 0x20 + name length
        let nameBytes = Data(name.lowercased().utf8)
        data.append(contentsOf: encodeVarIntWithPrefix(UInt64(nameBytes.count), prefixBits: 3, prefix: 0x20))
        data.append(nameBytes)
        data.append(contentsOf: encodeStringLiteral(value))
        return data
    }

    /// Encodes a string literal (H=0, no Huffman).
    private static func encodeStringLiteral(_ string: String) -> Data {
        let bytes = Data(string.utf8)
        var data = Data()
        // H=0, 7-bit length prefix
        data.append(contentsOf: encodeVarIntWithPrefix(UInt64(bytes.count), prefixBits: 7, prefix: 0x00))
        data.append(bytes)
        return data
    }

    /// Encodes a variable-length integer with a given prefix.
    private static func encodeVarIntWithPrefix(_ value: UInt64, prefixBits: Int, prefix: UInt8) -> Data {
        let maxPrefix = (1 << prefixBits) - 1
        var data = Data()

        if value < UInt64(maxPrefix) {
            data.append(prefix | UInt8(value))
        } else {
            data.append(prefix | UInt8(maxPrefix))
            var remaining = value - UInt64(maxPrefix)
            while remaining >= 128 {
                data.append(UInt8(remaining & 0x7F) | 0x80)
                remaining >>= 7
            }
            data.append(UInt8(remaining))
        }
        return data
    }

    // MARK: - Decoding Helpers

    private static func decodeVarIntPrefix(from data: Data, offset: Int, prefixBits: Int) -> (UInt64, Int)? {
        guard offset < data.count else { return nil }
        let mask = UInt8((1 << prefixBits) - 1)
        let first = data[offset] & mask

        if first < mask {
            return (UInt64(first), 1)
        }

        var value = UInt64(mask)
        var shift = 0
        var pos = offset + 1
        while pos < data.count {
            let byte = data[pos]
            value += UInt64(byte & 0x7F) << shift
            pos += 1
            if byte & 0x80 == 0 {
                return (value, pos - offset)
            }
            shift += 7
        }
        return nil
    }

    private static func decodeString(from data: Data, offset: Int) -> (String, Int)? {
        guard let (length, lenBytes) = decodeVarIntPrefix(from: data, offset: offset, prefixBits: 7) else {
            return nil
        }
        let isHuffman = (data[offset] & 0x80) != 0
        let strStart = offset + lenBytes
        guard strStart + Int(length) <= data.count else { return nil }

        let strData = Data(data[strStart..<(strStart + Int(length))])
        let str: String?
        if isHuffman {
            if let decoded = HPACKHuffman.decode(strData) {
                str = String(bytes: decoded, encoding: .utf8)
            } else {
                str = nil
            }
        } else {
            str = String(data: strData, encoding: .utf8)
        }
        guard let str else { return nil }
        return (str, lenBytes + Int(length))
    }

    private static func decodeStringAfterPrefix(from data: Data, offset: Int, prefixBits: Int) -> (String, Int)? {
        guard let (nameLen, nLenBytes) = decodeVarIntPrefix(from: data, offset: offset, prefixBits: prefixBits) else {
            return nil
        }
        let strStart = offset + nLenBytes
        guard strStart + Int(nameLen) <= data.count else { return nil }
        let strData = Data(data[strStart..<(strStart + Int(nameLen))])
        guard let str = String(data: strData, encoding: .utf8) else { return nil }
        return (str, nLenBytes + Int(nameLen))
    }

    // MARK: - Static Table

    private static func staticTableEntry(_ index: Int) -> (name: String, value: String)? {
        switch index {
        case 0: return (":authority", "")
        case 1: return (":path", "/")
        case 15: return (":method", "CONNECT")
        case 16: return (":method", "DELETE")
        case 17: return (":method", "GET")
        case 18: return (":method", "HEAD")
        case 19: return (":method", "OPTIONS")
        case 20: return (":method", "POST")
        case 21: return (":method", "PUT")
        case 22: return (":scheme", "http")
        case 23: return (":scheme", "https")
        case 24: return (":status", "103")
        case 25: return (":status", "200")
        case 26: return (":status", "204")
        case 27: return (":status", "206")
        case 28: return (":status", "304")
        case 29: return (":status", "400")
        case 30: return (":status", "403")
        case 31: return (":status", "404")
        case 32: return (":status", "421")
        case 33: return (":status", "425")
        case 34: return (":status", "500")
        default: return nil
        }
    }

    private static func staticTableName(_ index: Int) -> String? {
        switch index {
        case 0: return ":authority"
        case 1: return ":path"
        case 2: return "age"
        case 3: return "content-disposition"
        case 4: return "content-length"
        case 5: return "cookie"
        case 6: return "date"
        case 7: return "etag"
        case 8: return "if-modified-since"
        case 9: return "if-none-match"
        case 10: return "last-modified"
        case 11: return "link"
        case 12: return "location"
        case 13: return "referer"
        case 14: return "set-cookie"
        case 15: return ":method"
        case 16: return ":method"
        case 17: return ":method"
        case 18: return ":method"
        case 19: return ":method"
        case 20: return ":method"
        case 21: return ":method"
        case 22: return ":scheme"
        case 23: return ":scheme"
        case 24: return ":status"
        case 25: return ":status"
        default: return nil
        }
    }
}
