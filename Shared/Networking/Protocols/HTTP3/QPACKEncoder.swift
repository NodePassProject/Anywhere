//
//  QPACKEncoder.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
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

    /// Encodes CONNECT headers: classic CONNECT (RFC 9114 §4.4) sends only `:method` and
    /// `:authority`; extended CONNECT (RFC 9220/9298) adds `:protocol`, `:scheme`, `:path`.
    static func encodeConnectHeaders(
        authority: String,
        protocolPseudo: String? = nil,
        path: String? = nil,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()

        // Header block prefix: Required Insert Count 0, Delta Base 0 (no dynamic table).
        block.append(0x00)
        block.append(0x00)

        block.append(contentsOf: encodeIndexedFieldLine(QPACKStaticIndex.methodConnect.rawValue))

        if let protocolPseudo {
            // Extended CONNECT (RFC 9220 §3 / RFC 9298 §3): :protocol, :scheme,
            // and :path are all mandatory alongside :method and :authority.
            block.append(contentsOf: encodeLiteralFieldLine(
                name: ":protocol", value: protocolPseudo
            ))
            block.append(contentsOf: encodeIndexedFieldLine(23))  // :scheme = https (index 23)
            block.append(contentsOf: encodeLiteralWithNameRef(
                staticIndex: 1, value: path ?? "/"
            ))
        }

        // :authority (literal with name ref, static index 0)
        block.append(contentsOf: encodeLiteralWithNameRef(
            staticIndex: 0, value: authority
        ))

        for header in extraHeaders {
            block.append(contentsOf: encodeLiteralFieldLine(
                name: header.name, value: header.value
            ))
        }

        return block
    }

    /// Decodes a QPACK header block; nil if malformed or it references the dynamic
    /// table — a protocol violation since we advertise `QPACK_MAX_TABLE_CAPACITY=0`.
    static func decodeHeaders(from data: Data) -> [(name: String, value: String)]? {
        var headers: [(name: String, value: String)] = []
        guard data.count >= 2 else { return nil }

        // All byte access via `base + offset` so zero-copy slices (non-zero startIndex) work.
        let base = data.startIndex
        var offset = 0

        // QPACK prefix: Required Insert Count MUST be 0 (dynamic table disabled).
        guard let (requiredInsertCount, ricLen) =
                decodeVarIntPrefix(from: data, offset: offset, prefixBits: 8) else { return nil }
        offset += ricLen
        guard requiredInsertCount == 0 else { return nil }

        guard offset < data.count else { return nil }
        // Delta Base: 7-bit prefix after the sign bit; value unused (no dynamic table).
        guard let (_, dbLen) = decodeVarIntPrefix(from: data, offset: offset, prefixBits: 7) else {
            return nil
        }
        offset += dbLen

        while offset < data.count {
            let byte = data[base + offset]

            if byte & 0x80 != 0 {
                // Indexed field line: 1 T index(6+). T=0 (dynamic) is not supported.
                let isStatic = (byte & 0x40) != 0
                guard isStatic else { return nil }
                guard let (index, len) =
                        decodeVarIntPrefix(from: data, offset: offset, prefixBits: 6) else { return nil }
                offset += len
                // Indices outside our RFC 9204 Appendix A subset are skipped, not
                // failed, so unknown headers don't break origin-server interop.
                if let entry = staticTableEntry(Int(index)) {
                    headers.append(entry)
                }
            } else if byte & 0x40 != 0 {
                // Literal with name ref: 01 N T name-index(4+) value. T=0 (dynamic) not supported.
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
                // Literal field line with literal name: 001 N H nameLen(3+) name value
                let nameHuffman = (byte & 0x08) != 0
                guard let (nameLen, nameLenBytes) =
                        decodeVarIntPrefix(from: data, offset: offset, prefixBits: 3) else { return nil }
                offset += nameLenBytes
                guard offset + Int(nameLen) <= data.count else { return nil }
                let nameStart = base + offset
                let nameEnd = nameStart + Int(nameLen)
                let nameData = Data(data[nameStart..<nameEnd])
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
                // Post-base forms (0001xxxx / 0000xxxx) require the dynamic table — not supported.
                return nil
            }
        }

        return headers
    }

    /// Encodes HTTP/3 POST request headers into a QPACK header block.
    static func encodePostHeaders(
        authority: String,
        path: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()
        block.append(0x00)
        block.append(0x00)

        block.append(contentsOf: encodeIndexedFieldLine(20))  // :method POST
        block.append(contentsOf: encodeIndexedFieldLine(23))  // :scheme https
        block.append(contentsOf: encodeLiteralWithNameRef(staticIndex: 0, value: authority))
        block.append(contentsOf: encodeLiteralWithNameRef(staticIndex: 1, value: path))

        for header in extraHeaders {
            block.append(contentsOf: encodeLiteralFieldLine(name: header.name, value: header.value))
        }
        return block
    }

    /// Encodes HTTP/3 request headers for an arbitrary method into a QPACK header block.
    static func encodeRequestHeaders(
        method: String,
        authority: String,
        path: String,
        extraHeaders: [(name: String, value: String)]
    ) -> Data {
        var block = Data()
        block.append(0x00)
        block.append(0x00)

        switch method.uppercased() {
        case "GET":
            block.append(contentsOf: encodeIndexedFieldLine(17))  // :method GET
        case "POST":
            block.append(contentsOf: encodeIndexedFieldLine(20))  // :method POST
        default:
            block.append(contentsOf: encodeLiteralFieldLine(name: ":method", value: method))
        }
        block.append(contentsOf: encodeIndexedFieldLine(23))  // :scheme https
        block.append(contentsOf: encodeLiteralWithNameRef(staticIndex: 0, value: authority))
        block.append(contentsOf: encodeLiteralWithNameRef(staticIndex: 1, value: path))

        for header in extraHeaders {
            block.append(contentsOf: encodeLiteralFieldLine(name: header.name, value: header.value))
        }
        return block
    }

    // MARK: - Encoding Helpers

    /// Indexed field line: 1 T(1) index(6+). T=1 → prefix byte 0xC0.
    private static func encodeIndexedFieldLine(_ index: Int) -> Data {
        return encodeVarIntWithPrefix(UInt64(index), prefixBits: 6, prefix: 0xC0)
    }

    /// Literal field line with name reference: 01 N T nameIndex(4+) value.
    /// N=0 T=1 (static) → prefix 0x50.
    private static func encodeLiteralWithNameRef(staticIndex: Int, value: String) -> Data {
        var data = Data()
        data.append(contentsOf: encodeVarIntWithPrefix(UInt64(staticIndex), prefixBits: 4, prefix: 0x50))
        data.append(contentsOf: encodeStringLiteral(value))
        return data
    }

    /// Literal field line with literal name: 001 N H nameLen(3+) name value.
    /// N=0 → prefix 0x20.
    private static func encodeLiteralFieldLine(name: String, value: String) -> Data {
        var data = Data()
        let nameBytes = Data(name.lowercased().utf8)
        data.append(contentsOf: encodeVarIntWithPrefix(UInt64(nameBytes.count), prefixBits: 3, prefix: 0x20))
        data.append(nameBytes)
        data.append(contentsOf: encodeStringLiteral(value))
        return data
    }

    /// String literal: H=0 (no Huffman), 7-bit length prefix.
    private static func encodeStringLiteral(_ string: String) -> Data {
        let bytes = Data(string.utf8)
        var data = Data()
        data.append(contentsOf: encodeVarIntWithPrefix(UInt64(bytes.count), prefixBits: 7, prefix: 0x00))
        data.append(bytes)
        return data
    }

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

    /// Decode offsets are relative to `data.startIndex` (slice-safe). QPACK integers
    /// cap at 2^62 − 1 (RFC 9204 §4.1.1); overflow is malformed input, not a trap.
    private static let qpackIntMax: UInt64 = (1 << 62) - 1

    private static func decodeVarIntPrefix(from data: Data, offset: Int, prefixBits: Int) -> (UInt64, Int)? {
        guard offset < data.count else { return nil }
        let base = data.startIndex
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
            let add = UInt64(byte & 0x7F)
            // Check before shifting — Swift traps on overflow.
            if shift > 62 || (qpackIntMax >> shift) < add { return nil }
            let shifted = add << shift
            if qpackIntMax - shifted < value { return nil }
            value += shifted
            pos += 1
            if byte & 0x80 == 0 {
                return (value, pos - offset)
            }
            shift += 7
        }
        return nil
    }

    /// `offset` is relative to `data.startIndex`; slice-safe.
    private static func decodeString(from data: Data, offset: Int) -> (String, Int)? {
        guard offset < data.count else { return nil }
        let base = data.startIndex
        let isHuffman = (data[base + offset] & 0x80) != 0
        guard let (length, lenBytes) = decodeVarIntPrefix(from: data, offset: offset, prefixBits: 7) else {
            return nil
        }
        let strStart = offset + lenBytes
        guard strStart + Int(length) <= data.count else { return nil }

        let absStart = base + strStart
        let absEnd = absStart + Int(length)
        let strData = Data(data[absStart..<absEnd])
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

    /// `offset` is relative to `data.startIndex`; slice-safe.
    private static func decodeStringAfterPrefix(from data: Data, offset: Int, prefixBits: Int) -> (String, Int)? {
        guard let (nameLen, nLenBytes) = decodeVarIntPrefix(from: data, offset: offset, prefixBits: prefixBits) else {
            return nil
        }
        let strStart = offset + nLenBytes
        guard strStart + Int(nameLen) <= data.count else { return nil }
        let base = data.startIndex
        let absStart = base + strStart
        let absEnd = absStart + Int(nameLen)
        let strData = Data(data[absStart..<absEnd])
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
        case 26: return (":status", "304")
        case 27: return (":status", "404")
        case 28: return (":status", "503")
        case 29: return ("accept", "*/*")
        case 30: return ("accept", "application/dns-message")
        case 31: return ("accept-encoding", "gzip, deflate, br")
        case 32: return ("accept-ranges", "bytes")
        case 33: return ("access-control-allow-headers", "cache-control")
        case 34: return ("access-control-allow-headers", "content-type")
        // Statuses 100–500 live non-contiguously at 63–71 in RFC 9204 Appendix A;
        // they must resolve here or an indexed `:status` would go missing.
        case 63: return (":status", "100")
        case 64: return (":status", "204")
        case 65: return (":status", "206")
        case 66: return (":status", "302")
        case 67: return (":status", "400")
        case 68: return (":status", "403")
        case 69: return (":status", "421")
        case 70: return (":status", "425")
        case 71: return (":status", "500")
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
