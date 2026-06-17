//
//  TLSClientHelloSniffer.swift
//  Anywhere
//
//  Incremental, bounds-checked parser that extracts the SNI hostname from an
//  inbound TLS ClientHello, enabling domain-based routing for traffic that
//  reaches the tunnel by real IP. Strictly passive; buffers at most
//  tlsSnifferBufferLimit bytes.
//

import Foundation

struct TLSClientHelloSniffer {

    enum State: Equatable {
        /// Need more bytes to decide.
        case needMore
        /// First bytes do not start with a TLS Handshake record (0x16).
        case notTLS
        /// SNI extracted from a well-formed ClientHello (lowercased).
        case found(serverName: String)
        /// TLS-shaped but SNI unavailable (malformed, absent, or cap reached);
        /// caller should fall back to IP-based routing.
        case unavailable
    }

    private let bufferLimit: Int
    private var buffer = Data()
    private(set) var state: State = .needMore

    init(bufferLimit: Int = TunnelConstants.tlsSnifferBufferLimit) {
        self.bufferLimit = bufferLimit
    }

    /// Appends `data` and returns the new state; no-ops after a terminal state.
    mutating func feed(_ data: Data) -> State {
        guard state == .needMore, !data.isEmpty else { return state }

        // Fast reject before copying: a TLS record starts with 0x16, so the
        // buffer stays empty for non-TLS protocols.
        if buffer.isEmpty, data[data.startIndex] != 0x16 {
            state = .notTLS
            return state
        }

        buffer.append(data)
        if buffer.count > bufferLimit {
            state = .unavailable
            return state
        }

        state = parse(buffer)
        return state
    }

    // MARK: - Parsing

    /// TLS record layer: [content_type:1][legacy_version:2][length:2][fragment]
    ///
    /// A client may split the ClientHello across several TLS records (RFC 8446 §5.1) — common with
    /// TLS-fragmenting / anti-censorship clients. Reassemble the handshake message across consecutive
    /// handshake records before parsing, rather than giving up after the first record (which would
    /// drop SNI-based routing for those clients). The total is bounded by `bufferLimit`.
    private func parse(_ buf: Data) -> State {
        guard buf.count >= 5 else { return .needMore }
        let base = buf.startIndex
        guard buf[base] == 0x16 else { return .unavailable }

        var fragment = Data()
        var offset = 0                  // bytes scanned from base
        var messageLength: Int?         // 4 + bodyLen, once the handshake header is in hand
        let total = buf.count
        while true {
            guard total - offset >= 5 else { return .needMore }
            let h = buf.index(base, offsetBy: offset)
            guard buf[h] == 0x16 else { return .unavailable } // non-handshake record mid-message
            // RFC 8446 §5.1: record fragment length ≤ 2^14.
            let fragLen = (Int(buf[buf.index(h, offsetBy: 3)]) << 8) | Int(buf[buf.index(h, offsetBy: 4)])
            guard fragLen > 0, fragLen <= 16_384 else { return .unavailable }
            let recordTotal = 5 + fragLen
            guard total - offset >= recordTotal else { return .needMore }
            let fStart = buf.index(h, offsetBy: 5)
            let fEnd = buf.index(fStart, offsetBy: fragLen)
            fragment.append(buf[fStart..<fEnd])
            offset += recordTotal
            if messageLength == nil, fragment.count >= 4 {
                let b = fragment.startIndex
                guard fragment[b] == 0x01 else { return .unavailable } // ClientHello
                let bodyLen = (Int(fragment[fragment.index(b, offsetBy: 1)]) << 16)
                            | (Int(fragment[fragment.index(b, offsetBy: 2)]) << 8)
                            | Int(fragment[fragment.index(b, offsetBy: 3)])
                messageLength = 4 + bodyLen
            }
            if let ml = messageLength, fragment.count >= ml {
                return parseHandshake(fragment.prefix(ml))
            }
        }
    }

    /// Handshake layer: [msg_type:1][length:3][body]
    private func parseHandshake(_ frag: Data) -> State {
        var cur = Cursor(frag)
        guard let msgType = cur.readU8(), msgType == 0x01 else { return .unavailable } // ClientHello
        guard let bodyLen = cur.readU24(), let body = cur.readBytes(bodyLen) else { return .unavailable }
        return parseClientHello(body)
    }

    /// ClientHello body (after the 4-byte handshake header):
    ///   legacy_version (uint16)
    ///   random [32]
    ///   session_id             opaque<0..32>      (uint8  len + bytes)
    ///   cipher_suites          CipherSuite<2..2^16-2> (uint16 len + bytes)
    ///   compression_methods    opaque<1..2^8-1>   (uint8  len + bytes)
    ///   extensions             Extension<8..2^16-1> (uint16 len + bytes)
    private func parseClientHello(_ body: Data) -> State {
        var cur = Cursor(body)

        guard cur.skip(2 + 32) else { return .unavailable }
        guard let sidLen = cur.readU8(), cur.skip(Int(sidLen)) else { return .unavailable }
        guard let csLen = cur.readU16(), cur.skip(csLen) else { return .unavailable }
        guard let cmLen = cur.readU8(), cur.skip(Int(cmLen)) else { return .unavailable }
        guard let extLen = cur.readU16(), let extensions = cur.readBytes(extLen) else {
            return .unavailable
        }
        return parseExtensions(extensions)
    }

    /// Walks the extension list looking for server_name (type 0x0000).
    private func parseExtensions(_ buf: Data) -> State {
        var cur = Cursor(buf)
        while !cur.isAtEnd {
            guard let extType = cur.readU16(),
                  let extLen = cur.readU16(),
                  let extData = cur.readBytes(extLen) else {
                return .unavailable
            }
            if extType == 0x0000 {
                if let name = parseServerNameList(extData) {
                    return .found(serverName: name)
                }
                return .unavailable
            }
        }
        return .unavailable
    }

    /// server_name extension:
    ///   ServerNameList: uint16 length + list of ServerName
    ///   ServerName:     uint8 name_type + opaque<0..2^16-1>
    ///   name_type 0x00 = HostName (ASCII per RFC 6066)
    private func parseServerNameList(_ buf: Data) -> String? {
        var cur = Cursor(buf)
        guard let listLen = cur.readU16(), let list = cur.readBytes(listLen) else { return nil }
        var lc = Cursor(list)
        while !lc.isAtEnd {
            guard let nameType = lc.readU8(),
                  let nameLen = lc.readU16(),
                  let nameData = lc.readBytes(nameLen) else { return nil }
            if nameType == 0x00,
               !nameData.isEmpty,
               let host = String(data: nameData, encoding: .utf8) {
                return host.lowercased()
            }
        }
        return nil
    }

    // MARK: - Cursor

    private struct Cursor {
        let data: Data
        var pos: Int

        init(_ data: Data) {
            self.data = data
            self.pos = data.startIndex
        }

        var isAtEnd: Bool { pos >= data.endIndex }

        mutating func skip(_ n: Int) -> Bool {
            guard n >= 0, pos &+ n <= data.endIndex else { return false }
            pos += n
            return true
        }

        mutating func readU8() -> UInt8? {
            guard pos < data.endIndex else { return nil }
            let v = data[pos]
            pos += 1
            return v
        }

        mutating func readU16() -> Int? {
            guard pos &+ 2 <= data.endIndex else { return nil }
            let v = (Int(data[pos]) << 8) | Int(data[pos &+ 1])
            pos += 2
            return v
        }

        mutating func readU24() -> Int? {
            guard pos &+ 3 <= data.endIndex else { return nil }
            let v = (Int(data[pos]) << 16) | (Int(data[pos &+ 1]) << 8) | Int(data[pos &+ 2])
            pos += 3
            return v
        }

        mutating func readBytes(_ n: Int) -> Data? {
            guard n >= 0, pos &+ n <= data.endIndex else { return nil }
            let slice = data[pos..<(pos &+ n)]
            pos += n
            return slice
        }
    }
}
