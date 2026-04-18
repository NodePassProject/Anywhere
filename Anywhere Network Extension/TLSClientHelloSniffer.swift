//
//  TLSClientHelloSniffer.swift
//  Anywhere
//
//  Incremental, bounds-checked parser that extracts the SNI hostname from an
//  inbound TLS ClientHello. Used by LWIPTCPConnection to enable domain-based
//  routing for traffic that reaches the tunnel by real IP (hardcoded IPs, DoH
//  clients, etc.) — cases where the fake-IP ↔ domain mapping is unavailable.
//
//  The parser is strictly passive: it buffers up to
//  ``TunnelConstants/tlsSnifferBufferLimit`` bytes, walks the record /
//  handshake / extensions structure with explicit bounds checks, and returns
//  a terminal state as soon as the first byte rules out TLS or the first
//  server_name extension is reached. No bytes beyond the ClientHello are
//  retained.
//

import Foundation

struct TLSClientHelloSniffer {

    enum State: Equatable {
        /// Need more bytes to decide. Keep calling ``feed(_:)``.
        case needMore
        /// First bytes do not start with a TLS Handshake record (0x16).
        case notTLS
        /// SNI extracted from a well-formed ClientHello (lowercased).
        case found(serverName: String)
        /// Input is TLS-shaped but SNI cannot be extracted — malformed record,
        /// no server_name extension, or buffer cap reached. Caller should
        /// fall back to the IP-based routing decision.
        case unavailable
    }

    private let bufferLimit: Int
    private var buffer = Data()
    private(set) var state: State = .needMore

    init(bufferLimit: Int = TunnelConstants.tlsSnifferBufferLimit) {
        self.bufferLimit = bufferLimit
    }

    /// Appends `data` and advances the parse state. Returns the new state.
    /// After a terminal state is reached, further calls are no-ops.
    mutating func feed(_ data: Data) -> State {
        guard state == .needMore, !data.isEmpty else { return state }

        // Fast reject before copying: a real TLS record starts with 0x16.
        // This keeps the buffer empty for non-TLS protocols.
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
    private func parse(_ buf: Data) -> State {
        guard buf.count >= 5 else { return .needMore }

        let base = buf.startIndex
        guard buf[base] == 0x16 else { return .unavailable }

        // RFC 8446 §5.1: record fragment length ≤ 2^14.
        let fragLen = (Int(buf[base + 3]) << 8) | Int(buf[base + 4])
        guard fragLen > 0, fragLen <= 16_384 else { return .unavailable }

        let recordEnd = base + 5 + fragLen
        guard buf.count >= recordEnd else { return .needMore }

        return parseHandshake(buf[(base + 5)..<recordEnd])
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
