//
//  TLSClientHelloParser.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

/// Parsed view of an inbound ClientHello.
struct TLSClientHelloParsed {
    let serverName: String?
    let cipherSuites: [UInt16]
    let supportedVersions: [UInt16]
    let supportedGroups: [UInt16]
    let signatureAlgorithms: [UInt16]
    let alpnProtocols: [String]
    /// Map from named-group code to client-provided key_share blob (raw,
    /// without group-id / length prefix). Limited to the groups we care
    /// about — currently just X25519 (0x001D).
    let keyShares: [UInt16: Data]
    /// TLS legacy_version field from the ClientHello.
    let legacyVersion: UInt16
    let random: Data
    let legacySessionID: Data
    let compressionMethods: [UInt8]
    /// Whether the client offered the extended_master_secret extension (RFC 7627).
    /// Only meaningful for TLS 1.2 negotiations.
    let extendedMasterSecret: Bool
    /// Whether the client signaled support for secure renegotiation (RFC 5746),
    /// either by including the `renegotiation_info` extension or by listing
    /// the TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) signalling cipher
    /// suite. The server MUST NOT emit `renegotiation_info` in its
    /// ServerHello unless one of these was present.
    let secureRenegotiation: Bool
    /// Raw ClientHello (4-byte handshake header + body) — used for the TLS 1.3
    /// transcript hash.
    let handshakeMessage: Data
}

enum TLSClientHelloParserError: Error {
    case truncated
    case malformed(String)
    case notHandshake
    case notClientHello
    case lengthMismatch
}

enum TLSClientHelloParser {

    /// Parses a single ClientHello record. The input must contain exactly
    /// one TLS record carrying the ClientHello — additional records that
    /// might trail (early data, etc.) are not tolerated for v1.
    ///
    /// - Parameter record: Raw bytes including the 5-byte record header.
    static func parse(_ record: Data) throws -> TLSClientHelloParsed {
        // Record header: type(1) version(2) length(2)
        guard record.count >= 5 else { throw TLSClientHelloParserError.truncated }
        guard record[record.startIndex] == 0x16 else { throw TLSClientHelloParserError.notHandshake }

        let recordLen = (Int(record[record.startIndex + 3]) << 8) | Int(record[record.startIndex + 4])
        guard record.count >= 5 + recordLen else { throw TLSClientHelloParserError.lengthMismatch }
        let body = record.subdata(in: (record.startIndex + 5)..<(record.startIndex + 5 + recordLen))

        return try parseHandshakeBody(body)
    }

    /// Parses the handshake fragment without the outer 5-byte record
    /// header. Useful when the ClientHello has been pre-stripped (e.g.
    /// from buffered transcript bytes).
    static func parseHandshakeBody(_ body: Data) throws -> TLSClientHelloParsed {
        var cur = Cursor(body)
        guard let msgType = cur.readU8() else { throw TLSClientHelloParserError.truncated }
        guard msgType == 0x01 else { throw TLSClientHelloParserError.notClientHello }
        guard let bodyLen = cur.readU24(), let chBody = cur.readBytes(bodyLen) else {
            throw TLSClientHelloParserError.truncated
        }

        let handshakeMessage = body.subdata(in: body.startIndex..<(body.startIndex + 4 + bodyLen))

        return try parseClientHello(chBody, handshakeMessage: handshakeMessage)
    }

    // MARK: - Internals

    private static func parseClientHello(_ body: Data, handshakeMessage: Data) throws -> TLSClientHelloParsed {
        var cur = Cursor(body)
        guard let legacyVersion = cur.readU16() else { throw TLSClientHelloParserError.truncated }
        guard let random = cur.readBytes(32) else { throw TLSClientHelloParserError.truncated }
        guard let sidLen = cur.readU8(), let sessionID = cur.readBytes(Int(sidLen)) else {
            throw TLSClientHelloParserError.truncated
        }
        guard let csLen = cur.readU16(), let csData = cur.readBytes(csLen) else {
            throw TLSClientHelloParserError.truncated
        }
        var cipherSuites: [UInt16] = []
        cipherSuites.reserveCapacity(csLen / 2)
        var csCur = Cursor(csData)
        while let cs = csCur.readU16() { cipherSuites.append(UInt16(cs)) }

        guard let cmLen = cur.readU8(), let cmData = cur.readBytes(Int(cmLen)) else {
            throw TLSClientHelloParserError.truncated
        }
        var compressionMethods: [UInt8] = []
        compressionMethods.reserveCapacity(Int(cmLen))
        var cmCur = Cursor(cmData)
        while let m = cmCur.readU8() { compressionMethods.append(m) }

        guard let extLen = cur.readU16(), let extensions = cur.readBytes(extLen) else {
            throw TLSClientHelloParserError.truncated
        }

        let parsedExtensions = try parseExtensions(extensions)

        // RFC 5746 §3.6: a ClientHello signals secure renegotiation either
        // by carrying the `renegotiation_info` extension or by listing the
        // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00FF) cipher suite. The
        // ServerHello MUST NOT emit the extension otherwise.
        let secureRenegotiation = parsedExtensions.renegotiationInfo
            || cipherSuites.contains(0x00FF)

        return TLSClientHelloParsed(
            serverName: parsedExtensions.serverName,
            cipherSuites: cipherSuites,
            supportedVersions: parsedExtensions.supportedVersions,
            supportedGroups: parsedExtensions.supportedGroups,
            signatureAlgorithms: parsedExtensions.signatureAlgorithms,
            alpnProtocols: parsedExtensions.alpnProtocols,
            keyShares: parsedExtensions.keyShares,
            legacyVersion: UInt16(legacyVersion),
            random: random,
            legacySessionID: sessionID,
            compressionMethods: compressionMethods,
            extendedMasterSecret: parsedExtensions.extendedMasterSecret,
            secureRenegotiation: secureRenegotiation,
            handshakeMessage: handshakeMessage
        )
    }

    private struct ParsedExtensions {
        var serverName: String? = nil
        var supportedVersions: [UInt16] = []
        var supportedGroups: [UInt16] = []
        var signatureAlgorithms: [UInt16] = []
        var alpnProtocols: [String] = []
        var keyShares: [UInt16: Data] = [:]
        var extendedMasterSecret: Bool = false
        var renegotiationInfo: Bool = false
    }

    private static func parseExtensions(_ buf: Data) throws -> ParsedExtensions {
        var result = ParsedExtensions()
        var cur = Cursor(buf)
        while !cur.isAtEnd {
            guard let extType = cur.readU16(),
                  let extLen = cur.readU16(),
                  let extData = cur.readBytes(extLen) else {
                throw TLSClientHelloParserError.truncated
            }
            switch UInt16(extType) {
            case 0x0000: // server_name
                result.serverName = parseServerName(extData)
            case 0x0017: // extended_master_secret (RFC 7627) — empty data
                result.extendedMasterSecret = true
            case 0x002B: // supported_versions (ClientHello: list)
                result.supportedVersions = parseSupportedVersionsClient(extData)
            case 0x000A: // supported_groups
                result.supportedGroups = parseUInt16List(extData)
            case 0x000D: // signature_algorithms
                result.signatureAlgorithms = parseUInt16List(extData)
            case 0x0010: // ALPN
                result.alpnProtocols = parseALPN(extData)
            case 0x0033: // key_share (ClientHello: list of (group, exchange))
                result.keyShares = parseKeyShares(extData)
            case 0xFF01: // renegotiation_info (RFC 5746)
                result.renegotiationInfo = true
            default:
                continue
            }
        }
        return result
    }

    private static func parseServerName(_ buf: Data) -> String? {
        var cur = Cursor(buf)
        guard let listLen = cur.readU16(), let list = cur.readBytes(listLen) else { return nil }
        var lc = Cursor(list)
        while !lc.isAtEnd {
            guard let nameType = lc.readU8(),
                  let nameLen = lc.readU16(),
                  let nameData = lc.readBytes(nameLen) else { return nil }
            if nameType == 0x00, let host = String(data: nameData, encoding: .utf8), !host.isEmpty {
                return host.lowercased()
            }
        }
        return nil
    }

    private static func parseSupportedVersionsClient(_ buf: Data) -> [UInt16] {
        var cur = Cursor(buf)
        guard let listLen = cur.readU8() else { return [] }
        guard let list = cur.readBytes(Int(listLen)) else { return [] }
        var versions: [UInt16] = []
        var lc = Cursor(list)
        while let v = lc.readU16() { versions.append(UInt16(v)) }
        return versions
    }

    private static func parseUInt16List(_ buf: Data) -> [UInt16] {
        var cur = Cursor(buf)
        guard let listLen = cur.readU16(), let list = cur.readBytes(listLen) else { return [] }
        var values: [UInt16] = []
        var lc = Cursor(list)
        while let v = lc.readU16() { values.append(UInt16(v)) }
        return values
    }

    private static func parseALPN(_ buf: Data) -> [String] {
        var cur = Cursor(buf)
        guard let listLen = cur.readU16(), let list = cur.readBytes(listLen) else { return [] }
        var protocols: [String] = []
        var lc = Cursor(list)
        while !lc.isAtEnd {
            guard let pLen = lc.readU8(), let pData = lc.readBytes(Int(pLen)) else { return protocols }
            if let s = String(data: pData, encoding: .utf8) { protocols.append(s) }
        }
        return protocols
    }

    private static func parseKeyShares(_ buf: Data) -> [UInt16: Data] {
        var result: [UInt16: Data] = [:]
        var cur = Cursor(buf)
        guard let listLen = cur.readU16(), let list = cur.readBytes(listLen) else { return [:] }
        var lc = Cursor(list)
        while !lc.isAtEnd {
            guard let group = lc.readU16(),
                  let keyLen = lc.readU16(),
                  let keyData = lc.readBytes(keyLen) else { return result }
            result[UInt16(group)] = keyData
        }
        return result
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
