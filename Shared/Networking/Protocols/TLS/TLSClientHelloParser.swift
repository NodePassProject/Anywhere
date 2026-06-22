//
//  TLSClientHelloParser.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

struct TLSClientHelloParsed {
    let serverName: String?
    let cipherSuites: [UInt16]
    let supportedVersions: [UInt16]
    let supportedGroups: [UInt16]
    let signatureAlgorithms: [UInt16]
    let alpnProtocols: [String]
    let keyShares: [UInt16: Data]
    let legacyVersion: UInt16
    let random: Data
    let legacySessionID: Data
    let compressionMethods: [UInt8]
    let extendedMasterSecret: Bool
    let secureRenegotiation: Bool
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

    /// Parses a single ClientHello record (including the 5-byte record header); trailing records are not tolerated.
    static func parse(_ record: Data) throws -> TLSClientHelloParsed {
        guard record.count >= 5 else { throw TLSClientHelloParserError.truncated }
        guard record[record.startIndex] == TLSContentType.handshake else { throw TLSClientHelloParserError.notHandshake }

        let recordLen = (Int(record[record.startIndex + 3]) << 8) | Int(record[record.startIndex + 4])
        guard record.count >= 5 + recordLen else { throw TLSClientHelloParserError.lengthMismatch }
        let body = record.subdata(in: (record.startIndex + 5)..<(record.startIndex + 5 + recordLen))

        return try parseHandshakeBody(body)
    }

    /// Parses a handshake fragment without the outer 5-byte record header.
    static func parseHandshakeBody(_ body: Data) throws -> TLSClientHelloParsed {
        var current = Cursor(body)
        guard let msgType = current.readU8() else { throw TLSClientHelloParserError.truncated }
        guard msgType == TLSHandshakeType.clientHello else { throw TLSClientHelloParserError.notClientHello }
        guard let bodyLen = current.readU24(), let chBody = current.readBytes(bodyLen) else {
            throw TLSClientHelloParserError.truncated
        }

        let handshakeMessage = body.subdata(in: body.startIndex..<(body.startIndex + 4 + bodyLen))

        return try parseClientHello(chBody, handshakeMessage: handshakeMessage)
    }

    // MARK: - Internals

    private static func parseClientHello(_ body: Data, handshakeMessage: Data) throws -> TLSClientHelloParsed {
        var current = Cursor(body)
        guard let legacyVersion = current.readU16() else { throw TLSClientHelloParserError.truncated }
        guard let random = current.readBytes(32) else { throw TLSClientHelloParserError.truncated }
        guard let sessionIDLength = current.readU8(), sessionIDLength <= 32, let sessionID = current.readBytes(Int(sessionIDLength)) else {
            throw TLSClientHelloParserError.truncated
        }
        guard let cipherSuitesLength = current.readU16(), let cipherSuitesData = current.readBytes(cipherSuitesLength) else {
            throw TLSClientHelloParserError.truncated
        }
        var cipherSuites: [UInt16] = []
        cipherSuites.reserveCapacity(cipherSuitesLength / 2)
        var cipherSuiteCursor = Cursor(cipherSuitesData)
        while let cipherSuite = cipherSuiteCursor.readU16() { cipherSuites.append(UInt16(cipherSuite)) }

        guard let compressionMethodsLength = current.readU8(), let compressionMethodsData = current.readBytes(Int(compressionMethodsLength)) else {
            throw TLSClientHelloParserError.truncated
        }
        var compressionMethods: [UInt8] = []
        compressionMethods.reserveCapacity(Int(compressionMethodsLength))
        var compressionMethodCursor = Cursor(compressionMethodsData)
        while let m = compressionMethodCursor.readU8() { compressionMethods.append(m) }

        guard let extLen = current.readU16(), let extensions = current.readBytes(extLen) else {
            throw TLSClientHelloParserError.truncated
        }

        let parsedExtensions = try parseExtensions(extensions)

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
        var observedExtensionTypes = Set<UInt16>()
        var current = Cursor(buf)
        while !current.isAtEnd {
            guard let extType = current.readU16(),
                  let extLen = current.readU16(),
                  let extData = current.readBytes(extLen) else {
                throw TLSClientHelloParserError.truncated
            }
            let (inserted, _) = observedExtensionTypes.insert(UInt16(extType))
            if !inserted {
                throw TLSClientHelloParserError.malformed("duplicate extension \(extType)")
            }
            switch UInt16(extType) {
            case TLSExtensionType.serverName:
                result.serverName = parseServerName(extData)
            case TLSExtensionType.extendedMasterSecret:
                result.extendedMasterSecret = true
            case TLSExtensionType.supportedVersions:
                result.supportedVersions = parseSupportedVersionsClient(extData)
            case TLSExtensionType.supportedGroups:
                result.supportedGroups = parseUInt16List(extData)
            case TLSExtensionType.signatureAlgorithms:
                result.signatureAlgorithms = parseUInt16List(extData)
            case TLSExtensionType.applicationLayerProtocolNegotiation:
                result.alpnProtocols = parseALPN(extData)
            case TLSExtensionType.keyShare:
                result.keyShares = parseKeyShares(extData)
            case TLSExtensionType.renegotiationInfo:
                result.renegotiationInfo = true
            default:
                continue
            }
        }
        return result
    }

    private static func parseServerName(_ buf: Data) -> String? {
        var current = Cursor(buf)
        guard let listLen = current.readU16(), let list = current.readBytes(listLen) else { return nil }
        var listCursor = Cursor(list)
        while !listCursor.isAtEnd {
            guard let nameType = listCursor.readU8(),
                  let nameLen = listCursor.readU16(),
                  let nameData = listCursor.readBytes(nameLen) else { return nil }
            if nameType == 0x00, let host = String(data: nameData, encoding: .utf8), !host.isEmpty {
                return host.lowercased()
            }
        }
        return nil
    }

    private static func parseSupportedVersionsClient(_ buf: Data) -> [UInt16] {
        var current = Cursor(buf)
        guard let listLen = current.readU8() else { return [] }
        guard let list = current.readBytes(Int(listLen)) else { return [] }
        var versions: [UInt16] = []
        var listCursor = Cursor(list)
        while let v = listCursor.readU16() { versions.append(UInt16(v)) }
        return versions
    }

    private static func parseUInt16List(_ buf: Data) -> [UInt16] {
        var current = Cursor(buf)
        guard let listLen = current.readU16(), let list = current.readBytes(listLen) else { return [] }
        var values: [UInt16] = []
        var listCursor = Cursor(list)
        while let v = listCursor.readU16() { values.append(UInt16(v)) }
        return values
    }

    private static func parseALPN(_ buf: Data) -> [String] {
        var current = Cursor(buf)
        guard let listLen = current.readU16(), let list = current.readBytes(listLen) else { return [] }
        var protocols: [String] = []
        var listCursor = Cursor(list)
        while !listCursor.isAtEnd {
            guard let protocolLength = listCursor.readU8(), let protocolData = listCursor.readBytes(Int(protocolLength)) else { return protocols }
            if let s = String(data: protocolData, encoding: .utf8) { protocols.append(s) }
        }
        return protocols
    }

    private static func parseKeyShares(_ buf: Data) -> [UInt16: Data] {
        var result: [UInt16: Data] = [:]
        var current = Cursor(buf)
        guard let listLen = current.readU16(), let list = current.readBytes(listLen) else { return [:] }
        var listCursor = Cursor(list)
        while !listCursor.isAtEnd {
            guard let group = listCursor.readU16(),
                  let keyLen = listCursor.readU16(),
                  let keyData = listCursor.readBytes(keyLen) else { return result }
            result[UInt16(group)] = keyData
        }
        return result
    }

    // MARK: - Cursor

    private struct Cursor {
        let data: Data
        var position: Int

        init(_ data: Data) {
            self.data = data
            self.position = data.startIndex
        }

        var isAtEnd: Bool { position >= data.endIndex }

        mutating func readU8() -> UInt8? {
            guard position < data.endIndex else { return nil }
            let v = data[position]
            position += 1
            return v
        }

        mutating func readU16() -> Int? {
            guard position &+ 2 <= data.endIndex else { return nil }
            let v = (Int(data[position]) << 8) | Int(data[position &+ 1])
            position += 2
            return v
        }

        mutating func readU24() -> Int? {
            guard position &+ 3 <= data.endIndex else { return nil }
            let v = (Int(data[position]) << 16) | (Int(data[position &+ 1]) << 8) | Int(data[position &+ 2])
            position += 3
            return v
        }

        mutating func readBytes(_ n: Int) -> Data? {
            guard n >= 0, position &+ n <= data.endIndex else { return nil }
            let slice = data[position..<(position &+ n)]
            position += n
            return slice
        }
    }
}
