//
//  VMessProtocol.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/6/26.
//

import Foundation

struct VMessSession {
    let requestBodyKey: Data
    let requestBodyIV: Data
    let responseBodyKey: Data
    let responseBodyIV: Data
    let responseHeaderLengthKey: Data
    let responseHeaderLengthIV: Data
    let responseHeaderPayloadKey: Data
    let responseHeaderPayloadIV: Data
    let requestChaCha20Poly1305Key: Data?
    let responseChaCha20Poly1305Key: Data?
    let responseHeader: UInt8
    let security: VMessSecurity
    let command: ProxyCommand
    let options: UInt8

    var usesChunkStream: Bool {
        options & VMessProtocol.requestOptionChunkStream != 0
    }

    var usesChunkMasking: Bool {
        options & VMessProtocol.requestOptionChunkMasking != 0
    }

    var usesGlobalPadding: Bool {
        options & VMessProtocol.requestOptionGlobalPadding != 0
    }
}

enum VMessProtocol {
    static let version: UInt8 = 1

    static let requestOptionChunkStream: UInt8 = 0x01
    static let requestOptionChunkMasking: UInt8 = 0x04
    static let requestOptionGlobalPadding: UInt8 = 0x08
    static let requestOptionAuthenticatedLength: UInt8 = 0x10

    private static let authIDEncryptionKeySalt = Data("AES Auth ID Encryption".utf8)
    private static let headerPayloadAEADKeySalt = Data("VMess Header AEAD Key".utf8)
    private static let headerPayloadAEADIVSalt = Data("VMess Header AEAD Nonce".utf8)
    private static let headerPayloadLengthAEADKeySalt = Data("VMess Header AEAD Key_Length".utf8)
    private static let headerPayloadLengthAEADIVSalt = Data("VMess Header AEAD Nonce_Length".utf8)

    static let responseHeaderLengthKeySalt = Data("AEAD Resp Header Len Key".utf8)
    static let responseHeaderLengthIVSalt = Data("AEAD Resp Header Len IV".utf8)
    static let responseHeaderPayloadKeySalt = Data("AEAD Resp Header Key".utf8)
    static let responseHeaderPayloadIVSalt = Data("AEAD Resp Header IV".utf8)

    static func makeSession(security: VMessSecurity, command: ProxyCommand) -> VMessSession {
        let random = VMessCrypto.randomData(count: 33)
        let requestKey = Data(random.prefix(16))
        let requestIV = Data(random.dropFirst(16).prefix(16))
        let responseHeader = random[random.startIndex + 32]
        let responseKey = Data(VMessCrypto.sha256(requestKey).prefix(16))
        let responseIV = Data(VMessCrypto.sha256(requestIV).prefix(16))
        let normalizedSecurity = security.requestSecurity
        let requestChaCha20Poly1305Key: Data?
        let responseChaCha20Poly1305Key: Data?
        if normalizedSecurity == .chacha20Poly1305 {
            requestChaCha20Poly1305Key = VMessCrypto.generateChaCha20Poly1305Key(from: requestKey)
            responseChaCha20Poly1305Key = VMessCrypto.generateChaCha20Poly1305Key(from: responseKey)
        } else {
            requestChaCha20Poly1305Key = nil
            responseChaCha20Poly1305Key = nil
        }
        var options: UInt8 = 0
        if normalizedSecurity.usesChunkStream {
            options |= requestOptionChunkStream
            options |= requestOptionChunkMasking
        }
        if normalizedSecurity.usesGlobalPadding {
            options |= requestOptionGlobalPadding
        }

        return VMessSession(
            requestBodyKey: requestKey,
            requestBodyIV: requestIV,
            responseBodyKey: responseKey,
            responseBodyIV: responseIV,
            responseHeaderLengthKey: encodeResponseHeaderLengthKey(responseBodyKey: responseKey),
            responseHeaderLengthIV: encodeResponseHeaderLengthIV(responseBodyIV: responseIV),
            responseHeaderPayloadKey: encodeResponseHeaderPayloadKey(responseBodyKey: responseKey),
            responseHeaderPayloadIV: encodeResponseHeaderPayloadIV(responseBodyIV: responseIV),
            requestChaCha20Poly1305Key: requestChaCha20Poly1305Key,
            responseChaCha20Poly1305Key: responseChaCha20Poly1305Key,
            responseHeader: responseHeader,
            security: normalizedSecurity,
            command: command,
            options: options
        )
    }

    static func encodeRequestHeader(
        uuid: UUID,
        session: VMessSession,
        destinationAddress: String,
        destinationPort: UInt16
    ) throws -> Data {
        var header = Data(capacity: 64 + destinationAddress.utf8.count)
        header.append(version)
        header.append(session.requestBodyIV)
        header.append(session.requestBodyKey)
        header.append(session.responseHeader)
        header.append(session.options)

        let paddingLength = UInt8.random(in: 0..<16)
        header.append((paddingLength << 4) | (session.security.wireValue & 0x0f))
        header.append(0x00)
        header.append(session.command.rawValue)

        if session.command != .mux {
            VMessCrypto.appendUInt16BE(destinationPort, to: &header)
            appendAddress(destinationAddress, to: &header)
        }

        if paddingLength > 0 {
            header.append(VMessCrypto.randomData(count: Int(paddingLength)))
        }

        let checksum = VMessCrypto.fnv1a32(header)
        VMessCrypto.appendUInt32BE(checksum, to: &header)

        let commandKey = VMessCrypto.commandKey(for: uuid)
        return try sealAEADHeader(commandKey: commandKey, payload: header)
    }

    static func encodeResponseHeaderLengthKey(responseBodyKey: Data) -> Data {
        VMessCrypto.kdf16(responseBodyKey, path: [responseHeaderLengthKeySalt])
    }

    static func encodeResponseHeaderLengthIV(responseBodyIV: Data) -> Data {
        Data(VMessCrypto.kdf(responseBodyIV, path: [responseHeaderLengthIVSalt]).prefix(12))
    }

    static func encodeResponseHeaderPayloadKey(responseBodyKey: Data) -> Data {
        VMessCrypto.kdf16(responseBodyKey, path: [responseHeaderPayloadKeySalt])
    }

    static func encodeResponseHeaderPayloadIV(responseBodyIV: Data) -> Data {
        Data(VMessCrypto.kdf(responseBodyIV, path: [responseHeaderPayloadIVSalt]).prefix(12))
    }

    private static func createAuthID(commandKey: Data, timestamp: Int64) throws -> Data {
        var payload = Data(capacity: 16)
        VMessCrypto.appendInt64BE(timestamp, to: &payload)
        payload.append(VMessCrypto.randomData(count: 4))
        let checksum = VMessCrypto.crc32IEEE(payload)
        VMessCrypto.appendUInt32BE(checksum, to: &payload)

        let encryptionKey = VMessCrypto.kdf16(commandKey, path: [authIDEncryptionKeySalt])
        return try VMessCrypto.aesECBEncryptBlock(payload, key: encryptionKey)
    }

    private static func sealAEADHeader(commandKey: Data, payload: Data) throws -> Data {
        let authID = try createAuthID(commandKey: commandKey, timestamp: Int64(Date().timeIntervalSince1970))
        let connectionNonce = VMessCrypto.randomData(count: 8)

        var lengthPlaintext = Data(capacity: 2)
        VMessCrypto.appendUInt16BE(UInt16(payload.count), to: &lengthPlaintext)

        let lengthKey = VMessCrypto.kdf16(
            commandKey,
            path: [headerPayloadLengthAEADKeySalt, authID, connectionNonce]
        )
        let lengthNonce = Data(VMessCrypto.kdf(
            commandKey,
            path: [headerPayloadLengthAEADIVSalt, authID, connectionNonce]
        ).prefix(12))
        let encryptedLength = try VMessCrypto.sealAESGCM(
            key: lengthKey,
            nonce: lengthNonce,
            plaintext: lengthPlaintext,
            aad: authID
        )

        let payloadKey = VMessCrypto.kdf16(
            commandKey,
            path: [headerPayloadAEADKeySalt, authID, connectionNonce]
        )
        let payloadNonce = Data(VMessCrypto.kdf(
            commandKey,
            path: [headerPayloadAEADIVSalt, authID, connectionNonce]
        ).prefix(12))
        let encryptedPayload = try VMessCrypto.sealAESGCM(
            key: payloadKey,
            nonce: payloadNonce,
            plaintext: payload,
            aad: authID
        )

        var output = Data(capacity: 16 + encryptedLength.count + 8 + encryptedPayload.count)
        output.append(authID)
        output.append(encryptedLength)
        output.append(connectionNonce)
        output.append(encryptedPayload)
        return output
    }

    private static func appendAddress(_ address: String, to data: inout Data) {
        if let ipv4 = parseIPv4(address) {
            data.append(VLESSAddressType.ipv4.rawValue)
            data.append(ipv4)
            return
        }
        if let ipv6 = parseIPv6(address) {
            data.append(VLESSAddressType.ipv6.rawValue)
            data.append(ipv6)
            return
        }

        let domainData = Data(address.utf8)
        data.append(VLESSAddressType.domain.rawValue)
        data.append(UInt8(min(domainData.count, 255)))
        data.append(domainData.prefix(255))
    }

    private static func parseIPv4(_ address: String) -> Data? {
        var addr = in_addr()
        guard inet_pton(AF_INET, address, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Data($0) }
    }

    private static func parseIPv6(_ address: String) -> Data? {
        var clean = address
        if clean.hasPrefix("[") && clean.hasSuffix("]") {
            clean = String(clean.dropFirst().dropLast())
        }
        var addr = in6_addr()
        guard inet_pton(AF_INET6, clean, &addr) == 1 else { return nil }
        return withUnsafeBytes(of: &addr) { Data($0) }
    }
}
