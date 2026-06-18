//
//  NowhereProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import CryptoKit
import Security

enum NowhereProtocol {
    static let maxTargetLength = 512
    
    static let closeErrCodeOK: UInt64 = 0x100
    static let defaultSpec = "auto"

    private static let proxyFrameVersion: UInt8 = 1
    private static let defaultALPN = "now/1"
    private static let maxInputLength = 255
    private static let specIDLength = 8
    private static let authMagicLength = 8
    private static let authInfoLength = 32
    private static let authContextLength = 32
    private static let authTagLength = 32
    private static let authPaddingLengthSeedLength = 2
    private static let authPaddingMaxLength = 255
    private static let authPaddingKeyLength = 32
    private static let tcpPaddingLengthSeedLength = 1
    private static let tcpPaddingMaxLength = 64
    private static let tcpPaddingKeyLength = 32

    private static let specIDLabel = Data("spec id".utf8)
    private static let authMagicLabel = Data("auth magic".utf8)
    private static let authInfoLabel = Data("auth hmac info".utf8)
    private static let authContextLabel = Data("auth context".utf8)
    private static let authPaddingLengthLabel = Data("auth padding length".utf8)
    private static let authPaddingKeyLabel = Data("auth padding key".utf8)
    private static let authPaddingBytesLabel = Data("auth padding bytes".utf8)
    private static let tcpPaddingLengthLabel = Data("tcp request padding length".utf8)
    private static let tcpPaddingKeyLabel = Data("tcp request padding key".utf8)
    private static let tcpPaddingBytesLabel = Data("tcp request padding bytes".utf8)
    private static let frameLayoutLabel = Data("proxy frame layout".utf8)

    enum FrameElement: UInt8, Hashable {
        case version
        case type
        case flowID
        case target
        case padding
    }

    struct EffectiveSpec: Hashable {
        let effectiveALPN: String
        let defaultALPN: String
        let effectiveSpecID: String
        let authMagic: Data
        let authInfo: Data
        let authContext: Data
        let authPaddingLength: UInt8
        let authPaddingKey: Data
        let tcpPaddingLength: UInt8
        let tcpPaddingKey: Data
        let tcpFrameOrder: [FrameElement]
        let udpFrameOrder: [FrameElement]
    }

    enum UDPType: UInt8 {
        case request = 1
        case response = 2
        case close = 3
    }

    struct UDPMessage {
        let type: UInt8
        let flowID: UInt64
        let target: String
        let payload: Data
    }

    static func buildEffectiveSpec(key: String, spec: String?, alpn: String?) throws -> EffectiveSpec {
        let keyBytes = Data(key.utf8)
        try validateRequired(keyBytes, name: "shared key")

        let effectiveSpec = if let spec, !spec.isEmpty {
            try validateOptional(Data(spec.utf8), name: "spec")
        } else {
            Data(defaultSpec.utf8)
        }

        let specSalt = Data(SHA256.hash(data: effectiveSpec))
        let specPRK = hkdfExtract(salt: specSalt, input: effectiveSpec)
        let frameOrder = buildFrameOrder(seed: hkdfExpand(prk: specPRK, info: frameLayoutLabel, count: 8))
        let authPaddingLengthSeed = hkdfExpand(
            prk: specPRK,
            info: authPaddingLengthLabel,
            count: authPaddingLengthSeedLength
        )
        let authPaddingLengthValue = 1 + (readUInt16(authPaddingLengthSeed, at: 0) % authPaddingMaxLength)
        let tcpPaddingLengthSeed = hkdfExpand(
            prk: specPRK,
            info: tcpPaddingLengthLabel,
            count: tcpPaddingLengthSeedLength
        )
        let tcpPaddingLengthValue = Int(byte(tcpPaddingLengthSeed, at: 0)) % tcpPaddingMaxLength

        let effectiveALPN: String
        if let alpn, !alpn.isEmpty {
            try validateOptional(Data(alpn.utf8), name: "alpn")
            effectiveALPN = alpn
        } else {
            effectiveALPN = defaultALPN
        }

        return EffectiveSpec(
            effectiveALPN: effectiveALPN,
            defaultALPN: defaultALPN,
            effectiveSpecID: base64URLNoPadding(hkdfExpand(prk: specPRK, info: specIDLabel, count: specIDLength)),
            authMagic: hkdfExpand(prk: specPRK, info: authMagicLabel, count: authMagicLength),
            authInfo: hkdfExpand(prk: specPRK, info: authInfoLabel, count: authInfoLength),
            authContext: hkdfExpand(prk: specPRK, info: authContextLabel, count: authContextLength),
            authPaddingLength: UInt8(authPaddingLengthValue),
            authPaddingKey: hkdfExpand(prk: specPRK, info: authPaddingKeyLabel, count: authPaddingKeyLength),
            tcpPaddingLength: UInt8(tcpPaddingLengthValue),
            tcpPaddingKey: hkdfExpand(prk: specPRK, info: tcpPaddingKeyLabel, count: tcpPaddingKeyLength),
            tcpFrameOrder: frameOrder.tcp,
            udpFrameOrder: frameOrder.udp
        )
    }

    static func makeAuthFrame(key: String, protocolSpec: EffectiveSpec) throws -> Data {
        var nonce = Data(count: 32)
        let rv = nonce.withUnsafeMutableBytes { raw -> Int32 in
            guard let ptr = raw.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, 32, ptr)
        }
        guard rv == errSecSuccess else {
            throw NowhereError.connectionFailed("Failed to generate auth nonce")
        }

        let padding = authPaddingBytes(protocolSpec: protocolSpec, nonce: nonce)
        var message = Data()
        message.append(protocolSpec.authInfo)
        message.append(protocolSpec.authContext)
        message.append(nonce)
        message.append(protocolSpec.authPaddingLength)
        message.append(padding)

        let authKey = Data(SHA256.hash(data: Data(key.utf8)))
        let tag = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: authKey)
        )

        var frame = Data(capacity: protocolSpec.authMagic.count + nonce.count + 1 + padding.count + authTagLength)
        frame.append(protocolSpec.authMagic)
        frame.append(nonce)
        frame.append(protocolSpec.authPaddingLength)
        frame.append(padding)
        frame.append(contentsOf: tag)
        return frame
    }

    private static func validateRequired(_ value: Data, name: String) throws {
        guard !value.isEmpty else {
            throw ProxyError.protocolError("Missing Nowhere \(name)")
        }
        try validateOptional(value, name: name)
    }

    @discardableResult
    private static func validateOptional(_ value: Data, name: String) throws -> Data {
        guard value.count <= maxInputLength else {
            throw ProxyError.protocolError("Nowhere \(name) exceeds \(maxInputLength) bytes")
        }
        return value
    }

    private static func hkdfExtract(salt: Data, input: Data) -> Data {
        let code = HMAC<SHA256>.authenticationCode(
            for: input,
            using: SymmetricKey(data: salt)
        )
        return Data(code)
    }

    private static func hkdfExpand(prk: Data, info: Data, count: Int) -> Data {
        var output = Data()
        var previous = Data()
        var counter: UInt8 = 1

        while output.count < count {
            var message = Data()
            message.append(previous)
            message.append(info)
            message.append(counter)
            previous = Data(HMAC<SHA256>.authenticationCode(
                for: message,
                using: SymmetricKey(data: prk)
            ))
            output.append(previous)
            counter &+= 1
        }

        return output.prefix(count)
    }

    private static func authPaddingBytes(protocolSpec: EffectiveSpec, nonce: Data) -> Data {
        var info = Data(capacity: authPaddingBytesLabel.count + nonce.count + 1)
        info.append(authPaddingBytesLabel)
        info.append(nonce)
        info.append(protocolSpec.authPaddingLength)
        return hkdfExpand(
            prk: protocolSpec.authPaddingKey,
            info: info,
            count: Int(protocolSpec.authPaddingLength)
        )
    }

    private static func tcpRequestPaddingBytes(protocolSpec: EffectiveSpec, target: String) -> Data {
        let targetBytes = Data(target.utf8)
        var info = Data(capacity: tcpPaddingBytesLabel.count + targetBytes.count + 1)
        info.append(tcpPaddingBytesLabel)
        info.append(targetBytes)
        info.append(protocolSpec.tcpPaddingLength)
        return hkdfExpand(
            prk: protocolSpec.tcpPaddingKey,
            info: info,
            count: Int(protocolSpec.tcpPaddingLength)
        )
    }

    private static func base64URLNoPadding(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func buildFrameOrder(seed: Data) -> (tcp: [FrameElement], udp: [FrameElement]) {
        var tcp: [FrameElement] = [.version, .target, .padding]
        for i in stride(from: tcp.count - 1, through: 1, by: -1) {
            let seedIndex = tcp.count - 1 - i
            let seedByte = seedIndex < seed.count ? byte(seed, at: seedIndex) : 0
            tcp.swapAt(i, Int(seedByte) % (i + 1))
        }

        var udp: [FrameElement] = [.version, .type, .flowID, .target]
        guard !seed.isEmpty else { return (tcp, udp) }
        for i in stride(from: udp.count - 1, through: 1, by: -1) {
            let seedIndex = udp.count - i
            let seedByte = seedIndex < seed.count ? byte(seed, at: seedIndex) : 0
            udp.swapAt(i, Int(seedByte) % (i + 1))
        }
        return (tcp, udp)
    }

    static func encodeTCPRequest(address: String, protocolSpec: EffectiveSpec) throws -> Data {
        let targetBytes = try encodeTarget(address)
        let padding = tcpRequestPaddingBytes(protocolSpec: protocolSpec, target: address)
        var out = Data(capacity: 1 + targetBytes.count + 1 + padding.count)
        for element in protocolSpec.tcpFrameOrder {
            switch element {
            case .version:
                out.append(proxyFrameVersion)
            case .target:
                out.append(targetBytes)
            case .padding:
                out.append(protocolSpec.tcpPaddingLength)
                out.append(padding)
            case .type, .flowID:
                break
            }
        }
        return out
    }

    static func encodeUDPDatagram(type: UDPType, flowID: UInt64, target: String, payload: Data, protocolSpec: EffectiveSpec) throws -> Data {
        let header = try encodeUDPHeader(type: type, flowID: flowID, target: target, protocolSpec: protocolSpec)
        var out = Data(capacity: header.count + payload.count)
        out.append(header)
        out.append(payload)
        return out
    }

    private static func encodeUDPHeader(type: UDPType, flowID: UInt64, target: String, protocolSpec: EffectiveSpec) throws -> Data {
        let targetBytes = try encodeTarget(target)
        var out = Data(capacity: udpHeaderSize(target: target, protocolSpec: protocolSpec))
        for element in protocolSpec.udpFrameOrder {
            switch element {
            case .version:
                out.append(proxyFrameVersion)
            case .type:
                out.append(type.rawValue)
            case .flowID:
                out.append(uint64Bytes(flowID))
            case .target:
                out.append(targetBytes)
            case .padding:
                break
            }
        }
        return out
    }

    static func decodeUDPDatagram(_ data: Data, protocolSpec: EffectiveSpec) -> UDPMessage? {
        guard data.count >= 12 else { return nil }
        var offset = 0
        var frameType: UInt8?
        var flowID: UInt64?
        var target: String?
        for element in protocolSpec.udpFrameOrder {
            switch element {
            case .version:
                guard offset < data.count, byte(data, at: offset) == proxyFrameVersion else { return nil }
                offset += 1
            case .type:
                guard offset < data.count else { return nil }
                frameType = byte(data, at: offset)
                offset += 1
            case .flowID:
                guard offset + 8 <= data.count else { return nil }
                flowID = readUInt64(data, at: offset)
                offset += 8
            case .target:
                guard let parsed = decodeTarget(data, offset: offset) else { return nil }
                target = parsed.target
                offset = data.distance(from: data.startIndex, to: parsed.nextOffset)
            case .padding:
                break
            }
        }
        guard let type = frameType,
              type == UDPType.response.rawValue || type == UDPType.close.rawValue,
              let flowID,
              let target else { return nil }
        let payload = data.subdata(in: data.index(data.startIndex, offsetBy: offset)..<data.endIndex)
        return UDPMessage(type: type, flowID: flowID, target: target, payload: payload)
    }

    static func udpHeaderSize(target: String, protocolSpec _: EffectiveSpec) -> Int {
        1 + 1 + 8 + 2 + target.utf8.count
    }

    private static func encodeTarget(_ target: String) throws -> Data {
        let bytes = Data(target.utf8)
        guard !bytes.isEmpty, bytes.count <= maxTargetLength else {
            throw NowhereError.invalidTargetLength(bytes.count)
        }
        var out = Data(capacity: 2 + bytes.count)
        out.append(UInt8((bytes.count >> 8) & 0xFF))
        out.append(UInt8(bytes.count & 0xFF))
        out.append(bytes)
        return out
    }

    private static func decodeTarget(_ data: Data, offset: Int) -> (target: String, nextOffset: Data.Index)? {
        guard offset + 2 <= data.count else { return nil }
        let len = (Int(byte(data, at: offset)) << 8) | Int(byte(data, at: offset + 1))
        guard len > 0, len <= maxTargetLength, offset + 2 + len <= data.count else { return nil }
        let start = data.index(data.startIndex, offsetBy: offset + 2)
        let end = data.index(start, offsetBy: len)
        guard let target = String(data: data[start..<end], encoding: .utf8) else { return nil }
        return (target, end)
    }

    private static func uint64Bytes(_ value: UInt64) -> Data {
        var v = value.bigEndian
        return withUnsafeBytes(of: &v) { Data($0) }
    }

    private static func readUInt64(_ data: Data, at offset: Int) -> UInt64 {
        data.withUnsafeBytes { raw in
            var value: UInt64 = 0
            memcpy(&value, raw.baseAddress!.advanced(by: offset), 8)
            return UInt64(bigEndian: value)
        }
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> Int {
        guard offset + 2 <= data.count else { return 0 }
        return (Int(byte(data, at: offset)) << 8) | Int(byte(data, at: offset + 1))
    }

    private static func byte(_ data: Data, at offset: Int) -> UInt8 {
        data[data.index(data.startIndex, offsetBy: offset)]
    }
}
