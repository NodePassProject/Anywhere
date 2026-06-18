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
    static let authFrameLength = 72
    static let protocolVersion: UInt8 = 1
    static let frameHeaderLength = 15
    static let maxTargetLength = 512
    static let defaultALPN = "now/1"
    static let frameFlagUpload: UInt8 = 1
    static let frameFlagDownload: UInt8 = 2
    
    static let closeErrCodeOK: UInt64 = 0x100

    private static let maxInputLength = 255
    private static let specIDLength = 8
    private static let authMagicLength = 8
    private static let authInfoLength = 32
    private static let specCommitmentLength = 32
    private static let behaviorSeedLength = 32

    private static let labelMaster = Data("portal".utf8)
    private static let labelMagic = Data("magic".utf8)
    private static let labelAuthInfo = Data("auth".utf8)
    private static let labelAuthKey = Data("auth-key".utf8)
    private static let labelAuthFrame = Data("auth-frame".utf8)
    private static let labelSpecID = Data("spec-id".utf8)
    private static let labelSpecCommitment = Data("spec-commitment".utf8)
    private static let labelBehaviorSeed = Data("behavior".utf8)

    struct EffectiveSpec: Hashable {
        let effectiveSpec: String
        let specEnabled: Bool
        let effectiveALPN: String
        let derivedALPN: String
        let effectiveSpecID: String
        let authMagic: Data
        let authInfo: Data
        let specCommitment: Data
        let behaviorSeed: Data
    }

    enum UDPType: UInt8 {
        case request = 1
        case response = 2
        case close = 3
    }

    enum FrameType: UInt8 {
        case auth = 1
        case settings = 2
        case laneAttach = 3
        case laneAccept = 4
        case routeUpdate = 5
        case routeAccept = 6
        case routeReject = 7
        case flowOpen = 16
        case flowData = 17
        case flowClose = 18
        case udpData = 24
        case ping = 32
        case pong = 33
        case error = 34
    }

    enum LaneKind: UInt8, Hashable {
        case quic = 1
        case tcp = 2

        var displayName: String {
            switch self {
            case .quic: "UDP"
            case .tcp: "TCP"
            }
        }
    }

    struct Frame {
        let type: FrameType
        let flags: UInt8
        let flowID: UInt64
        let payload: Data
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

        let effectiveSpecString = if let spec, !spec.isEmpty {
            spec
        } else {
            "auto"
        }
        try validateOptional(Data(effectiveSpecString.utf8), name: "spec")
        let specEnabled = effectiveSpecString.lowercased() != "off"

        let effectiveALPN: String
        if let alpn, !alpn.isEmpty {
            try validateOptional(Data(alpn.utf8), name: "alpn")
            effectiveALPN = alpn
        } else {
            effectiveALPN = defaultALPN
        }

        let keyMaster = hkdfExtract(salt: labelMaster, input: keyBytes)
        let authInfo = hkdfExpand(prk: keyMaster, info: labelAuthInfo, count: authInfoLength)
        let specSeedBytes = Data((specEnabled ? effectiveSpecString : "off").utf8)
        let specHash = Data(SHA256.hash(data: specSeedBytes))
        let specMaster = hkdfExtract(salt: authInfo, input: specHash)

        return EffectiveSpec(
            effectiveSpec: effectiveSpecString,
            specEnabled: specEnabled,
            effectiveALPN: effectiveALPN,
            derivedALPN: defaultALPN,
            effectiveSpecID: base64URLNoPadding(hkdfExpand(prk: specMaster, info: labelSpecID, count: specIDLength)),
            authMagic: hkdfExpand(prk: keyMaster, info: labelMagic, count: authMagicLength),
            authInfo: authInfo,
            specCommitment: hkdfExpand(prk: specMaster, info: labelSpecCommitment, count: specCommitmentLength),
            behaviorSeed: hkdfExpand(prk: specMaster, info: labelBehaviorSeed, count: behaviorSeedLength)
        )
    }

    static func makeAuthPayload(key: String, protocolSpec: EffectiveSpec) throws -> Data {
        var nonce = Data(count: 32)
        let rv = nonce.withUnsafeMutableBytes { raw -> Int32 in
            guard let ptr = raw.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, 32, ptr)
        }
        guard rv == errSecSuccess else {
            throw NowhereError.connectionFailed("Failed to generate auth nonce")
        }

        var message = labelAuthFrame
        message.append(protocolSpec.authInfo)
        message.append(nonce)

        let keyMaster = hkdfExtract(salt: labelMaster, input: Data(key.utf8))
        let derived = hkdfExpand(prk: keyMaster, info: labelAuthKey, count: 32)
        let tag = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: derived)
        )

        var frame = Data(capacity: authFrameLength)
        frame.append(protocolSpec.authMagic)
        frame.append(nonce)
        frame.append(contentsOf: tag)
        return frame
    }

    static func makeAuthFrame(key: String, protocolSpec: EffectiveSpec) throws -> Data {
        try encodeFrame(Frame(type: .auth, flags: 0, flowID: 0, payload: makeAuthPayload(key: key, protocolSpec: protocolSpec)))
    }

    static func makeLaneAttachFrame(sessionID: UInt64, key: String, protocolSpec: EffectiveSpec) throws -> Data {
        var payload = uint64Bytes(sessionID)
        payload.append(try makeAuthPayload(key: key, protocolSpec: protocolSpec))
        return encodeFrame(Frame(type: .laneAttach, flags: 0, flowID: 0, payload: payload))
    }

    static func decodeSessionIDPayload(_ payload: Data) -> UInt64? {
        guard payload.count == 8 else { return nil }
        return readUInt64(payload, at: 0)
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

    private static func base64URLNoPadding(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func encodeTCPRequest(address: String, flowID: UInt64, generation: UInt64 = 1, uploadLane: LaneKind = .quic, downloadLane: LaneKind = .quic) throws -> Data {
        var payload = Data()
        payload.append(uint64Bytes(generation))
        payload.append(uploadLane.rawValue)
        payload.append(downloadLane.rawValue)
        payload.append(try encodeTarget(address))
        return encodeFrame(Frame(type: .flowOpen, flags: 0, flowID: flowID, payload: payload))
    }

    static func encodeTCPData(flowID: UInt64, payload: Data) -> Data {
        encodeFrame(Frame(type: .flowData, flags: frameFlagUpload, flowID: flowID, payload: payload))
    }

    static func encodeTCPClose(flowID: UInt64) -> Data {
        encodeFrame(Frame(type: .flowClose, flags: frameFlagUpload, flowID: flowID, payload: Data()))
    }

    static func encodeUDPDatagram(type: UDPType, flowID: UInt64, target: String, payload: Data) throws -> Data {
        var out = Data()
        let targetBytes = try encodeTarget(target)
        out.append(targetBytes)
        out.append(payload)
        return encodeFrame(Frame(type: .udpData, flags: type.rawValue, flowID: flowID, payload: out))
    }

    static func decodeUDPDatagram(_ data: Data) -> UDPMessage? {
        guard let frame = decodeFrame(data), frame.type == .udpData else { return nil }
        let type = frame.flags
        guard type == UDPType.response.rawValue || type == UDPType.close.rawValue else { return nil }
        guard let parsed = decodeTarget(frame.payload, offset: 0) else { return nil }
        let payload = frame.payload.subdata(in: parsed.nextOffset..<frame.payload.endIndex)
        return UDPMessage(type: type, flowID: frame.flowID, target: parsed.target, payload: payload)
    }

    static func udpHeaderSize(target: String) -> Int {
        frameHeaderLength + 2 + target.utf8.count
    }

    static func encodeFrame(_ frame: Frame) -> Data {
        var out = Data(capacity: frameHeaderLength + frame.payload.count)
        out.append(protocolVersion)
        out.append(frame.type.rawValue)
        out.append(frame.flags)
        out.append(uint64Bytes(frame.flowID))
        out.append(UInt8((frame.payload.count >> 24) & 0xFF))
        out.append(UInt8((frame.payload.count >> 16) & 0xFF))
        out.append(UInt8((frame.payload.count >> 8) & 0xFF))
        out.append(UInt8(frame.payload.count & 0xFF))
        out.append(frame.payload)
        return out
    }

    static func decodeFrame(_ data: Data) -> Frame? {
        var buffer = data
        return takeFrame(from: &buffer)
    }

    static func takeFrame(from buffer: inout Data) -> Frame? {
        guard buffer.count >= frameHeaderLength else { return nil }
        guard byte(buffer, at: 0) == protocolVersion else { return nil }
        guard let type = FrameType(rawValue: byte(buffer, at: 1)) else { return nil }
        let flags = byte(buffer, at: 2)
        let flowID = readUInt64(buffer, at: 3)
        let length = (Int(byte(buffer, at: 11)) << 24)
            | (Int(byte(buffer, at: 12)) << 16)
            | (Int(byte(buffer, at: 13)) << 8)
            | Int(byte(buffer, at: 14))
        guard buffer.count >= frameHeaderLength + length else { return nil }
        let payloadStart = buffer.index(buffer.startIndex, offsetBy: frameHeaderLength)
        let payloadEnd = buffer.index(payloadStart, offsetBy: length)
        let payload = Data(buffer[payloadStart..<payloadEnd])
        buffer.removeFirst(frameHeaderLength + length)
        return Frame(type: type, flags: flags, flowID: flowID, payload: payload)
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

    private static func byte(_ data: Data, at offset: Int) -> UInt8 {
        data[data.index(data.startIndex, offsetBy: offset)]
    }
}
