//
//  NowhereProtocol.swift
//  Anywhere
//
// Created by NodePassProject on 5/29/26.
//

import Foundation
import CryptoKit
import Security

enum NowhereProtocol {
    static let alpn = "nowhere/1"
    static let authFrameLength = 80
    static let maxTargetLength = 512

    private static let authMagic = Data("NWQAUTH1".utf8)
    private static let authInfo = Data("nowhere quic auth v1".utf8)
    private static let sideMagic = Data([0x00, 0x4E, 0x57, 0x53])

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

    struct SideFrame {
        let type: UInt8
        let clientID: UInt64
        let flowID: UInt64
        let target: String
        let payload: Data
    }

    static func randomClientID() -> UInt64 {
        var bytes = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        var value: UInt64 = 0
        for byte in bytes {
            value = (value << 8) | UInt64(byte)
        }
        return value == 0 ? 1 : value
    }

    static func makeAuthFrame(key: String, clientID: UInt64) throws -> Data {
        var nonce = Data(count: 32)
        let rv = nonce.withUnsafeMutableBytes { raw -> Int32 in
            guard let ptr = raw.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, 32, ptr)
        }
        guard rv == errSecSuccess else {
            throw NowhereError.connectionFailed("Failed to generate auth nonce")
        }

        let clientBytes = uint64Bytes(clientID)
        var message = Data()
        message.append(authInfo)
        message.append(clientBytes)
        message.append(nonce)

        let derived = Data(SHA256.hash(data: Data(key.utf8)))
        let tag = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: derived)
        )

        var frame = Data(capacity: authFrameLength)
        frame.append(authMagic)
        frame.append(clientBytes)
        frame.append(nonce)
        frame.append(contentsOf: tag)
        return frame
    }

    static func encodeTCPRequest(address: String) throws -> Data {
        try encodeTarget(address)
    }

    static func encodeUDPDatagram(type: UDPType, flowID: UInt64, target: String, payload: Data) throws -> Data {
        let targetBytes = try encodeTarget(target)
        var out = Data(capacity: 1 + 8 + targetBytes.count + payload.count)
        out.append(type.rawValue)
        out.append(uint64Bytes(flowID))
        out.append(targetBytes)
        out.append(payload)
        return out
    }

    static func decodeUDPDatagram(_ data: Data) -> UDPMessage? {
        guard data.count >= 11 else { return nil }
        let type = byte(data, at: 0)
        guard type == UDPType.response.rawValue || type == UDPType.close.rawValue else { return nil }
        let flowID = readUInt64(data, at: 1)
        guard let parsed = decodeTarget(data, offset: 9) else { return nil }
        let payload = data.subdata(in: parsed.nextOffset..<data.endIndex)
        return UDPMessage(type: type, flowID: flowID, target: parsed.target, payload: payload)
    }

    static func encodeSideFrame(type: UDPType, clientID: UInt64, flowID: UInt64, target: String, payload: Data) throws -> Data {
        let targetBytes = try encodeTarget(target)
        var out = Data(capacity: 4 + 1 + 8 + 8 + targetBytes.count + payload.count)
        out.append(sideMagic)
        out.append(type.rawValue)
        out.append(uint64Bytes(clientID))
        out.append(uint64Bytes(flowID))
        out.append(targetBytes)
        out.append(payload)
        return out
    }

    static func decodeSideFrame(_ data: Data) -> SideFrame? {
        guard data.count >= 23, data.prefix(sideMagic.count) == sideMagic else { return nil }
        let type = byte(data, at: 4)
        guard type == UDPType.response.rawValue || type == UDPType.close.rawValue else { return nil }
        let clientID = readUInt64(data, at: 5)
        let flowID = readUInt64(data, at: 13)
        guard let parsed = decodeTarget(data, offset: 21) else { return nil }
        let payload = data.subdata(in: parsed.nextOffset..<data.endIndex)
        return SideFrame(type: type, clientID: clientID, flowID: flowID, target: parsed.target, payload: payload)
    }

    static func isSideFrame(_ data: Data) -> Bool {
        data.count >= sideMagic.count && data.prefix(sideMagic.count) == sideMagic
    }

    static func isQUICLongHeader(_ data: Data) -> Bool {
        guard !data.isEmpty else { return false }
        return (byte(data, at: 0) & 0x80) != 0
    }

    static func isQUICShortHeader(_ data: Data) -> Bool {
        guard !data.isEmpty else { return false }
        let first = byte(data, at: 0)
        return (first & 0x80) == 0 && (first & 0x40) != 0
    }

    static func udpHeaderSize(target: String) -> Int {
        1 + 8 + 2 + target.utf8.count
    }

    static func sideHeaderSize(target: String) -> Int {
        4 + 1 + 8 + 8 + 2 + target.utf8.count
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
