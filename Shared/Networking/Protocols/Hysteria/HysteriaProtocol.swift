//
//  HysteriaProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Security

nonisolated enum HysteriaProtocol {
    static let tcpRequestFrameType: UInt64 = 0x401
    
    static let closeErrCodeOK: UInt64 = 0x100
    static let closeErrCodeProtocolError: UInt64 = 0x101
    
    static let tcpResponseStatusOK: UInt8 = 0
    static let authSuccessStatus = 233

    // MARK: Padding ranges
    
    static let authPaddingRange: ClosedRange<Int> = 256...2047
    static let tcpRequestPaddingRange: ClosedRange<Int> = 64...511

    // MARK: Limits

    static let maxAddressLength = 2048
    static let maxResponseMessageLength = 2048
    static let maxPaddingLength = 4096

    // MARK: - VarInt (QUIC RFC 9000 §16)
    
    static func encodeVarInt(_ value: UInt64) -> Data? {
        if value < (1 << 6) {
            return Data([UInt8(value)])
        }
        if value < (1 << 14) {
            let v = value | (UInt64(0b01) << 14)
            return Data([UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)])
        }
        if value < (1 << 30) {
            let v = value | (UInt64(0b10) << 30)
            return Data([
                UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
                UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF),
            ])
        }
        if value < (UInt64(1) << 62) {
            let v = value | (UInt64(0b11) << 62)
            return Data([
                UInt8((v >> 56) & 0xFF), UInt8((v >> 48) & 0xFF),
                UInt8((v >> 40) & 0xFF), UInt8((v >> 32) & 0xFF),
                UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
                UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF),
            ])
        }
        return nil
    }
    
    static func decodeVarInt(from data: Data, offset: Int = 0) -> (UInt64, Int)? {
        guard offset < data.count else { return nil }
        let first = data[data.index(data.startIndex, offsetBy: offset)]
        let prefix = first >> 6
        let length = 1 << Int(prefix)
        guard offset + length <= data.count else { return nil }

        var decoded: UInt64 = UInt64(first & 0x3F)
        for i in 1..<length {
            decoded = (decoded << 8) | UInt64(data[data.index(data.startIndex, offsetBy: offset + i)])
        }
        return (decoded, length)
    }
    
    static func varIntLength(_ value: UInt64) -> Int {
        if value < (1 << 6) { return 1 }
        if value < (1 << 14) { return 2 }
        if value < (1 << 30) { return 4 }
        return 8
    }

    // MARK: - TCP framing
    
    static func encodeTCPRequest(address: String) -> Data {
        let addrBytes = Data(address.utf8)
        let padLen = Int.random(in: tcpRequestPaddingRange)
        let padBytes = randomPadding(length: padLen)

        var out = Data()
        out.append(encodeVarInt(tcpRequestFrameType)!)
        out.append(encodeVarInt(UInt64(addrBytes.count))!)
        out.append(addrBytes)
        out.append(encodeVarInt(UInt64(padBytes.count))!)
        out.append(padBytes)
        return out
    }
    
    static func parseTCPResponse(from data: Data) -> (status: UInt8, message: String, consumed: Int)? {
        guard !data.isEmpty else { return nil }
        var offset = 0
        let status = data[data.index(data.startIndex, offsetBy: offset)]
        offset += 1

        guard let (msgLen, msgLenLen) = decodeVarInt(from: data, offset: offset),
              msgLen <= UInt64(maxResponseMessageLength) else { return nil }
        offset += msgLenLen
        guard offset + Int(msgLen) <= data.count else { return nil }
        let msgStart = data.index(data.startIndex, offsetBy: offset)
        let msgEnd = data.index(msgStart, offsetBy: Int(msgLen))
        let message = String(data: data[msgStart..<msgEnd], encoding: .utf8) ?? ""
        offset += Int(msgLen)

        guard let (padLen, padLenLen) = decodeVarInt(from: data, offset: offset),
              padLen <= UInt64(maxPaddingLength) else { return nil }
        offset += padLenLen
        guard offset + Int(padLen) <= data.count else { return nil }
        offset += Int(padLen)

        return (status, message, offset)
    }

    // MARK: - UDP datagram framing
    
    static let udpHeaderFixedSize = 4 + 2 + 1 + 1

    struct UDPMessage: Sendable {
        let sessionID: UInt32
        let packetID: UInt16
        let fragID: UInt8
        let fragCount: UInt8
        let address: String
        let data: Data
        
        var encoded: Data {
            let addrBytes = Data(address.utf8)
            let addrLenVarInt = HysteriaProtocol.encodeVarInt(UInt64(addrBytes.count))!

            var out = Data(capacity: HysteriaProtocol.udpHeaderFixedSize + addrLenVarInt.count + addrBytes.count + data.count)

            var sid = sessionID.bigEndian
            withUnsafeBytes(of: &sid) { out.append(contentsOf: $0) }
            var pid = packetID.bigEndian
            withUnsafeBytes(of: &pid) { out.append(contentsOf: $0) }
            out.append(fragID)
            out.append(fragCount)

            out.append(addrLenVarInt)
            out.append(addrBytes)
            out.append(data)
            return out
        }
    }
    
    static func decodeUDPMessage(_ data: Data) -> UDPMessage? {
        guard data.count >= udpHeaderFixedSize else { return nil }
        var offset = 0

        let sessionID = data.withUnsafeBytes { buffer -> UInt32 in
            var v: UInt32 = 0
            memcpy(&v, buffer.baseAddress!.advanced(by: 0), 4)
            return UInt32(bigEndian: v)
        }
        offset += 4
        let packetID = data.withUnsafeBytes { buffer -> UInt16 in
            var v: UInt16 = 0
            memcpy(&v, buffer.baseAddress!.advanced(by: 4), 2)
            return UInt16(bigEndian: v)
        }
        offset += 2
        let fragID = data[data.index(data.startIndex, offsetBy: offset)]
        offset += 1
        let fragCount = data[data.index(data.startIndex, offsetBy: offset)]
        offset += 1
        
        guard let (addrLen, addrLenLen) = decodeVarInt(from: data, offset: offset),
              addrLen > 0, addrLen <= UInt64(maxAddressLength) else { return nil }
        offset += addrLenLen
        guard offset + Int(addrLen) < data.count else { return nil }
        let addrStart = data.index(data.startIndex, offsetBy: offset)
        let addrEnd = data.index(addrStart, offsetBy: Int(addrLen))
        guard let address = String(data: data[addrStart..<addrEnd], encoding: .utf8) else { return nil }
        offset += Int(addrLen)
        
        let payloadStart = data.index(data.startIndex, offsetBy: offset)
        let payload = data.subdata(in: payloadStart..<data.endIndex)
        return UDPMessage(
            sessionID: sessionID,
            packetID: packetID,
            fragID: fragID,
            fragCount: fragCount,
            address: address,
            data: payload
        )
    }
    
    static func udpHeaderSize(address: String) -> Int {
        let addrBytes = address.utf8.count
        return udpHeaderFixedSize + varIntLength(UInt64(addrBytes)) + addrBytes
    }
    
    static func fragmentUDP(
        sessionID: UInt32,
        packetID: UInt16,
        address: String,
        data: Data,
        maxDatagramSize: Int
    ) -> [UDPMessage] {
        let headerSize = udpHeaderSize(address: address)
        let maxPayload = max(1, maxDatagramSize - headerSize)
        if data.count <= maxPayload {
            return [
                UDPMessage(
                    sessionID: sessionID,
                    packetID: packetID,
                    fragID: 0,
                    fragCount: 1,
                    address: address,
                    data: data
                )
            ]
        }
        let chunks = Int((data.count + maxPayload - 1) / maxPayload)
        guard chunks <= Int(UInt8.max) else { return [] }
        var out: [UDPMessage] = []
        out.reserveCapacity(chunks)
        for i in 0..<chunks {
            let start = i * maxPayload
            let end = min(start + maxPayload, data.count)
            let chunk = Data(data[data.index(data.startIndex, offsetBy: start)..<data.index(data.startIndex, offsetBy: end)])
            out.append(
                UDPMessage(
                    sessionID: sessionID,
                    packetID: packetID,
                    fragID: UInt8(i),
                    fragCount: UInt8(chunks),
                    address: address,
                    data: chunk
                )
            )
        }
        return out
    }

    // MARK: - Padding generation
    
    static func randomPadding(length: Int) -> Data {
        guard length > 0 else { return Data() }
        let alphabet: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".utf8)
        var out = Data(count: length)
        out.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, length, base)
            let bytes = base.assumingMemoryBound(to: UInt8.self)
            for i in 0..<length {
                bytes[i] = alphabet[Int(bytes[i]) % alphabet.count]
            }
        }
        return out
    }
    
    static func randomPaddingString(range: ClosedRange<Int> = authPaddingRange) -> String {
        let length = Int.random(in: range)
        return String(data: randomPadding(length: length), encoding: .utf8) ?? ""
    }
}
