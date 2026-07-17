//
//  NowhereProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import CryptoKit
import Security

nonisolated enum NowhereProtocol {
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
    private static let authFrameLayoutLabel = Data("auth frame layout".utf8)
    private static let frameLayoutLabel = Data("proxy frame layout".utf8)

    static func normalizedSpec(_ spec: String?) -> String {
        let trimmed = spec?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return trimmed.isEmpty ? defaultSpec : trimmed
    }

    enum AuthFrameElement: UInt8, Hashable {
        case magic
        case nonce
        case padding
        case tag
    }

    enum FrameElement: UInt8, Hashable {
        case version
        case target
        case padding
    }

    struct EffectiveSpec: Hashable {
        let effectiveALPN: String
        let defaultALPN: String
        let effectiveSpecID: String
        let authMagic: Data
        let authFrameOrder: [AuthFrameElement]
        let authInfo: Data
        let authContext: Data
        let authPaddingLength: UInt8
        let authPaddingKey: Data
        let tcpPaddingLength: UInt8
        let tcpPaddingKey: Data
        let tcpFrameOrder: [FrameElement]
    }

    enum UDPType: UInt8, Equatable {
        case data = 1
        case close = 2
    }

    struct UDPMessage: Sendable {
        let type: UDPType
        let flowID: UInt64
        let packetID: UInt32
        let fragmentID: UInt8
        let fragmentCount: UInt8
        let totalLength: UInt16
        let payload: Data
    }

    enum UDPStreamType: UInt8, Equatable {
        case data = 1
        case ready = 2
        case close = 3
        case reject = 4
    }

    static let udpFrameMagic = Data("NOWU".utf8)
    static let maxUDPPacketSize = Int(UInt16.max)
    static let udpControlHeaderSize = 4 + 1 + 8
    static let udpDataHeaderSize = udpControlHeaderSize + 4 + 1 + 1 + 2

    enum FlowRole: UInt8 { case open = 1, attach = 2, duplex = 3 }
    enum FlowKind: UInt8 { case tcp = 1, udp = 2 }

    enum FlowResultStatus: UInt8, Equatable {
        case ready = 1
        case reject = 2
    }

    enum FlowRejectCode: UInt8, Equatable, CaseIterable {
        case invalidRequest = 1
        case metadataConflict = 2
        case pairTimeout = 3
        case flowLimit = 4
        case dialFailed = 5
        case sessionReplaced = 6
        case internalError = 7

        var description: String {
            switch self {
            case .invalidRequest: return "invalid request"
            case .metadataConflict: return "metadata conflict"
            case .pairTimeout: return "pair timeout"
            case .flowLimit: return "flow limit"
            case .dialFailed: return "dial failed"
            case .sessionReplaced: return "session replaced"
            case .internalError: return "internal error"
            }
        }
    }

    enum FlowResult: Equatable {
        case ready
        case reject(FlowRejectCode)
    }

    struct UDPStreamMessage: Equatable {
        let type: UDPStreamType
        let payload: Data
    }

    private static let flowResultMagic: UInt8 = 0xF2
    private static let flowResultVersion: UInt8 = 1
    static let flowResultSize = 4

    struct FlowHeader {
        let role: FlowRole
        let flowID: UInt64
        let kind: FlowKind
        let uplink: NowhereNetwork
        let downlink: NowhereNetwork
    }

    static func buildEffectiveSpec(key: String, spec: String?, alpn: String?) throws -> EffectiveSpec {
        let keyBytes = Data(key.utf8)
        try validateRequired(keyBytes, name: "shared key")

        let effectiveSpec = try validateOptional(Data(normalizedSpec(spec).utf8), name: "spec")

        let specSalt = Data(SHA256.hash(data: effectiveSpec))
        let specPRK = hkdfExtract(salt: specSalt, input: effectiveSpec)
        let authFrameOrder = buildAuthFrameOrder(seed: hkdfExpand(prk: specPRK, info: authFrameLayoutLabel, count: 8))
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
            authFrameOrder: authFrameOrder,
            authInfo: hkdfExpand(prk: specPRK, info: authInfoLabel, count: authInfoLength),
            authContext: hkdfExpand(prk: specPRK, info: authContextLabel, count: authContextLength),
            authPaddingLength: UInt8(authPaddingLengthValue),
            authPaddingKey: hkdfExpand(prk: specPRK, info: authPaddingKeyLabel, count: authPaddingKeyLength),
            tcpPaddingLength: UInt8(tcpPaddingLengthValue),
            tcpPaddingKey: hkdfExpand(prk: specPRK, info: tcpPaddingKeyLabel, count: tcpPaddingKeyLength),
            tcpFrameOrder: frameOrder
        )
    }

    static func makeAuthFrame(key: String, protocolSpec: EffectiveSpec, sessionID: Data) throws -> Data {
        guard sessionID.count == 16 else {
            throw NowhereError.connectionFailed("Invalid session ID")
        }
        var nonce = Data(count: 32)
        let randomStatus = nonce.withUnsafeMutableBytes { raw -> Int32 in
            guard let pointer = raw.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, 32, pointer)
        }
        guard randomStatus == errSecSuccess else {
            throw NowhereError.connectionFailed("Failed to generate auth nonce")
        }

        return try makeAuthFrame(
            key: key,
            protocolSpec: protocolSpec,
            sessionID: sessionID,
            nonce: nonce
        )
    }

    static func makeAuthFrame(
        key: String,
        protocolSpec: EffectiveSpec,
        sessionID: Data,
        nonce: Data
    ) throws -> Data {
        guard sessionID.count == 16, nonce.count == 32 else {
            throw NowhereError.connectionFailed("Invalid authentication material")
        }

        let padding = authPaddingBytes(protocolSpec: protocolSpec, nonce: nonce)
        var message = Data()
        message.append(protocolSpec.authInfo)
        message.append(protocolSpec.authContext)
        message.append(nonce)
        message.append(protocolSpec.authPaddingLength)
        message.append(padding)
        message.append(sessionID)

        let authKey = Data(SHA256.hash(data: Data(key.utf8)))
        let tag = HMAC<SHA256>.authenticationCode(
            for: message,
            using: SymmetricKey(data: authKey)
        )

        var paddingBlock = Data(capacity: 1 + padding.count)
        paddingBlock.append(protocolSpec.authPaddingLength)
        paddingBlock.append(padding)

        var frame = Data(capacity: protocolSpec.authMagic.count + nonce.count + 1 + padding.count + authTagLength)
        for element in protocolSpec.authFrameOrder {
            switch element {
            case .magic:
                frame.append(protocolSpec.authMagic)
            case .nonce:
                frame.append(nonce)
            case .padding:
                frame.append(paddingBlock)
            case .tag:
                frame.append(contentsOf: tag)
            }
        }
        frame.append(sessionID)
        return frame
    }

    static func encodeFlowHeader(_ header: FlowHeader) -> Data {
        var out = Data(capacity: 14)
        out.append(0xF1)
        out.append(1)
        out.append(header.role.rawValue)
        out.append(uint64Bytes(header.flowID))
        out.append(header.kind.rawValue)
        out.append(header.uplink == .tcp ? 1 : 2)
        out.append(header.downlink == .tcp ? 1 : 2)
        return out
    }

    static func isValidFlowHeader(_ header: FlowHeader) -> Bool {
        guard header.flowID != 0 else { return false }
        switch header.role {
        case .duplex:
            return header.uplink == header.downlink
        case .open, .attach:
            return header.uplink != header.downlink
        }
    }

    static func encodeFlowRequest(
        header: FlowHeader,
        target: String,
        protocolSpec: EffectiveSpec
    ) throws -> Data {
        guard isValidFlowHeader(header) else {
            throw NowhereError.connectionFailed("Invalid Nowhere flow metadata")
        }
        var out = encodeFlowHeader(header)
        if header.role != .attach {
            out.append(try encodeTCPRequest(address: target, protocolSpec: protocolSpec))
        }
        return out
    }

    static func encodeFlowResult(_ result: FlowResult) -> Data {
        switch result {
        case .ready:
            return Data([flowResultMagic, flowResultVersion, FlowResultStatus.ready.rawValue, 0])
        case .reject(let code):
            return Data([flowResultMagic, flowResultVersion, FlowResultStatus.reject.rawValue, code.rawValue])
        }
    }

    static func decodeFlowResult(_ data: Data) -> FlowResult? {
        guard data.count == flowResultSize,
              byte(data, at: 0) == flowResultMagic,
              byte(data, at: 1) == flowResultVersion,
              let status = FlowResultStatus(rawValue: byte(data, at: 2)) else { return nil }
        let code = byte(data, at: 3)
        switch status {
        case .ready:
            guard code == 0 else { return nil }
            return .ready
        case .reject:
            guard let rejectCode = FlowRejectCode(rawValue: code) else { return nil }
            return .reject(rejectCode)
        }
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

    private static func buildAuthFrameOrder(seed: Data) -> [AuthFrameElement] {
        let canonical: [AuthFrameElement] = [.magic, .nonce, .padding, .tag]
        var order = canonical
        for i in stride(from: order.count - 1, through: 1, by: -1) {
            let seedIndex = order.count - 1 - i
            let seedByte = seedIndex < seed.count ? byte(seed, at: seedIndex) : 0
            order.swapAt(i, Int(seedByte) % (i + 1))
        }
        if order == canonical {
            order.append(order.removeFirst())
        }
        return order
    }

    private static func buildFrameOrder(seed: Data) -> [FrameElement] {
        var tcp: [FrameElement] = [.version, .target, .padding]
        for i in stride(from: tcp.count - 1, through: 1, by: -1) {
            let seedIndex = tcp.count - 1 - i
            let seedByte = seedIndex < seed.count ? byte(seed, at: seedIndex) : 0
            tcp.swapAt(i, Int(seedByte) % (i + 1))
        }

        return tcp
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
            }
        }
        return out
    }

    static func encodeUDPDataFragments(
        flowID: UInt64,
        packetID: UInt32,
        payload: Data,
        maxDatagramSize: Int
    ) throws -> [Data] {
        try encodeUDPFragments(
            flowID: flowID,
            packetID: packetID,
            payload: payload,
            maxDatagramSize: maxDatagramSize
        )
    }

    static func encodeUDPControl(type: UDPType, flowID: UInt64) throws -> Data {
        guard flowID != 0 else { throw NowhereError.connectionFailed("Invalid flow ID") }
        guard type == .close else {
            throw NowhereError.connectionFailed("Invalid UDP control type")
        }
        var out = Data(capacity: udpControlHeaderSize)
        out.append(udpFrameMagic)
        out.append(type.rawValue)
        out.append(uint64Bytes(flowID))
        return out
    }

    static func encodeUDPStreamFrame(type: UDPStreamType, payload: Data = Data()) throws -> Data {
        guard payload.count <= maxUDPPacketSize else {
            if type == .data { throw NowhereError.udpPacketTooLarge }
            throw NowhereError.connectionFailed("UoT control payload exceeds 65535 bytes")
        }
        switch type {
        case .data:
            break
        case .ready, .close:
            guard payload.isEmpty else {
                throw NowhereError.connectionFailed("UDP control frame has payload")
            }
        case .reject:
            guard payload.count == 1,
                  FlowRejectCode(rawValue: byte(payload, at: 0)) != nil else {
                throw NowhereError.connectionFailed("Invalid UoT reject frame")
            }
        }
        var out = Data(capacity: 3 + payload.count)
        out.append(type.rawValue)
        out.append(UInt8((payload.count >> 8) & 0xFF))
        out.append(UInt8(payload.count & 0xFF))
        out.append(payload)
        return out
    }

    static func decodeUDPStreamFrame(_ data: Data, offset: Int = 0) -> (UDPStreamMessage, Int)? {
        guard offset >= 0, offset + 3 <= data.count,
              let type = UDPStreamType(rawValue: byte(data, at: offset)) else { return nil }
        let length = Int(readUInt16(data, at: offset + 1))
        guard offset + 3 + length <= data.count else { return nil }
        let start = data.index(data.startIndex, offsetBy: offset + 3)
        let end = data.index(start, offsetBy: length)
        let payload = Data(data[start..<end])
        switch type {
        case .data:
            break
        case .ready, .close:
            guard payload.isEmpty else { return nil }
        case .reject:
            guard payload.count == 1,
                  FlowRejectCode(rawValue: byte(payload, at: 0)) != nil else { return nil }
        }
        return (UDPStreamMessage(type: type, payload: payload), 3 + length)
    }

    private static func encodeUDPFragments(
        flowID: UInt64,
        packetID: UInt32,
        payload: Data,
        maxDatagramSize: Int
    ) throws -> [Data] {
        guard flowID != 0 else { throw NowhereError.connectionFailed("Invalid flow ID") }
        guard packetID != 0 else { throw NowhereError.connectionFailed("Invalid UDP packet ID") }
        guard payload.count <= maxUDPPacketSize else {
            throw NowhereError.udpPacketTooLarge
        }
        let headerSize = udpDataHeaderSize
        guard maxDatagramSize >= headerSize else {
            throw NowhereError.destinationTooLargeForDatagram(
                maxFrame: maxDatagramSize,
                headerSize: headerSize
            )
        }
        let maxPayload = maxDatagramSize - headerSize
        guard payload.isEmpty || maxPayload > 0 else {
            throw NowhereError.destinationTooLargeForDatagram(
                maxFrame: maxDatagramSize,
                headerSize: headerSize
            )
        }
        let fragmentCount = payload.isEmpty ? 1 : (payload.count + maxPayload - 1) / maxPayload
        guard fragmentCount <= Int(UInt8.max) else {
            throw NowhereError.udpPacketTooLarge
        }
        var frames: [Data] = []
        frames.reserveCapacity(fragmentCount)
        for fragmentID in 0..<fragmentCount {
            let start = fragmentID * maxPayload
            let end = min(payload.count, start + maxPayload)
            var out = Data(capacity: headerSize + end - start)
            out.append(udpFrameMagic)
            out.append(UDPType.data.rawValue)
            out.append(uint64Bytes(flowID))
            out.append(UInt8((packetID >> 24) & 0xFF))
            out.append(UInt8((packetID >> 16) & 0xFF))
            out.append(UInt8((packetID >> 8) & 0xFF))
            out.append(UInt8(packetID & 0xFF))
            out.append(UInt8(fragmentID))
            out.append(UInt8(fragmentCount))
            out.append(UInt8((payload.count >> 8) & 0xFF))
            out.append(UInt8(payload.count & 0xFF))
            if end > start {
                let startIndex = payload.index(payload.startIndex, offsetBy: start)
                let endIndex = payload.index(payload.startIndex, offsetBy: end)
                out.append(payload[startIndex..<endIndex])
            }
            frames.append(out)
        }
        return frames
    }

    static func decodeUDPDatagram(_ data: Data) -> UDPMessage? {
        guard data.count >= udpControlHeaderSize,
              data.prefix(udpFrameMagic.count) == udpFrameMagic,
              let type = UDPType(rawValue: byte(data, at: udpFrameMagic.count)) else { return nil }
        let flowID = readUInt64(data, at: udpFrameMagic.count + 1)
        guard flowID != 0 else { return nil }
        if type == .close {
            guard data.count == udpControlHeaderSize else { return nil }
            return UDPMessage(
                type: type, flowID: flowID,
                packetID: 0, fragmentID: 0, fragmentCount: 0, totalLength: 0,
                payload: Data()
            )
        }

        var offset = udpControlHeaderSize
        guard type == .data, offset + 8 <= data.count else { return nil }
        let packetID = readUInt32(data, at: offset)
        let fragmentID = byte(data, at: offset + 4)
        let fragmentCount = byte(data, at: offset + 5)
        let totalLength = UInt16(readUInt16(data, at: offset + 6))
        offset += 8
        guard packetID != 0, fragmentCount > 0, fragmentID < fragmentCount else { return nil }
        let payload = data.subdata(in: data.index(data.startIndex, offsetBy: offset)..<data.endIndex)
        guard payload.count <= Int(totalLength) else { return nil }
        if totalLength == 0 {
            guard fragmentCount == 1, fragmentID == 0, payload.isEmpty else { return nil }
        } else {
            guard !payload.isEmpty else { return nil }
            if fragmentCount == 1, payload.count != Int(totalLength) { return nil }
        }
        return UDPMessage(
            type: type, flowID: flowID,
            packetID: packetID, fragmentID: fragmentID, fragmentCount: fragmentCount,
            totalLength: totalLength, payload: payload
        )
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
        let length = (Int(byte(data, at: offset)) << 8) | Int(byte(data, at: offset + 1))
        guard length > 0, length <= maxTargetLength, offset + 2 + length <= data.count else { return nil }
        let start = data.index(data.startIndex, offsetBy: offset + 2)
        let end = data.index(start, offsetBy: length)
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

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        return (UInt32(byte(data, at: offset)) << 24)
            | (UInt32(byte(data, at: offset + 1)) << 16)
            | (UInt32(byte(data, at: offset + 2)) << 8)
            | UInt32(byte(data, at: offset + 3))
    }

    private static func readUInt16(_ data: Data, at offset: Int) -> Int {
        guard offset + 2 <= data.count else { return 0 }
        return (Int(byte(data, at: offset)) << 8) | Int(byte(data, at: offset + 1))
    }

    private static func byte(_ data: Data, at offset: Int) -> UInt8 {
        data[data.index(data.startIndex, offsetBy: offset)]
    }
}
