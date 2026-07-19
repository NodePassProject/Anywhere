//
//  NowhereProtocol.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import CryptoKit
import Darwin

/// Nowhere's compact application protocol. All multibyte integers use network byte order.
nonisolated enum NowhereProtocol {
    static let closeErrCodeOK: UInt64 = 0x100
    static let defaultALPN = "now/1"
    static let authFrameSize = 32
    static let flowHeaderSize = 5
    static let flowResultSize = 1
    static let udpHeaderSize = 5
    static let udpFragmentHeaderSize = 13
    static let maxUDPPacketSize = Int(UInt16.max)
    static let maxDomainLength = 253

    typealias AuthKey = Data

    enum AuthTransport: UInt8 {
        case tlsTCP = 0x01
        case quic = 0x02
    }

    enum FlowRole: UInt8 {
        case duplex = 0
        case open = 1
        case attach = 2
    }

    enum FlowKind: UInt8 {
        case tcp = 0
        case udp = 1
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

    struct FlowHeader: Equatable {
        let role: FlowRole
        let flowID: UInt32
        let kind: FlowKind
        let uplink: NowhereNetwork
        let downlink: NowhereNetwork

        var carriesTarget: Bool { role != .attach }

        func validate(on carrier: NowhereNetwork? = nil) throws {
            guard flowID != 0 else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid zero flow ID"))
            }
            switch role {
            case .duplex:
                guard uplink == downlink else {
                    throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Duplex carrier mismatch"))
                }
            case .open, .attach:
                guard uplink != downlink else {
                    throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Split carriers must differ"))
                }
            }
            if let carrier {
                let expected = role == .attach ? downlink : uplink
                guard carrier == expected else {
                    throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Flow carrier mismatch"))
                }
            }
        }
    }

    enum Target: Equatable {
        case ipv4([UInt8], UInt16)
        case ipv6([UInt8], UInt16)
        case domain(String, UInt16)

        init(host: String, port: UInt16) throws {
            guard port != 0 else { throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid zero target port")) }
            let unwrapped = host.hasPrefix("[") && host.hasSuffix("]")
                ? String(host.dropFirst().dropLast())
                : host

            var ipv4 = in_addr()
            if unwrapped.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
                let bytes = withUnsafeBytes(of: &ipv4.s_addr) { Array($0) }
                self = .ipv4(bytes, port)
                return
            }

            var ipv6 = in6_addr()
            if unwrapped.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
                let bytes = withUnsafeBytes(of: &ipv6) { Array($0.prefix(16)) }
                self = .ipv6(bytes, port)
                return
            }

            let wireHost = try Self.asciiWireHost(unwrapped)
            try Self.validateDomain(wireHost)
            self = .domain(wireHost, port)
        }

        var encodedLength: Int {
            switch self {
            case .ipv4: return 7
            case .ipv6: return 19
            case .domain(let host, _): return 4 + host.utf8.count
            }
        }

        func appendEncoded(to output: inout Data) {
            switch self {
            case .ipv4(let address, let port):
                output.append(0x01)
                output.append(contentsOf: address)
                output.appendUInt16(port)
            case .domain(let host, let port):
                output.append(0x03)
                output.append(UInt8(host.utf8.count))
                output.append(contentsOf: host.utf8)
                output.appendUInt16(port)
            case .ipv6(let address, let port):
                output.append(0x04)
                output.append(contentsOf: address)
                output.appendUInt16(port)
            }
        }

        private static func asciiWireHost(_ host: String) throws -> String {
            guard !host.isEmpty else { throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Empty target host")) }
            if host.unicodeScalars.allSatisfy(\.isASCII) { return host.lowercased() }
            var components = URLComponents()
            components.scheme = "https"
            components.host = host
            guard let converted = components.url?.host,
                  converted.unicodeScalars.allSatisfy(\.isASCII) else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Target is not valid IDNA"))
            }
            return converted.lowercased()
        }

        private static func validateDomain(_ domain: String) throws {
            let bytes = Array(domain.utf8)
            guard !bytes.isEmpty, bytes.count <= maxDomainLength else {
                throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "invalid target length (\(bytes.count))"))
            }
            for label in domain.split(separator: ".", omittingEmptySubsequences: false) {
                let scalars = label.utf8
                guard !scalars.isEmpty, scalars.count <= 63,
                      scalars.first != Character("-").asciiValue,
                      scalars.last != Character("-").asciiValue,
                      scalars.allSatisfy({ $0.isASCIIAlphaNumeric || $0 == 0x2d }) else {
                    throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid DNS target"))
                }
            }
        }
    }

    enum UDPType: UInt8, Equatable {
        case data = 0
        case fragment = 1
        case close = 2
    }

    struct UDPMessage: Sendable {
        let type: UDPType
        let flowID: UInt32
        let packetID: UInt32
        let fragmentID: UInt8
        let fragmentCount: UInt8
        let totalLength: UInt16
        let payload: Data
    }

    // MARK: - Authentication

    static func deriveAuthKey(sharedKey: String) throws -> AuthKey {
        let keyBytes = Data(sharedKey.utf8)
        guard !keyBytes.isEmpty else { throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Missing Nowhere shared key")) }
        guard keyBytes.count <= UInt8.max else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Nowhere shared key exceeds 255 bytes"))
        }
        let salt = Data(SHA256.hash(data: Data("nowhere/now/1/auth-root".utf8)))
        let authRoot = hmacSHA256(key: salt, message: keyBytes)
        var info = Data("authentication".utf8)
        info.append(0x01)
        return hmacSHA256(key: authRoot, message: info)
    }

    static func makeAuthFrame(
        authKey: AuthKey,
        transport: AuthTransport,
        exporter: Data,
        sessionID: Data
    ) throws -> Data {
        guard authKey.count == 32, exporter.count == 32, sessionID.count == 16 else {
            throw AnywhereError.proxy(.nowhere, .authenticationRejected(status: nil, detail: "Invalid authentication material"))
        }
        var message = Data(capacity: 49)
        message.append(transport.rawValue)
        message.append(exporter)
        message.append(sessionID)
        let tag = hmacSHA256(key: authKey, message: message)
        var frame = Data(capacity: authFrameSize)
        frame.append(sessionID)
        frame.append(tag.prefix(16))
        return frame
    }

    private static func hmacSHA256(key: Data, message: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
    }

    // MARK: - Flow, target, and result

    static func encodeFlowHeader(_ header: FlowHeader) throws -> Data {
        try header.validate()
        var output = Data(capacity: flowHeaderSize)
        var flags = header.role.rawValue | (header.kind.rawValue << 2)
        if header.uplink == .udp { flags |= 1 << 3 }
        if header.downlink == .udp { flags |= 1 << 4 }
        output.append(flags)
        output.appendUInt32(header.flowID)
        return output
    }

    static func decodeFlowHeader(_ data: Data) -> FlowHeader? {
        guard data.count == flowHeaderSize else { return nil }
        let flags = data.byte(at: 0)
        guard flags & 0xe0 == 0,
              let role = FlowRole(rawValue: flags & 0x03) else { return nil }
        let header = FlowHeader(
            role: role,
            flowID: data.uint32(at: 1),
            kind: (flags & 0x04) == 0 ? .tcp : .udp,
            uplink: (flags & 0x08) == 0 ? .tcp : .udp,
            downlink: (flags & 0x10) == 0 ? .tcp : .udp
        )
        return (try? header.validate()) == nil ? nil : header
    }

    static func encodeFlowRequest(
        header: FlowHeader,
        target: Target?,
        initialData: Data? = nil
    ) throws -> Data {
        try header.validate()
        guard header.carriesTarget == (target != nil) else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Flow target does not match role"))
        }
        let initialCount = initialData?.count ?? 0
        var output = Data(capacity: flowHeaderSize + (target?.encodedLength ?? 0) + initialCount)
        output.append(try encodeFlowHeader(header))
        target?.appendEncoded(to: &output)
        if let initialData, !initialData.isEmpty { output.append(initialData) }
        return output
    }

    static func encodeFlowResult(_ result: FlowResult) -> Data {
        switch result {
        case .ready: return Data([0])
        case .reject(let code): return Data([code.rawValue])
        }
    }

    static func decodeFlowResult(_ data: Data, offset: Int = 0) -> FlowResult? {
        guard offset >= 0, offset < data.count else { return nil }
        let value = data.byte(at: offset)
        if value == 0 { return .ready }
        guard let code = FlowRejectCode(rawValue: value) else { return nil }
        return .reject(code)
    }

    // MARK: - QUIC DATAGRAM

    static func encodeUDPControl(type: UDPType, flowID: UInt32) throws -> Data {
        guard type == .close, flowID != 0 else {
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid UDP CLOSE frame"))
        }
        var output = Data(capacity: udpHeaderSize)
        output.append(type.rawValue)
        output.appendUInt32(flowID)
        return output
    }

    static func encodeUDPDataFragments(
        flowID: UInt32,
        packetID: UInt32,
        payload: Data,
        maxDatagramSize: Int
    ) throws -> [Data] {
        guard flowID != 0 else { throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid flow ID")) }
        guard payload.count <= maxUDPPacketSize else { throw AnywhereError.proxy(.nowhere, .packetTooLarge) }
        guard maxDatagramSize >= udpHeaderSize else {
            throw AnywhereError.proxy(.nowhere, .datagramTooLarge(maxFrame: maxDatagramSize, headerSize: udpHeaderSize))
        }
        if payload.count <= maxDatagramSize - udpHeaderSize {
            var frame = Data(capacity: udpHeaderSize + payload.count)
            frame.append(UDPType.data.rawValue)
            frame.appendUInt32(flowID)
            frame.append(payload)
            return [frame]
        }

        guard packetID != 0, maxDatagramSize > udpFragmentHeaderSize else {
            throw AnywhereError.proxy(.nowhere, .datagramTooLarge(maxFrame: maxDatagramSize, headerSize: udpFragmentHeaderSize))
        }
        let payloadCapacity = maxDatagramSize - udpFragmentHeaderSize
        let count = (payload.count + payloadCapacity - 1) / payloadCapacity
        guard (2...Int(UInt8.max)).contains(count) else { throw AnywhereError.proxy(.nowhere, .packetTooLarge) }

        var frames: [Data] = []
        frames.reserveCapacity(count)
        for index in 0..<count {
            let start = index * payloadCapacity
            let end = min(payload.count, start + payloadCapacity)
            var frame = Data(capacity: udpFragmentHeaderSize + end - start)
            frame.append(UDPType.fragment.rawValue)
            frame.appendUInt32(flowID)
            frame.appendUInt32(packetID)
            frame.append(UInt8(index))
            frame.append(UInt8(count))
            frame.appendUInt16(UInt16(payload.count))
            let startIndex = payload.index(payload.startIndex, offsetBy: start)
            let endIndex = payload.index(payload.startIndex, offsetBy: end)
            frame.append(payload[startIndex..<endIndex])
            frames.append(frame)
        }
        return frames
    }

    static func decodeUDPDatagram(_ data: Data) -> UDPMessage? {
        guard let (type, flowID) = decodeUDPEnvelope(data) else { return nil }
        switch type {
        case .data:
            let payload = Data(data.dropFirst(udpHeaderSize))
            guard payload.count <= maxUDPPacketSize else { return nil }
            return UDPMessage(type: .data, flowID: flowID, packetID: 0,
                              fragmentID: 0, fragmentCount: 0,
                              totalLength: UInt16(payload.count), payload: payload)
        case .fragment:
            guard data.count > udpFragmentHeaderSize else { return nil }
            let packetID = data.uint32(at: 5)
            let index = data.byte(at: 9)
            let count = data.byte(at: 10)
            let total = data.uint16(at: 11)
            let payload = Data(data.dropFirst(udpFragmentHeaderSize))
            guard packetID != 0, count >= 2, index < count, total != 0,
                  Int(total) >= Int(count), !payload.isEmpty,
                  payload.count + Int(count) - 1 <= Int(total) else { return nil }
            return UDPMessage(type: .fragment, flowID: flowID, packetID: packetID,
                              fragmentID: index, fragmentCount: count,
                              totalLength: total, payload: payload)
        case .close:
            guard data.count == udpHeaderSize else { return nil }
            return UDPMessage(type: .close, flowID: flowID, packetID: 0,
                              fragmentID: 0, fragmentCount: 0,
                              totalLength: 0, payload: Data())
        }
    }

    /// Validates only the common header so unknown or pre-READY routes can be dropped
    /// before the callback-backed payload is copied.
    static func decodeUDPEnvelope(_ data: Data) -> (type: UDPType, flowID: UInt32)? {
        guard data.count >= udpHeaderSize else { return nil }
        let flags = data.byte(at: 0)
        guard flags & 0xfc == 0,
              let type = UDPType(rawValue: flags & 0x03) else { return nil }
        let flowID = data.uint32(at: 1)
        guard flowID != 0 else { return nil }
        return (type, flowID)
    }

    // MARK: - UDP over stream

    static func encodeUDPStreamPacket(_ payload: Data) throws -> Data {
        guard payload.count <= maxUDPPacketSize else { throw AnywhereError.proxy(.nowhere, .packetTooLarge) }
        var output = Data(capacity: 2 + payload.count)
        output.appendUInt16(UInt16(payload.count))
        output.append(payload)
        return output
    }

    static func decodeUDPStreamPacket(_ data: Data, offset: Int = 0) -> (payload: Data, consumed: Int)? {
        guard offset >= 0, offset + 2 <= data.count else { return nil }
        let length = Int(data.uint16(at: offset))
        guard offset + 2 + length <= data.count else { return nil }
        return (Data(data[(offset + 2)..<(offset + 2 + length)]), 2 + length)
    }
}

nonisolated private extension UInt8 {
    var isASCIIAlphaNumeric: Bool {
        (0x30...0x39).contains(self) || (0x41...0x5a).contains(self) || (0x61...0x7a).contains(self)
    }
}

nonisolated private extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8(value >> 8))
        append(UInt8(value & 0xff))
    }

    mutating func appendUInt32(_ value: UInt32) {
        append(UInt8(value >> 24))
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }

    func byte(at offset: Int) -> UInt8 {
        self[index(startIndex, offsetBy: offset)]
    }

    func uint16(at offset: Int) -> UInt16 {
        (UInt16(byte(at: offset)) << 8) | UInt16(byte(at: offset + 1))
    }

    func uint32(at offset: Int) -> UInt32 {
        (UInt32(byte(at: offset)) << 24)
            | (UInt32(byte(at: offset + 1)) << 16)
            | (UInt32(byte(at: offset + 2)) << 8)
            | UInt32(byte(at: offset + 3))
    }
}
