//
//  IPv6Header.swift
//  AnywhereIP
//
//  Created by NodePassProject on 9/20/26.
//

struct IPv6Header: Hashable, Sendable {
    static let length = 40

    var trafficClass: UInt8
    var flowLabel: UInt32
    var payloadLength: Int
    var nextHeader: UInt8
    var hopLimit: UInt8
    var source: IPAddress.V6
    var destination: IPAddress.V6
    
    var totalLength: Int { Self.length + payloadLength }

    init(
        payloadLength: Int,
        nextHeader: UInt8,
        hopLimit: UInt8,
        source: IPAddress.V6,
        destination: IPAddress.V6,
        trafficClass: UInt8 = 0,
        flowLabel: UInt32 = 0
    ) {
        self.trafficClass = trafficClass
        self.flowLabel = flowLabel
        self.payloadLength = payloadLength
        self.nextHeader = nextHeader
        self.hopLimit = hopLimit
        self.source = source
        self.destination = destination
    }

    init?(parsing bytes: UnsafeRawBufferPointer) {
        guard bytes.count >= Self.length, let base = bytes.baseAddress else { return nil }
        let first = UInt32(bigEndian: base.loadUnaligned(as: UInt32.self))
        guard first >> 28 == 6 else { return nil }
        let payloadLength = Int(UInt16(bigEndian: base.loadUnaligned(fromByteOffset: 4, as: UInt16.self)))
        guard payloadLength <= bytes.count - Self.length else { return nil }
        trafficClass = UInt8(truncatingIfNeeded: first >> 20)
        flowLabel = first & 0xF_FFFF
        self.payloadLength = payloadLength
        nextHeader = base.load(fromByteOffset: 6, as: UInt8.self)
        hopLimit = base.load(fromByteOffset: 7, as: UInt8.self)
        source = IPAddress.V6(bytes: base + 8)
        destination = IPAddress.V6(bytes: base + 24)
    }

    func write(to bytes: UnsafeMutableRawBufferPointer) {
        precondition(bytes.count >= Self.length)
        let base = bytes.baseAddress!
        let first = UInt32(6) << 28 | UInt32(trafficClass) << 20 | flowLabel & 0xF_FFFF
        base.storeBytes(of: first.bigEndian, as: UInt32.self)
        base.storeBytes(of: UInt16(payloadLength).bigEndian, toByteOffset: 4, as: UInt16.self)
        base.storeBytes(of: nextHeader, toByteOffset: 6, as: UInt8.self)
        base.storeBytes(of: hopLimit, toByteOffset: 7, as: UInt8.self)
        source.write(to: base + 8)
        destination.write(to: base + 24)
    }
}

extension IPv6Header {
    struct IPv6Payload: Hashable, Sendable {
        public var nextHeader: UInt8
        public var offset: Int
        public var nextHeaderFieldOffset: Int
    }

    enum IPv6PayloadLocation: Hashable, Sendable {
        case found(IPv6Payload)
        case dropped
        case parameterProblem(code: UInt8, pointer: UInt32)
    }
    
    func locatePayload(in packet: UnsafeRawBufferPointer) -> IPv6PayloadLocation {
        var nextHeader = self.nextHeader
        var nextHeaderFieldOffset = 6
        var offset = Self.length
        while true {
            switch nextHeader {
            case 0, 60:
                guard packet.count - offset >= 8 else { return .dropped }
                let headerLength = 8 * (1 + Int(packet[offset + 1]))
                guard headerLength <= packet.count - offset else { return .dropped }
                let end = offset + headerLength
                var option = offset + 2
                while option < end {
                    let type = packet[option]
                    if type == 0 {
                        option += 1
                        continue
                    }
                    guard option + 1 < end else { return .dropped }
                    switch type {
                    case 1, 5, 194:
                        break
                    case 201 where nextHeader == 60:
                        break
                    default:
                        switch type >> 6 {
                        case 0: break
                        case 1: return .dropped
                        default: return .parameterProblem(code: 2, pointer: UInt32(option))
                        }
                    }
                    option += 2 + Int(packet[option + 1])
                }
                nextHeader = packet[offset]
                nextHeaderFieldOffset = offset
                offset = end
            case 43:
                guard packet.count - offset >= 8 else { return .dropped }
                let headerLength = 8 * (1 + Int(packet[offset + 1]))
                guard headerLength <= packet.count - offset else { return .dropped }
                if packet[offset + 3] != 0 {
                    if packet[offset + 1] & 1 != 0 {
                        return .parameterProblem(code: 0, pointer: UInt32(offset + 1))
                    }
                    switch packet[offset + 2] {
                    case 2, 3: break
                    default: return .parameterProblem(code: 0, pointer: UInt32(offset + 2))
                    }
                }
                nextHeader = packet[offset]
                nextHeaderFieldOffset = offset
                offset += headerLength
            case 44:
                guard packet.count - offset >= 8 else { return .dropped }
                let fragmentField = UInt16(bigEndian: packet.loadUnaligned(fromByteOffset: offset + 2, as: UInt16.self))
                if fragmentField & 1 != 0 && payloadLength & 7 != 0 {
                    return .parameterProblem(code: 0, pointer: 4)
                }
                guard fragmentField & 0xFFF9 == 0 else { return .dropped }
                nextHeader = packet[offset]
                nextHeaderFieldOffset = offset
                offset += 8
            default:
                return .found(IPv6Payload(nextHeader: nextHeader, offset: offset, nextHeaderFieldOffset: nextHeaderFieldOffset))
            }
            if nextHeader == 0 {
                return .parameterProblem(code: 1, pointer: UInt32(nextHeaderFieldOffset))
            }
        }
    }
}
