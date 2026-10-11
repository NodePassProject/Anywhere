//
//  Frame.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

struct FrameType: RawRepresentable, Hashable, Sendable {
    var rawValue: UInt64

    init(rawValue: UInt64) {
        self.rawValue = rawValue
    }
}

extension FrameType {
    static let padding = FrameType(rawValue: 0x00)
    static let ping = FrameType(rawValue: 0x01)
    static let ack = FrameType(rawValue: 0x02)
    static let ackECN = FrameType(rawValue: 0x03)
    static let resetStream = FrameType(rawValue: 0x04)
    static let stopSending = FrameType(rawValue: 0x05)
    static let crypto = FrameType(rawValue: 0x06)
    static let newToken = FrameType(rawValue: 0x07)
    static let stream = FrameType(rawValue: 0x08)
    static let maxData = FrameType(rawValue: 0x10)
    static let maxStreamData = FrameType(rawValue: 0x11)
    static let maxStreamsBidirectional = FrameType(rawValue: 0x12)
    static let maxStreamsUnidirectional = FrameType(rawValue: 0x13)
    static let dataBlocked = FrameType(rawValue: 0x14)
    static let streamDataBlocked = FrameType(rawValue: 0x15)
    static let streamsBlockedBidirectional = FrameType(rawValue: 0x16)
    static let streamsBlockedUnidirectional = FrameType(rawValue: 0x17)
    static let newConnectionID = FrameType(rawValue: 0x18)
    static let retireConnectionID = FrameType(rawValue: 0x19)
    static let pathChallenge = FrameType(rawValue: 0x1A)
    static let pathResponse = FrameType(rawValue: 0x1B)
    static let connectionClose = FrameType(rawValue: 0x1C)
    static let applicationClose = FrameType(rawValue: 0x1D)
    static let handshakeDone = FrameType(rawValue: 0x1E)
    static let datagram = FrameType(rawValue: 0x30)
    static let datagramWithLength = FrameType(rawValue: 0x31)

    static let streamFINBit: UInt64 = 0x01
    static let streamLengthBit: UInt64 = 0x02
    static let streamOffsetBit: UInt64 = 0x04

    var isStream: Bool { self.rawValue & ~0x07 == FrameType.stream.rawValue }
}

extension FrameType: CustomStringConvertible {
    var description: String {
        switch self {
        case .padding:
            return "PADDING"
        case .ping:
            return "PING"
        case .ack:
            return "ACK"
        case .ackECN:
            return "ACK_ECN"
        case .resetStream:
            return "RESET_STREAM"
        case .stopSending:
            return "STOP_SENDING"
        case .crypto:
            return "CRYPTO"
        case .newToken:
            return "NEW_TOKEN"
        case .maxData:
            return "MAX_DATA"
        case .maxStreamData:
            return "MAX_STREAM_DATA"
        case .maxStreamsBidirectional:
            return "MAX_STREAMS_BIDI"
        case .maxStreamsUnidirectional:
            return "MAX_STREAMS_UNI"
        case .dataBlocked:
            return "DATA_BLOCKED"
        case .streamDataBlocked:
            return "STREAM_DATA_BLOCKED"
        case .streamsBlockedBidirectional:
            return "STREAMS_BLOCKED_BIDI"
        case .streamsBlockedUnidirectional:
            return "STREAMS_BLOCKED_UNI"
        case .newConnectionID:
            return "NEW_CONNECTION_ID"
        case .retireConnectionID:
            return "RETIRE_CONNECTION_ID"
        case .pathChallenge:
            return "PATH_CHALLENGE"
        case .pathResponse:
            return "PATH_RESPONSE"
        case .connectionClose:
            return "CONNECTION_CLOSE"
        case .applicationClose:
            return "CONNECTION_CLOSE_APP"
        case .handshakeDone:
            return "HANDSHAKE_DONE"
        case .datagram, .datagramWithLength:
            return "DATAGRAM"
        default:
            if self.isStream {
                return "STREAM"
            }
            return "FrameType(rawValue: 0x\(String(self.rawValue, radix: 16, uppercase: true)))"
        }
    }
}

extension InputBuffer {
    mutating func readFrameType() throws(DecodeError) -> FrameType {
        return FrameType(rawValue: try self.readVarInt())
    }
}

extension OutputBuffer {
    @discardableResult
    mutating func writeFrameType(_ type: FrameType) -> Bool {
        return self.writeVarInt(type.rawValue)
    }
}

struct ACKFrame {
    struct ECNCounts: Hashable {
        var ect0: UInt64
        var ect1: UInt64
        var ce: UInt64
    }

    static let maxRanges = 32

    var largestAcknowledged: UInt64
    var ackDelay: UInt64
    var firstRange: UInt64
    var additionalRanges: [(gap: UInt64, length: UInt64)]
    var ecnCounts: ECNCounts?

    var smallestAcknowledged: UInt64 {
        var smallest = self.largestAcknowledged - self.firstRange
        for range in self.additionalRanges {
            smallest = smallest - range.gap - 2 - range.length
        }
        return smallest
    }

    func forEachRange<E: Error>(_ body: (ClosedRange<UInt64>) throws(E) -> Void) throws(E) {
        var largest = self.largestAcknowledged
        var smallest = largest - self.firstRange
        try body(smallest...largest)
        for range in self.additionalRanges {
            largest = smallest - range.gap - 2
            smallest = largest - range.length
            try body(smallest...largest)
        }
    }

    var ranges: [ClosedRange<UInt64>] {
        var result: [ClosedRange<UInt64>] = []
        result.reserveCapacity(self.additionalRanges.count + 1)
        self.forEachRange { result.append($0) }
        return result
    }

    static func validate(largest: UInt64, firstRange: UInt64, additional: [(gap: UInt64, length: UInt64)]) -> Bool {
        guard firstRange <= largest else {
            return false
        }
        var smallest = largest - firstRange
        for range in additional {
            guard range.gap + 2 <= smallest else {
                return false
            }
            let largest = smallest - range.gap - 2
            guard range.length <= largest else {
                return false
            }
            smallest = largest - range.length
        }
        return true
    }
}

struct ConnectionCloseFrame {
    var isApplication: Bool
    var errorCode: UInt64
    var frameType: FrameType
    var reason: UnsafeRawBufferPointer
}

enum Frame {
    case padding(Int)
    case ping
    case ack(ACKFrame)
    case resetStream(streamID: UInt64, errorCode: UInt64, finalSize: UInt64)
    case stopSending(streamID: UInt64, errorCode: UInt64)
    case crypto(offset: UInt64, data: UnsafeRawBufferPointer)
    case newToken(UnsafeRawBufferPointer)
    case stream(streamID: UInt64, offset: UInt64, data: UnsafeRawBufferPointer, fin: Bool)
    case maxData(UInt64)
    case maxStreamData(streamID: UInt64, maximum: UInt64)
    case maxStreams(bidirectional: Bool, maximum: UInt64)
    case dataBlocked(UInt64)
    case streamDataBlocked(streamID: UInt64, limit: UInt64)
    case streamsBlocked(bidirectional: Bool, limit: UInt64)
    case newConnectionID(sequence: UInt64, retirePriorTo: UInt64, id: QUICConnectionID, token: QUICStatelessResetToken)
    case retireConnectionID(sequence: UInt64)
    case pathChallenge(UInt64)
    case pathResponse(UInt64)
    case connectionClose(ConnectionCloseFrame)
    case handshakeDone
    case datagram(data: UnsafeRawBufferPointer, frameLength: Int, hasLength: Bool)

    var type: FrameType {
        switch self {
        case .padding:
            return .padding
        case .ping:
            return .ping
        case .ack(let ack):
            return ack.ecnCounts == nil ? .ack : .ackECN
        case .resetStream:
            return .resetStream
        case .stopSending:
            return .stopSending
        case .crypto:
            return .crypto
        case .newToken:
            return .newToken
        case .stream:
            return .stream
        case .maxData:
            return .maxData
        case .maxStreamData:
            return .maxStreamData
        case .maxStreams(let bidirectional, _):
            return bidirectional ? .maxStreamsBidirectional : .maxStreamsUnidirectional
        case .dataBlocked:
            return .dataBlocked
        case .streamDataBlocked:
            return .streamDataBlocked
        case .streamsBlocked(let bidirectional, _):
            return bidirectional ? .streamsBlockedBidirectional : .streamsBlockedUnidirectional
        case .newConnectionID:
            return .newConnectionID
        case .retireConnectionID:
            return .retireConnectionID
        case .pathChallenge:
            return .pathChallenge
        case .pathResponse:
            return .pathResponse
        case .connectionClose(let close):
            return close.isApplication ? .applicationClose : .connectionClose
        case .handshakeDone:
            return .handshakeDone
        case .datagram(_, _, let hasLength):
            return hasLength ? .datagramWithLength : .datagram
        }
    }

    var isACKEliciting: Bool {
        switch self {
        case .padding, .ack, .connectionClose:
            return false
        default:
            return true
        }
    }

    var isProbing: Bool {
        switch self {
        case .padding, .newConnectionID, .pathChallenge, .pathResponse:
            return true
        default:
            return false
        }
    }

    var isAllowedInHandshakeLevels: Bool {
        switch self {
        case .padding, .ping, .ack, .crypto:
            return true
        case .connectionClose(let close):
            return !close.isApplication
        default:
            return false
        }
    }
}

extension InputBuffer {
    mutating func readFrame() throws(TransportError) -> Frame {
        let typeStart = self.position
        let type: FrameType
        do {
            type = try self.readFrameType()
        } catch {
            throw TransportError(.frameEncodingError, reason: "truncated frame type")
        }
        do {
            switch type {
            case .padding:
                var count = 1
                while self.byteCount > 0, self.bytes[0] == 0 {
                    _ = try self.readInteger(as: UInt8.self)
                    count += 1
                }
                return .padding(count)
            case .ping:
                return .ping
            case .ack, .ackECN:
                let largest = try self.readVarInt()
                let delay = try self.readVarInt()
                let rangeCount = try self.readVarInt()
                let firstRange = try self.readVarInt()
                guard rangeCount <= UInt64(self.byteCount) else {
                    throw DecodeError.malformed
                }
                var additional: [(gap: UInt64, length: UInt64)] = []
                additional.reserveCapacity(Int(rangeCount))
                for _ in 0..<rangeCount {
                    let gap = try self.readVarInt()
                    let length = try self.readVarInt()
                    additional.append((gap, length))
                }
                var ecn: ACKFrame.ECNCounts?
                if type == .ackECN {
                    ecn = ACKFrame.ECNCounts(
                        ect0: try self.readVarInt(),
                        ect1: try self.readVarInt(),
                        ce: try self.readVarInt()
                    )
                }
                guard ACKFrame.validate(largest: largest, firstRange: firstRange, additional: additional) else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "invalid ACK ranges")
                }
                return .ack(ACKFrame(
                    largestAcknowledged: largest,
                    ackDelay: delay,
                    firstRange: firstRange,
                    additionalRanges: additional,
                    ecnCounts: ecn
                ))
            case .resetStream:
                let streamID = try self.readVarInt()
                let errorCode = try self.readVarInt()
                let finalSize = try self.readVarInt()
                return .resetStream(streamID: streamID, errorCode: errorCode, finalSize: finalSize)
            case .stopSending:
                return .stopSending(streamID: try self.readVarInt(), errorCode: try self.readVarInt())
            case .crypto:
                let offset = try self.readVarInt()
                let length = try self.readVarInt()
                guard length <= UInt64(self.byteCount), offset + length <= VarInt.max else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "invalid CRYPTO length")
                }
                return .crypto(offset: offset, data: try self.read(length: Int(length)))
            case .newToken:
                let length = try self.readVarInt()
                guard length > 0, length <= UInt64(self.byteCount) else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "invalid NEW_TOKEN length")
                }
                return .newToken(try self.read(length: Int(length)))
            case _ where type.isStream:
                let streamID = try self.readVarInt()
                var offset: UInt64 = 0
                if type.rawValue & FrameType.streamOffsetBit != 0 {
                    offset = try self.readVarInt()
                }
                let length: UInt64
                if type.rawValue & FrameType.streamLengthBit != 0 {
                    length = try self.readVarInt()
                    guard length <= UInt64(self.byteCount) else {
                        throw TransportError(.frameEncodingError, frameType: type, reason: "invalid STREAM length")
                    }
                } else {
                    length = UInt64(self.byteCount)
                }
                guard offset + length <= VarInt.max else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "STREAM offset overflow")
                }
                let fin = type.rawValue & FrameType.streamFINBit != 0
                return .stream(streamID: streamID, offset: offset, data: try self.read(length: Int(length)), fin: fin)
            case .maxData:
                return .maxData(try self.readVarInt())
            case .maxStreamData:
                return .maxStreamData(streamID: try self.readVarInt(), maximum: try self.readVarInt())
            case .maxStreamsBidirectional, .maxStreamsUnidirectional:
                let maximum = try self.readVarInt()
                guard maximum <= StreamLimits.maxStreamCount else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "MAX_STREAMS exceeds 2^60")
                }
                return .maxStreams(bidirectional: type == .maxStreamsBidirectional, maximum: maximum)
            case .dataBlocked:
                return .dataBlocked(try self.readVarInt())
            case .streamDataBlocked:
                return .streamDataBlocked(streamID: try self.readVarInt(), limit: try self.readVarInt())
            case .streamsBlockedBidirectional, .streamsBlockedUnidirectional:
                let limit = try self.readVarInt()
                guard limit <= StreamLimits.maxStreamCount else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "STREAMS_BLOCKED exceeds 2^60")
                }
                return .streamsBlocked(bidirectional: type == .streamsBlockedBidirectional, limit: limit)
            case .newConnectionID:
                let sequence = try self.readVarInt()
                let retirePriorTo = try self.readVarInt()
                let length = Int(try self.readInteger(as: UInt8.self))
                guard length >= 1, length <= QUICConnectionID.maxLength, retirePriorTo <= sequence else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "invalid NEW_CONNECTION_ID")
                }
                let id = QUICConnectionID(try self.read(length: length))
                let token = QUICStatelessResetToken(try self.read(length: QUICStatelessResetToken.length))
                return .newConnectionID(sequence: sequence, retirePriorTo: retirePriorTo, id: id, token: token)
            case .retireConnectionID:
                return .retireConnectionID(sequence: try self.readVarInt())
            case .pathChallenge:
                return .pathChallenge(try self.readInteger(as: UInt64.self))
            case .pathResponse:
                return .pathResponse(try self.readInteger(as: UInt64.self))
            case .connectionClose, .applicationClose:
                let errorCode = try self.readVarInt()
                var frameType = FrameType.padding
                if type == .connectionClose {
                    frameType = try self.readFrameType()
                }
                let length = try self.readVarInt()
                guard length <= UInt64(self.byteCount) else {
                    throw TransportError(
                        .frameEncodingError,
                        frameType: type,
                        reason: "invalid CONNECTION_CLOSE reason length"
                    )
                }
                return .connectionClose(ConnectionCloseFrame(
                    isApplication: type == .applicationClose,
                    errorCode: errorCode,
                    frameType: frameType,
                    reason: try self.read(length: Int(length))
                ))
            case .datagram, .datagramWithLength:
                let hasLength = type == .datagramWithLength
                let length = hasLength ? try self.readVarInt() : UInt64(self.byteCount)
                guard length <= UInt64(self.byteCount) else {
                    throw TransportError(.frameEncodingError, frameType: type, reason: "invalid DATAGRAM length")
                }
                let data = try self.read(length: Int(length))
                return .datagram(data: data, frameLength: self.position - typeStart, hasLength: hasLength)
            case .handshakeDone:
                return .handshakeDone
            default:
                throw TransportError(.frameEncodingError, frameType: type, reason: "unknown frame type")
            }
        } catch let error as TransportError {
            self.position = typeStart
            throw error
        } catch {
            self.position = typeStart
            throw TransportError(.frameEncodingError, frameType: type, reason: "truncated frame")
        }
    }
}

enum StreamLimits {
    static let maxStreamCount: UInt64 = 1 << 60
}
