//
//  QUICTransportParameters.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public struct QUICTransportParameters: Hashable, Sendable {
    public static let defaultMaxUDPPayloadSize: UInt64 = 65527
    public static let defaultACKDelayExponent: UInt64 = 3
    public static let defaultMaxACKDelay: Duration = .milliseconds(25)
    public static let defaultActiveConnectionIDLimit: UInt64 = 2
    public static let minimumMaxUDPPayloadSize: UInt64 = 1200
    public static let maximumACKDelayExponent: UInt64 = 20
    public static let maximumMaxACKDelay: Duration = .milliseconds(1 << 14)

    public struct PreferredAddress: Sendable {
        public var ipv4: (address: UInt32, port: UInt16)?
        public var ipv6: (address: [UInt8], port: UInt16)?
        public var connectionID: QUICConnectionID
        public var statelessResetToken: QUICStatelessResetToken

        public init(
            ipv4: (address: UInt32, port: UInt16)?,
            ipv6: (address: [UInt8], port: UInt16)?,
            connectionID: QUICConnectionID,
            statelessResetToken: QUICStatelessResetToken
        ) {
            self.ipv4 = ipv4
            self.ipv6 = ipv6
            self.connectionID = connectionID
            self.statelessResetToken = statelessResetToken
        }
    }

    public enum Perspective: Sendable {
        case client
        case server
    }

    public var originalDestinationConnectionID: QUICConnectionID?
    public var maxIdleTimeout: Duration
    public var statelessResetToken: QUICStatelessResetToken?
    public var maxUDPPayloadSize: UInt64
    public var initialMaxData: UInt64
    public var initialMaxStreamDataBidirectionalLocal: UInt64
    public var initialMaxStreamDataBidirectionalRemote: UInt64
    public var initialMaxStreamDataUnidirectional: UInt64
    public var initialMaxStreamsBidirectional: UInt64
    public var initialMaxStreamsUnidirectional: UInt64
    public var ackDelayExponent: UInt64
    public var maxACKDelay: Duration
    public var isActiveMigrationDisabled: Bool
    public var preferredAddress: PreferredAddress?
    public var activeConnectionIDLimit: UInt64
    public var initialSourceConnectionID: QUICConnectionID?
    public var retrySourceConnectionID: QUICConnectionID?
    public var maxDatagramFrameSize: UInt64

    public init(
        originalDestinationConnectionID: QUICConnectionID? = nil,
        maxIdleTimeout: Duration = .zero,
        statelessResetToken: QUICStatelessResetToken? = nil,
        maxUDPPayloadSize: UInt64 = QUICTransportParameters.defaultMaxUDPPayloadSize,
        initialMaxData: UInt64 = 0,
        initialMaxStreamDataBidirectionalLocal: UInt64 = 0,
        initialMaxStreamDataBidirectionalRemote: UInt64 = 0,
        initialMaxStreamDataUnidirectional: UInt64 = 0,
        initialMaxStreamsBidirectional: UInt64 = 0,
        initialMaxStreamsUnidirectional: UInt64 = 0,
        ackDelayExponent: UInt64 = QUICTransportParameters.defaultACKDelayExponent,
        maxACKDelay: Duration = QUICTransportParameters.defaultMaxACKDelay,
        isActiveMigrationDisabled: Bool = false,
        preferredAddress: PreferredAddress? = nil,
        activeConnectionIDLimit: UInt64 = QUICTransportParameters.defaultActiveConnectionIDLimit,
        initialSourceConnectionID: QUICConnectionID? = nil,
        retrySourceConnectionID: QUICConnectionID? = nil,
        maxDatagramFrameSize: UInt64 = 0
    ) {
        self.originalDestinationConnectionID = originalDestinationConnectionID
        self.maxIdleTimeout = maxIdleTimeout
        self.statelessResetToken = statelessResetToken
        self.maxUDPPayloadSize = maxUDPPayloadSize
        self.initialMaxData = initialMaxData
        self.initialMaxStreamDataBidirectionalLocal = initialMaxStreamDataBidirectionalLocal
        self.initialMaxStreamDataBidirectionalRemote = initialMaxStreamDataBidirectionalRemote
        self.initialMaxStreamDataUnidirectional = initialMaxStreamDataUnidirectional
        self.initialMaxStreamsBidirectional = initialMaxStreamsBidirectional
        self.initialMaxStreamsUnidirectional = initialMaxStreamsUnidirectional
        self.ackDelayExponent = ackDelayExponent
        self.maxACKDelay = maxACKDelay
        self.isActiveMigrationDisabled = isActiveMigrationDisabled
        self.preferredAddress = preferredAddress
        self.activeConnectionIDLimit = activeConnectionIDLimit
        self.initialSourceConnectionID = initialSourceConnectionID
        self.retrySourceConnectionID = retrySourceConnectionID
        self.maxDatagramFrameSize = maxDatagramFrameSize
    }

    public func encoded(from perspective: Perspective) -> [UInt8] {
        var buffer = ByteBuffer(capacity: 128)
        buffer.writeTransportParameters(self, from: perspective)
        return buffer.readableBytesView
    }

    public static func decode(
        _ bytes: [UInt8],
        from perspective: Perspective
    ) throws(QUICTransportParameterError) -> QUICTransportParameters {
        return try bytes.withUnsafeBufferPointer { (pointer) throws(QUICTransportParameterError) in
            var buffer = InputBuffer(storage: UnsafeRawBufferPointer(pointer))
            return try buffer.readTransportParameters(from: perspective)
        }
    }
}

extension QUICTransportParameters.PreferredAddress: Hashable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.ipv4?.address == rhs.ipv4?.address
            && lhs.ipv4?.port == rhs.ipv4?.port
            && lhs.ipv6?.address == rhs.ipv6?.address
            && lhs.ipv6?.port == rhs.ipv6?.port
            && lhs.connectionID == rhs.connectionID
            && lhs.statelessResetToken == rhs.statelessResetToken
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.ipv4?.address)
        hasher.combine(self.ipv4?.port)
        hasher.combine(self.ipv6?.address)
        hasher.combine(self.ipv6?.port)
        hasher.combine(self.connectionID)
        hasher.combine(self.statelessResetToken)
    }
}

public struct QUICTransportParameterError: Hashable, Error, Sendable {
    public var reason: String
    public var id: UInt64?

    public init(reason: String, id: UInt64? = nil) {
        self.reason = reason
        self.id = id
    }
}

struct TransportParameterID: RawRepresentable, Sendable {
    var rawValue: UInt64

    init(rawValue: UInt64) {
        self.rawValue = rawValue
    }
}

extension TransportParameterID: Hashable {
    static let originalDestinationConnectionID = TransportParameterID(rawValue: 0x00)
    static let maxIdleTimeout = TransportParameterID(rawValue: 0x01)
    static let statelessResetToken = TransportParameterID(rawValue: 0x02)
    static let maxUDPPayloadSize = TransportParameterID(rawValue: 0x03)
    static let initialMaxData = TransportParameterID(rawValue: 0x04)
    static let initialMaxStreamDataBidirectionalLocal = TransportParameterID(rawValue: 0x05)
    static let initialMaxStreamDataBidirectionalRemote = TransportParameterID(rawValue: 0x06)
    static let initialMaxStreamDataUnidirectional = TransportParameterID(rawValue: 0x07)
    static let initialMaxStreamsBidirectional = TransportParameterID(rawValue: 0x08)
    static let initialMaxStreamsUnidirectional = TransportParameterID(rawValue: 0x09)
    static let ackDelayExponent = TransportParameterID(rawValue: 0x0A)
    static let maxACKDelay = TransportParameterID(rawValue: 0x0B)
    static let disableActiveMigration = TransportParameterID(rawValue: 0x0C)
    static let preferredAddress = TransportParameterID(rawValue: 0x0D)
    static let activeConnectionIDLimit = TransportParameterID(rawValue: 0x0E)
    static let initialSourceConnectionID = TransportParameterID(rawValue: 0x0F)
    static let retrySourceConnectionID = TransportParameterID(rawValue: 0x10)
    static let maxDatagramFrameSize = TransportParameterID(rawValue: 0x20)

    var isReservedForGreasing: Bool {
        return self.rawValue >= 27 && (self.rawValue - 27) % 31 == 0
    }
}

extension TransportParameterID: CustomStringConvertible {
    var description: String {
        switch self {
        case .originalDestinationConnectionID:
            return "original_destination_connection_id"
        case .maxIdleTimeout:
            return "max_idle_timeout"
        case .statelessResetToken:
            return "stateless_reset_token"
        case .maxUDPPayloadSize:
            return "max_udp_payload_size"
        case .initialMaxData:
            return "initial_max_data"
        case .initialMaxStreamDataBidirectionalLocal:
            return "initial_max_stream_data_bidi_local"
        case .initialMaxStreamDataBidirectionalRemote:
            return "initial_max_stream_data_bidi_remote"
        case .initialMaxStreamDataUnidirectional:
            return "initial_max_stream_data_uni"
        case .initialMaxStreamsBidirectional:
            return "initial_max_streams_bidi"
        case .initialMaxStreamsUnidirectional:
            return "initial_max_streams_uni"
        case .ackDelayExponent:
            return "ack_delay_exponent"
        case .maxACKDelay:
            return "max_ack_delay"
        case .disableActiveMigration:
            return "disable_active_migration"
        case .preferredAddress:
            return "preferred_address"
        case .activeConnectionIDLimit:
            return "active_connection_id_limit"
        case .initialSourceConnectionID:
            return "initial_source_connection_id"
        case .retrySourceConnectionID:
            return "retry_source_connection_id"
        case .maxDatagramFrameSize:
            return "max_datagram_frame_size"
        default:
            return "TransportParameterID(rawValue: 0x\(String(self.rawValue, radix: 16, uppercase: true)))"
        }
    }
}

extension InputBuffer {
    mutating func readTransportParameterID() throws(DecodeError) -> TransportParameterID {
        return TransportParameterID(rawValue: try self.readVarInt())
    }

    mutating func readTransportParameters(
        from perspective: QUICTransportParameters.Perspective
    ) throws(QUICTransportParameterError) -> QUICTransportParameters {
        var parameters = QUICTransportParameters()
        var seen = Set<TransportParameterID>()
        while self.byteCount > 0 {
            let id: TransportParameterID
            let length: UInt64
            do {
                id = try self.readTransportParameterID()
                length = try self.readVarInt()
            } catch {
                throw QUICTransportParameterError(reason: "truncated parameter header")
            }
            guard length <= UInt64(self.byteCount) else {
                throw QUICTransportParameterError(reason: "parameter overruns buffer", id: id.rawValue)
            }
            let valueBytes: UnsafeRawBufferPointer
            do {
                valueBytes = try self.read(length: Int(length))
            } catch {
                throw QUICTransportParameterError(reason: "parameter overruns buffer", id: id.rawValue)
            }
            if !id.isReservedForGreasing {
                guard seen.insert(id).inserted else {
                    throw QUICTransportParameterError(reason: "duplicate parameter", id: id.rawValue)
                }
            }

            func varIntValue() throws(QUICTransportParameterError) -> UInt64 {
                guard let (value, consumed) = VarInt.read(from: valueBytes), consumed == valueBytes.count else {
                    throw QUICTransportParameterError(reason: "malformed integer parameter", id: id.rawValue)
                }
                return value
            }

            func connectionIDValue() throws(QUICTransportParameterError) -> QUICConnectionID {
                guard valueBytes.count <= QUICConnectionID.maxLength else {
                    throw QUICTransportParameterError(reason: "connection ID too long", id: id.rawValue)
                }
                return QUICConnectionID(valueBytes)
            }

            func requireServer() throws(QUICTransportParameterError) {
                if perspective == .client {
                    throw QUICTransportParameterError(reason: "parameter not allowed from client", id: id.rawValue)
                }
            }

            switch id {
            case .originalDestinationConnectionID:
                try requireServer()
                parameters.originalDestinationConnectionID = try connectionIDValue()
            case .maxIdleTimeout:
                parameters.maxIdleTimeout = .milliseconds(Int64(clamping: try varIntValue()))
            case .statelessResetToken:
                try requireServer()
                guard valueBytes.count == QUICStatelessResetToken.length else {
                    throw QUICTransportParameterError(reason: "stateless reset token must be 16 bytes", id: id.rawValue)
                }
                parameters.statelessResetToken = QUICStatelessResetToken(valueBytes)
            case .maxUDPPayloadSize:
                let value = try varIntValue()
                guard value >= QUICTransportParameters.minimumMaxUDPPayloadSize else {
                    throw QUICTransportParameterError(reason: "max_udp_payload_size below 1200", id: id.rawValue)
                }
                parameters.maxUDPPayloadSize = value
            case .initialMaxData:
                parameters.initialMaxData = try varIntValue()
            case .initialMaxStreamDataBidirectionalLocal:
                parameters.initialMaxStreamDataBidirectionalLocal = try varIntValue()
            case .initialMaxStreamDataBidirectionalRemote:
                parameters.initialMaxStreamDataBidirectionalRemote = try varIntValue()
            case .initialMaxStreamDataUnidirectional:
                parameters.initialMaxStreamDataUnidirectional = try varIntValue()
            case .initialMaxStreamsBidirectional:
                let value = try varIntValue()
                guard value <= StreamLimits.maxStreamCount else {
                    throw QUICTransportParameterError(reason: "initial_max_streams_bidi exceeds 2^60", id: id.rawValue)
                }
                parameters.initialMaxStreamsBidirectional = value
            case .initialMaxStreamsUnidirectional:
                let value = try varIntValue()
                guard value <= StreamLimits.maxStreamCount else {
                    throw QUICTransportParameterError(reason: "initial_max_streams_uni exceeds 2^60", id: id.rawValue)
                }
                parameters.initialMaxStreamsUnidirectional = value
            case .ackDelayExponent:
                let value = try varIntValue()
                guard value <= QUICTransportParameters.maximumACKDelayExponent else {
                    throw QUICTransportParameterError(reason: "ack_delay_exponent above 20", id: id.rawValue)
                }
                parameters.ackDelayExponent = value
            case .maxACKDelay:
                let value = try varIntValue()
                guard value < 1 << 14 else {
                    throw QUICTransportParameterError(reason: "max_ack_delay not below 2^14", id: id.rawValue)
                }
                parameters.maxACKDelay = .milliseconds(Int64(value))
            case .disableActiveMigration:
                guard valueBytes.isEmpty else {
                    throw QUICTransportParameterError(reason: "disable_active_migration must be empty", id: id.rawValue)
                }
                parameters.isActiveMigrationDisabled = true
            case .preferredAddress:
                try requireServer()
                var buffer = InputBuffer(storage: valueBytes)
                do {
                    parameters.preferredAddress = try buffer.readPreferredAddress()
                } catch {
                    throw QUICTransportParameterError(reason: "malformed preferred_address", id: id.rawValue)
                }
            case .activeConnectionIDLimit:
                let value = try varIntValue()
                guard value >= 2 else {
                    throw QUICTransportParameterError(reason: "active_connection_id_limit below 2", id: id.rawValue)
                }
                parameters.activeConnectionIDLimit = value
            case .initialSourceConnectionID:
                parameters.initialSourceConnectionID = try connectionIDValue()
            case .maxDatagramFrameSize:
                parameters.maxDatagramFrameSize = try varIntValue()
            case .retrySourceConnectionID:
                try requireServer()
                parameters.retrySourceConnectionID = try connectionIDValue()
            default:
                break
            }
        }
        return parameters
    }

    mutating func readPreferredAddress() throws(DecodeError) -> QUICTransportParameters.PreferredAddress {
        let ipv4Address = try self.readInteger(as: UInt32.self)
        let ipv4Port = try self.readInteger(as: UInt16.self)
        let ipv6Address = try self.readBytes(length: 16)
        let ipv6Port = try self.readInteger(as: UInt16.self)
        let idLength = Int(try self.readInteger(as: UInt8.self))
        guard idLength <= QUICConnectionID.maxLength else {
            throw DecodeError.malformed
        }
        let id = QUICConnectionID(try self.read(length: idLength))
        let token = QUICStatelessResetToken(try self.read(length: QUICStatelessResetToken.length))
        guard self.byteCount == 0 else {
            throw DecodeError.malformed
        }
        let ipv4: (address: UInt32, port: UInt16)? =
            (ipv4Address == 0 && ipv4Port == 0) ? nil : (ipv4Address, ipv4Port)
        let ipv6: (address: [UInt8], port: UInt16)? =
            (ipv6Address.allSatisfy { $0 == 0 } && ipv6Port == 0) ? nil : (ipv6Address, ipv6Port)
        return QUICTransportParameters.PreferredAddress(
            ipv4: ipv4,
            ipv6: ipv6,
            connectionID: id,
            statelessResetToken: token
        )
    }
}

extension ByteBuffer {
    @discardableResult
    mutating func writeTransportParameterID(_ id: TransportParameterID) -> Int {
        return self.writeVarInt(id.rawValue)
    }

    mutating func writeTransportParameter(_ id: TransportParameterID, varInt value: UInt64) {
        self.writeTransportParameterID(id)
        self.writeVarInt(UInt64(VarInt.encodedLength(value)))
        self.writeVarInt(value)
    }

    mutating func writeTransportParameter(_ id: TransportParameterID, bytes: [UInt8]) {
        self.writeTransportParameterID(id)
        self.writeVarInt(UInt64(bytes.count))
        self.writeBytes(bytes)
    }

    mutating func writeTransportParameters(
        _ parameters: QUICTransportParameters,
        from perspective: QUICTransportParameters.Perspective
    ) {
        if perspective == .server, let originalDestinationConnectionID = parameters.originalDestinationConnectionID {
            self.writeTransportParameter(.originalDestinationConnectionID, bytes: originalDestinationConnectionID.bytes)
        }
        if parameters.maxIdleTimeout > .zero {
            self.writeTransportParameter(
                .maxIdleTimeout,
                varInt: Swift.min(parameters.maxIdleTimeout.clampedNanoseconds / Time.millisecond, VarInt.max)
            )
        }
        if perspective == .server, let statelessResetToken = parameters.statelessResetToken {
            self.writeTransportParameter(.statelessResetToken, bytes: statelessResetToken.bytes)
        }
        if parameters.maxUDPPayloadSize != QUICTransportParameters.defaultMaxUDPPayloadSize {
            self.writeTransportParameter(.maxUDPPayloadSize, varInt: parameters.maxUDPPayloadSize)
        }
        if parameters.initialMaxData > 0 {
            self.writeTransportParameter(.initialMaxData, varInt: parameters.initialMaxData)
        }
        if parameters.initialMaxStreamDataBidirectionalLocal > 0 {
            self.writeTransportParameter(
                .initialMaxStreamDataBidirectionalLocal,
                varInt: parameters.initialMaxStreamDataBidirectionalLocal
            )
        }
        if parameters.initialMaxStreamDataBidirectionalRemote > 0 {
            self.writeTransportParameter(
                .initialMaxStreamDataBidirectionalRemote,
                varInt: parameters.initialMaxStreamDataBidirectionalRemote
            )
        }
        if parameters.initialMaxStreamDataUnidirectional > 0 {
            self.writeTransportParameter(
                .initialMaxStreamDataUnidirectional,
                varInt: parameters.initialMaxStreamDataUnidirectional
            )
        }
        if parameters.initialMaxStreamsBidirectional > 0 {
            self.writeTransportParameter(.initialMaxStreamsBidirectional, varInt: parameters.initialMaxStreamsBidirectional)
        }
        if parameters.initialMaxStreamsUnidirectional > 0 {
            self.writeTransportParameter(
                .initialMaxStreamsUnidirectional,
                varInt: parameters.initialMaxStreamsUnidirectional
            )
        }
        if parameters.ackDelayExponent != QUICTransportParameters.defaultACKDelayExponent {
            self.writeTransportParameter(.ackDelayExponent, varInt: parameters.ackDelayExponent)
        }
        if parameters.maxACKDelay != QUICTransportParameters.defaultMaxACKDelay {
            self.writeTransportParameter(
                .maxACKDelay,
                varInt: Swift.min(parameters.maxACKDelay.clampedNanoseconds / Time.millisecond, VarInt.max)
            )
        }
        if parameters.isActiveMigrationDisabled {
            self.writeTransportParameterID(.disableActiveMigration)
            self.writeVarInt(0)
        }
        if perspective == .server, let preferredAddress = parameters.preferredAddress {
            var body = ByteBuffer(capacity: 64)
            body.writeInteger(preferredAddress.ipv4?.address ?? 0)
            body.writeInteger(preferredAddress.ipv4?.port ?? 0)
            body.writeBytes(preferredAddress.ipv6?.address ?? [UInt8](repeating: 0, count: 16))
            body.writeInteger(preferredAddress.ipv6?.port ?? 0)
            body.writeInteger(UInt8(preferredAddress.connectionID.count))
            body.writeBytes(preferredAddress.connectionID.bytes)
            body.writeBytes(preferredAddress.statelessResetToken.bytes)
            self.writeTransportParameter(.preferredAddress, bytes: body.readableBytesView)
        }
        if parameters.activeConnectionIDLimit != QUICTransportParameters.defaultActiveConnectionIDLimit {
            self.writeTransportParameter(.activeConnectionIDLimit, varInt: parameters.activeConnectionIDLimit)
        }
        if let initialSourceConnectionID = parameters.initialSourceConnectionID {
            self.writeTransportParameter(.initialSourceConnectionID, bytes: initialSourceConnectionID.bytes)
        }
        if perspective == .server, let retrySourceConnectionID = parameters.retrySourceConnectionID {
            self.writeTransportParameter(.retrySourceConnectionID, bytes: retrySourceConnectionID.bytes)
        }
        if parameters.maxDatagramFrameSize > 0 {
            self.writeTransportParameter(.maxDatagramFrameSize, varInt: parameters.maxDatagramFrameSize)
        }
    }
}
