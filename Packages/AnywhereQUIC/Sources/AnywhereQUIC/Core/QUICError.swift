//
//  QUICError.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

public struct QUICTransportErrorCode: RawRepresentable, Sendable {
    public var rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }
}

extension QUICTransportErrorCode {
    public static let noError = QUICTransportErrorCode(rawValue: 0x00)
    public static let internalError = QUICTransportErrorCode(rawValue: 0x01)
    public static let connectionRefused = QUICTransportErrorCode(rawValue: 0x02)
    public static let flowControlError = QUICTransportErrorCode(rawValue: 0x03)
    public static let streamLimitError = QUICTransportErrorCode(rawValue: 0x04)
    public static let streamStateError = QUICTransportErrorCode(rawValue: 0x05)
    public static let finalSizeError = QUICTransportErrorCode(rawValue: 0x06)
    public static let frameEncodingError = QUICTransportErrorCode(rawValue: 0x07)
    public static let transportParameterError = QUICTransportErrorCode(rawValue: 0x08)
    public static let connectionIDLimitError = QUICTransportErrorCode(rawValue: 0x09)
    public static let protocolViolation = QUICTransportErrorCode(rawValue: 0x0A)
    public static let invalidToken = QUICTransportErrorCode(rawValue: 0x0B)
    public static let applicationError = QUICTransportErrorCode(rawValue: 0x0C)
    public static let cryptoBufferExceeded = QUICTransportErrorCode(rawValue: 0x0D)
    public static let keyUpdateError = QUICTransportErrorCode(rawValue: 0x0E)
    public static let aeadLimitReached = QUICTransportErrorCode(rawValue: 0x0F)
    public static let noViablePath = QUICTransportErrorCode(rawValue: 0x10)

    public static func cryptoError(alert: UInt8) -> QUICTransportErrorCode {
        return QUICTransportErrorCode(rawValue: 0x100 | UInt64(alert))
    }

    public var isCryptoError: Bool {
        return self.rawValue >= 0x100 && self.rawValue <= 0x1FF
    }

    public var tlsAlert: UInt8? {
        return self.isCryptoError ? UInt8(truncatingIfNeeded: self.rawValue) : nil
    }
}

extension QUICTransportErrorCode: Hashable, CustomStringConvertible {
    public var description: String {
        switch self {
        case .noError:
            return "NO_ERROR"
        case .internalError:
            return "INTERNAL_ERROR"
        case .connectionRefused:
            return "CONNECTION_REFUSED"
        case .flowControlError:
            return "FLOW_CONTROL_ERROR"
        case .streamLimitError:
            return "STREAM_LIMIT_ERROR"
        case .streamStateError:
            return "STREAM_STATE_ERROR"
        case .finalSizeError:
            return "FINAL_SIZE_ERROR"
        case .frameEncodingError:
            return "FRAME_ENCODING_ERROR"
        case .transportParameterError:
            return "TRANSPORT_PARAMETER_ERROR"
        case .connectionIDLimitError:
            return "CONNECTION_ID_LIMIT_ERROR"
        case .protocolViolation:
            return "PROTOCOL_VIOLATION"
        case .invalidToken:
            return "INVALID_TOKEN"
        case .applicationError:
            return "APPLICATION_ERROR"
        case .cryptoBufferExceeded:
            return "CRYPTO_BUFFER_EXCEEDED"
        case .keyUpdateError:
            return "KEY_UPDATE_ERROR"
        case .aeadLimitReached:
            return "AEAD_LIMIT_REACHED"
        case .noViablePath:
            return "NO_VIABLE_PATH"
        default:
            if let alert = self.tlsAlert {
                return "CRYPTO_ERROR(\(alert))"
            }
            return "0x" + String(self.rawValue, radix: 16)
        }
    }
}

public struct QUICTLSAlert: Error, Sendable {
    public var alert: UInt8

    public init(alert: UInt8) {
        self.alert = alert
    }
}

extension QUICTLSAlert: Hashable {
    public static let unexpectedMessage = QUICTLSAlert(alert: 10)
    public static let handshakeFailure = QUICTLSAlert(alert: 40)
    public static let badCertificate = QUICTLSAlert(alert: 42)
    public static let illegalParameter = QUICTLSAlert(alert: 47)
    public static let decodeError = QUICTLSAlert(alert: 50)
    public static let internalError = QUICTLSAlert(alert: 80)
    public static let missingExtension = QUICTLSAlert(alert: 109)
    public static let noApplicationProtocol = QUICTLSAlert(alert: 120)
}

public enum QUICError: Hashable, Error, Sendable {
    case invalidState
    case exporterUnavailable
    case invalidArgument
    case streamNotFound
    case streamSendClosed
    case streamIDBlocked
    case connectionIDBlocked
    case sendBufferFull
    case datagramUnsupported
    case datagramTooLarge
    case migrationDisabled
    case pathUnchanged
}

public enum QUICConnectionCloseReason: Sendable {
    case peerTransportError(code: QUICTransportErrorCode, frameType: UInt64?, reason: String)
    case peerApplicationError(code: UInt64, reason: String)
    case localTransportError(code: QUICTransportErrorCode, reason: String)
    case localApplicationError(code: UInt64, reason: String)
    case tlsError(any Error)
    case idleTimeout
    case handshakeTimeout
    case statelessReset
    case versionNegotiation(offeredVersions: [UInt32])
    case packetNumberExhausted

    public var isPeerInitiated: Bool {
        switch self {
        case .peerTransportError, .peerApplicationError, .statelessReset, .versionNegotiation:
            return true
        default:
            return false
        }
    }
}

struct TransportError: Error {
    var code: QUICTransportErrorCode
    var frameType: FrameType?
    var reason: String
    var underlying: (any Error)?

    init(
        _ code: QUICTransportErrorCode,
        frameType: FrameType? = nil,
        reason: String = "",
        underlying: (any Error)? = nil
    ) {
        self.code = code
        self.frameType = frameType
        self.reason = reason
        self.underlying = underlying
    }
}

struct DiscardedPacketError: Error { }
