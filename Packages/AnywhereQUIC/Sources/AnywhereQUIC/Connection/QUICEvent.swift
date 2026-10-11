//
//  QUICEvent.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

public enum QUICEvent: Sendable {
    case datagramReceived(Data)
    case peerVerificationRequested(certificates: [Data])
    case handshakeCompleted
    case handshakeConfirmed
    case streamOpened(QUICStreamID)
    case streamData(QUICStreamID, Data, fin: Bool)
    case streamWritable(QUICStreamID)
    case streamReset(QUICStreamID, errorCode: UInt64, finalSize: UInt64)
    case streamSendingStopped(QUICStreamID, errorCode: UInt64)
    case streamClosed(QUICStreamID, applicationErrorCode: UInt64?)
    case streamLimitUpdated(bidirectional: Bool, maximumStreams: UInt64)
    case pathValidated(QUICPath)
    case pathValidationFailed(QUICPath)
    case pathValidationAborted(QUICPath)
    case connectionClosed(QUICConnectionCloseReason)
}

public enum QUICConnectionState: Hashable, Sendable {
    case handshaking
    case established
    case closing
    case draining
    case closed
}

public enum QUICTimeoutKind: CaseIterable, Hashable, Sendable {
    case pacing
    case ackDelay
    case lossDetection
    case pathValidation
    case pathMTUDiscovery
    case connectionIDs
    case keepAlive
    case handshake
    case idle
    case closing
    
    public var isCoarse: Bool {
        switch self {
        case .pacing, .ackDelay, .lossDetection, .pathValidation, .pathMTUDiscovery:
            return false
        case .connectionIDs, .keepAlive, .handshake, .idle, .closing:
            return true
        }
    }
}
