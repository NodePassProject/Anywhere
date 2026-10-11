//
//  Stream.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

final class Stream {
    let id: QUICStreamID
    let isLocal: Bool
    var send: SendBuffer?
    var receive: ReceiveBuffer?

    var sendMaxOffset: UInt64
    var sendLastBlockedOffset: UInt64 = .max

    var receiveMaxOffset: UInt64
    var receiveUnsentMaxOffset: UInt64
    var receiveWindow: UInt64
    var receiveLastOffset: UInt64 = 0
    var lastMaxStreamDataSentAt: Nanoseconds = Time.never

    var isReadClosed = false
    var isWriteClosed = false
    var hasSentResetStream = false
    var isResetStreamAcknowledged = false
    var hasReceivedResetStream = false
    var hasSentStopSending = false
    var hasReceivedStopSending = false
    var isResetStreamPending = false
    var isStopSendingPending = false
    var resetStreamErrorCode: UInt64 = 0
    var stopSendingErrorCode: UInt64 = 0
    var applicationErrorCode: UInt64?
    var hasSentStreamFrame = false
    var hasAcknowledgedStreamFrame = false
    var isQueued = false
    var wantsWritableEvent = false

    init(
        id: QUICStreamID,
        isLocal: Bool,
        sendMaxOffset: UInt64,
        receiveMaxOffset: UInt64,
        canSend: Bool,
        canReceive: Bool
    ) {
        self.id = id
        self.isLocal = isLocal
        self.sendMaxOffset = sendMaxOffset
        self.receiveMaxOffset = receiveMaxOffset
        self.receiveUnsentMaxOffset = receiveMaxOffset
        self.receiveWindow = receiveMaxOffset
        self.send = canSend ? SendBuffer() : nil
        self.receive = canReceive ? ReceiveBuffer() : nil
    }

    var sendOffset: UInt64 { self.send?.sentOffset ?? 0 }

    var receiveOffset: UInt64 { self.receive?.readOffset ?? 0 }

    var isAllSendDataAcknowledged: Bool {
        guard let send = self.send else {
            return true
        }
        return send.isAllAcknowledged
    }

    var isReceiveComplete: Bool {
        return self.isReadClosed && (self.hasReceivedResetStream || self.receiveOffset == self.receiveLastOffset)
    }

    var isSendComplete: Bool {
        return (self.hasSentResetStream && self.isResetStreamAcknowledged) || self.isAllSendDataAcknowledged
    }

    var isClosed: Bool {
        return self.isReadClosed && self.isWriteClosed && self.isReceiveComplete && self.isSendComplete
    }

    var hasPendingSendData: Bool {
        guard let send = self.send, !self.hasSentResetStream else {
            return false
        }
        return send.hasPendingData
    }

    var hasPendingFrames: Bool {
        return self.isResetStreamPending
            || self.isStopSendingPending
            || self.hasPendingSendData
            || self.shouldSendStreamDataBlocked
            || self.shouldSendMaxStreamData()
    }

    var shouldSendStreamDataBlocked: Bool {
        guard let send = self.send, !self.isWriteClosed, !self.hasSentResetStream else {
            return false
        }
        return send.sentOffset == self.sendMaxOffset
            && send.endOffset > send.sentOffset
            && self.sendLastBlockedOffset != self.sendMaxOffset
    }

    func shouldSendMaxStreamData() -> Bool {
        guard self.receive != nil, !self.isReadClosed, !self.hasSentStopSending else {
            return false
        }
        return self.receiveWindow < 4 * (self.receiveUnsentMaxOffset - self.receiveMaxOffset)
    }

    func setApplicationErrorCode(_ code: UInt64) {
        if self.applicationErrorCode == nil {
            self.applicationErrorCode = code
        }
    }
}
