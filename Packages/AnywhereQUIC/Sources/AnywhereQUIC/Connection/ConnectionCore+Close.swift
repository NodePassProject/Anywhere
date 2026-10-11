//
//  ConnectionCore+Close.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    var closeReasonIfClosed: QUICConnectionCloseReason? { self.closeReason }

    func close(applicationErrorCode: UInt64, reason: String = "", now: QUICInstant) {
        let now = self.updateTimestamp(now.nanoseconds)
        guard self.state == .handshaking || self.state == .established else {
            return
        }
        let closeReason = QUICConnectionCloseReason.localApplicationError(code: applicationErrorCode, reason: reason)
        self.pendingClose = (true, applicationErrorCode, FrameType(rawValue: 0), reason)
        self.enterClosing(reason: closeReason, now: now)
    }

    func closeLocally(_ error: TransportError, now: Nanoseconds) {
        guard self.state == .handshaking || self.state == .established else {
            return
        }
        let reason: QUICConnectionCloseReason
        if let underlying = error.underlying {
            reason = .tlsError(underlying)
        } else {
            reason = .localTransportError(code: error.code, reason: error.reason)
        }
        self.pendingClose = (false, error.code.rawValue, error.frameType ?? FrameType(rawValue: 0), error.reason)
        self.enterClosing(reason: reason, now: now)
    }

    private func enterClosing(reason: QUICConnectionCloseReason, now: Nanoseconds) {
        self.closeReason = reason
        self.state = .closing
        self.pendingDatagrams.removeAll()
        self.closingEndsAt = now.addingClamped(3 * self.pto(for: self.applicationSpace))
        self.lossDetectionTimer = Time.never
        self.pathValidation = nil
        self.pathMTUDiscovery = nil
        self.pacer.reset()
        self.emit(.connectionClosed(reason))
    }

    func handlePeerClose(_ frame: ConnectionCloseFrame, now: Nanoseconds) {
        let text = String(decoding: frame.reason.prefix(1024), as: UTF8.self)
        let reason: QUICConnectionCloseReason
        if frame.isApplication {
            reason = .peerApplicationError(code: frame.errorCode, reason: text)
        } else {
            reason = .peerTransportError(
                code: QUICTransportErrorCode(rawValue: frame.errorCode),
                frameType: frame.frameType.rawValue,
                reason: text
            )
        }
        self.enterDraining(reason: reason, now: now)
    }

    func enterDraining(reason: QUICConnectionCloseReason, now: Nanoseconds) {
        guard self.state != .draining, self.state != .closed else {
            return
        }
        self.closeReason = reason
        self.state = .draining
        self.pendingDatagrams.removeAll()
        self.closingEndsAt = now.addingClamped(3 * self.pto(for: self.applicationSpace))
        self.lossDetectionTimer = Time.never
        self.pathValidation = nil
        self.pathMTUDiscovery = nil
        self.pendingClose = nil
        self.emit(.connectionClosed(reason))
    }

    func enterClosed(reason: QUICConnectionCloseReason, emitEvent: Bool) {
        guard self.state != .closed else {
            return
        }
        if self.closeReason == nil || emitEvent {
            self.closeReason = reason
        }
        self.state = .closed
        self.pendingDatagrams.removeAll()
        self.lossDetectionTimer = Time.never
        if emitEvent {
            self.emit(.connectionClosed(reason))
        }
    }

    func writeClosePacketIfNeeded(
        into buffer: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) -> QUICOutgoingDatagram? {
        if let pendingClose = self.pendingClose {
            self.pendingClose = nil
            guard !self.isPacketNumberExhausted else {
                return nil
            }
            let maxLength = Swift.min(buffer.count, self.pathMaxSendUDPPayloadSize)
            let destination = UnsafeMutableBufferPointer(rebasing: buffer[0..<maxLength])
            let packetsSentBefore = self.packetsSent
            let written = self.writeClosePackets(into: destination, close: pendingClose, now: now)
            guard written > 0 else {
                return nil
            }
            self.closePacket = Array(destination[0..<written])
            self.closePacketCount = self.packetsSent - packetsSentBefore
            self.closePacketPath = self.active.path
            return QUICOutgoingDatagram(count: written, path: self.active.path)
        }
        if self.isCloseResendPending, let closePacket = self.closePacket, closePacket.count <= buffer.count {
            self.isCloseResendPending = false
            closePacket.withUnsafeBytes { raw in
                UnsafeMutableRawBufferPointer(buffer).copyMemory(from: raw)
            }
            self.packetsSent += self.closePacketCount
            self.bytesSent += UInt64(closePacket.count)
            return QUICOutgoingDatagram(count: closePacket.count, path: self.closePacketPath ?? self.active.path)
        }
        return nil
    }

    private func writeClosePackets(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        close: (isApplication: Bool, errorCode: UInt64, frameType: FrameType, reason: String),
        now: Nanoseconds
    ) -> Int {
        var written = 0
        let reasonBytes = Array(close.reason.utf8.prefix(1024))
        let hasApplicationKeys = self.applicationSpace.writeKeys != nil
        if !self.isHandshakeConfirmed {
            let errorCode = close.isApplication ? QUICTransportErrorCode.applicationError.rawValue : close.errorCode
            let frameType = close.isApplication ? FrameType(rawValue: 0) : close.frameType
            let reason = close.isApplication ? [] : reasonBytes
            if let handshakeSpace = self.handshakeSpace, handshakeSpace.writeKeys != nil {
                written += self.writeSingleFramePacket(
                    space: handshakeSpace,
                    type: .handshake,
                    destinationID: self.active.connectionID.id,
                    into: destination,
                    offset: written,
                    padToDatagram: false,
                    padToLength: nil,
                    track: nil,
                    now: now
                ) { writer in
                    return writer.writeConnectionClose(
                        isApplication: false,
                        errorCode: errorCode,
                        frameType: frameType,
                        reason: reason
                    )
                }
            } else if let initialSpace = self.initialSpace, initialSpace.writeKeys != nil {
                written += self.writeSingleFramePacket(
                    space: initialSpace,
                    type: .initial,
                    destinationID: self.active.connectionID.id,
                    into: destination,
                    offset: written,
                    padToDatagram: !hasApplicationKeys,
                    padToLength: nil,
                    track: nil,
                    now: now
                ) { writer in
                    return writer.writeConnectionClose(
                        isApplication: false,
                        errorCode: errorCode,
                        frameType: frameType,
                        reason: reason
                    )
                }
            }
            if !hasApplicationKeys {
                return written
            }
        }
        guard hasApplicationKeys else {
            return written
        }
        written += self.writeSingleFramePacket(
            space: self.applicationSpace,
            type: .oneRTT,
            destinationID: self.active.connectionID.id,
            into: destination,
            offset: written,
            padToDatagram: false,
            padToLength: nil,
            track: nil,
            now: now
        ) { writer in
            return writer.writeConnectionClose(
                isApplication: close.isApplication,
                errorCode: close.errorCode,
                frameType: close.frameType,
                reason: reasonBytes
            )
        }
        return written
    }
}
