//
//  ConnectionCore+Handshake.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    func startHandshakeIfNeeded(now: Nanoseconds) throws(TransportError) {
        guard !self.hasStartedHandshake else {
            return
        }
        self.hasStartedHandshake = true
        let encoded = self.localTransportParameters.encoded(from: .client)
        let actions: [QUICHandshakeAction]
        do {
            actions = try self.tls.startHandshake(localTransportParameters: Data(encoded))
        } catch {
            throw self.tlsFailure(error)
        }
        try self.applyHandshakeActions(actions, now: now)
    }

    func tlsFailure(_ error: any Error) -> TransportError {
        let alert = (error as? QUICTLSAlert)?.alert ?? QUICTLSAlert.internalError.alert
        return TransportError(.cryptoError(alert: alert), reason: String(describing: error), underlying: error)
    }

    func deliverCryptoData(_ data: Data, level: QUICEncryptionLevel, now: Nanoseconds) throws(TransportError) {
        let actions: [QUICHandshakeAction]
        do {
            actions = try self.tls.receiveCryptoData(data, at: level)
        } catch {
            throw self.tlsFailure(error)
        }
        try self.applyHandshakeActions(actions, now: now)
    }

    func applyHandshakeActions(_ actions: [QUICHandshakeAction], now: Nanoseconds) throws(TransportError) {
        for action in actions {
            switch action {
            case .sendCryptoData(let data, let level):
                guard let space = self.space(for: level) else {
                    continue
                }
                data.withUnsafeBytes { space.appendCryptoData($0) }
            case .installHandshakeKeys(let suite, let readSecret, let writeSecret):
                guard let handshakeSpace = self.handshakeSpace else {
                    continue
                }
                handshakeSpace.readKeys = PacketKeys(suite: suite, secret: Array(readSecret))
                handshakeSpace.writeKeys = PacketKeys(suite: suite, secret: Array(writeSecret))
                self.shouldProcessBufferedHandshakePackets = true
            case .installApplicationKeys(let suite, let readSecret, let writeSecret):
                self.applicationSpace.readKeys = PacketKeys(suite: suite, secret: Array(readSecret))
                self.applicationSpace.writeKeys = PacketKeys(suite: suite, secret: Array(writeSecret))
                self.keyUpdate = KeyUpdateState()
                self.keyUpdate.writeFirstPacketNumber = self.applicationSpace.nextPacketNumber
                self.shouldProcessBufferedApplicationPackets = true
            case .setRemoteTransportParameters(let data):
                try self.setRemoteTransportParameters(Array(data))
            case .verifyPeer(let certificates):
                self.isAwaitingPeerVerification = true
                self.emit(.peerVerificationRequested(certificates: certificates))
            case .handshakeComplete:
                try self.completeTLSHandshake(now: now)
            }
        }
    }

    func completePeerVerification(error: (any Error)?, now: QUICInstant) throws(QUICError) {
        let now = self.updateTimestamp(now.nanoseconds)
        guard self.state == .handshaking, self.isAwaitingPeerVerification else {
            throw QUICError.invalidState
        }
        self.isAwaitingPeerVerification = false
        do {
            try self.resumeHandshake(afterPeerVerification: error, now: now)
        } catch {
            self.closeLocally(error, now: now)
        }
    }

    private func resumeHandshake(afterPeerVerification failure: (any Error)?, now: Nanoseconds) throws(TransportError) {
        let actions: [QUICHandshakeAction]
        do {
            actions = try self.tls.completePeerVerification(error: failure)
        } catch {
            throw self.tlsFailure(error)
        }
        try self.applyHandshakeActions(actions, now: now)
        try self.drainBufferedPackets(now: now)
    }

    func setRemoteTransportParameters(_ bytes: [UInt8]) throws(TransportError) {
        guard !self.hasReceivedTransportParameters else {
            throw TransportError(.protocolViolation, reason: "duplicate transport parameters")
        }
        let parameters: QUICTransportParameters
        do {
            parameters = try QUICTransportParameters.decode(bytes, from: .server)
        } catch {
            throw TransportError(.transportParameterError, reason: error.reason)
        }
        guard parameters.initialSourceConnectionID == self.active.connectionID.id else {
            throw TransportError(.transportParameterError, reason: "initial_source_connection_id mismatch")
        }
        guard parameters.originalDestinationConnectionID == self.originalDestinationID else {
            throw TransportError(.transportParameterError, reason: "original_destination_connection_id mismatch")
        }
        if self.hasReceivedRetry {
            guard parameters.retrySourceConnectionID == self.retrySourceID else {
                throw TransportError(.transportParameterError, reason: "retry_source_connection_id mismatch")
            }
        } else if parameters.retrySourceConnectionID != nil {
            throw TransportError(.transportParameterError, reason: "unexpected retry_source_connection_id")
        }
        self.remoteTransportParameters = parameters
        self.hasReceivedTransportParameters = true
        self.localBidirectionalMaxStreams = parameters.initialMaxStreamsBidirectional
        self.localUnidirectionalMaxStreams = parameters.initialMaxStreamsUnidirectional
        self.sendMaxOffset = Swift.max(self.sendMaxOffset, parameters.initialMaxData)
        for stream in self.streams.values where stream.isLocal {
            let limit = stream.id.isBidirectional
                ? parameters.initialMaxStreamDataBidirectionalRemote
                : parameters.initialMaxStreamDataUnidirectional
            stream.sendMaxOffset = Swift.max(stream.sendMaxOffset, limit)
        }
        if let token = parameters.statelessResetToken, self.active.connectionID.sequence == 0 {
            self.active.connectionID.token = token
        }
    }

    func completeTLSHandshake(now: Nanoseconds) throws(TransportError) {
        guard !self.isTLSHandshakeComplete else {
            return
        }
        guard self.hasReceivedTransportParameters else {
            throw TransportError(
                .cryptoError(alert: QUICTLSAlert.missingExtension.alert),
                reason: "missing quic_transport_parameters"
            )
        }
        self.isTLSHandshakeComplete = true
        self.isHandshakeComplete = true
        self.emit(.handshakeCompleted)
        if self.localBidirectionalMaxStreams > 0 {
            self.emit(.streamLimitUpdated(bidirectional: true, maximumStreams: self.localBidirectionalMaxStreams))
        }
        if self.localUnidirectionalMaxStreams > 0 {
            self.emit(.streamLimitUpdated(bidirectional: false, maximumStreams: self.localUnidirectionalMaxStreams))
        }
    }

    func confirmHandshake(now: Nanoseconds) {
        guard !self.isHandshakeConfirmed else {
            return
        }
        self.isHandshakeConfirmed = true
        self.isServerAddressVerified = true
        self.handshakeConfirmedAt = now
        self.discardHandshakeSpace(now: now)
        self.emit(.handshakeConfirmed)
        self.setLossDetectionTimer(now: now)
    }
}

extension ConnectionCore {
    func discardInitialSpace(now: Nanoseconds) {
        guard let space = self.initialSpace else {
            return
        }
        self.discard(space, now: now)
        self.initialSpace = nil
    }

    func discardHandshakeSpace(now: Nanoseconds) {
        guard let space = self.handshakeSpace else {
            return
        }
        self.discard(space, now: now)
        self.handshakeSpace = nil
    }

    private func discard(_ space: PacketNumberSpace, now: Nanoseconds) {
        _ = space.sent.removeAll(state: &self.congestionState)
        space.readKeys = nil
        space.writeKeys = nil
        space.bufferedPackets.removeAll()
        space.lastSentAt = Time.never
        self.setLossDetectionTimer(now: now)
    }
}

extension ConnectionCore {
    func prepareKeyUpdate(now: Nanoseconds) throws(TransportError) {
        guard let write = self.applicationSpace.writeKeys, let read = self.applicationSpace.readKeys else {
            return
        }
        if self.keyUpdate.encryptionCount >= write.aead.confidentialityLimit {
            guard self.initiateKeyUpdate(now: now) else {
                throw TransportError(.aeadLimitReached, reason: "confidentiality limit reached")
            }
        }
        guard !self.keyUpdate.isPending,
              !Time.notElapsed(self.keyUpdate.confirmedAt, self.pto(for: self.applicationSpace), now) else {
            return
        }
        if self.keyUpdate.nextRead != nil || self.keyUpdate.nextWrite != nil {
            return
        }
        self.keyUpdate.nextRead = read.updated()
        self.keyUpdate.nextWrite = write.updated()
        self.keyUpdate.oldRead = nil
    }

    @discardableResult
    func initiateKeyUpdate(now: Nanoseconds) -> Bool {
        guard self.isHandshakeConfirmed,
              !self.keyUpdate.isPending,
              self.keyUpdate.nextRead != nil,
              self.keyUpdate.nextWrite != nil,
              !Time.notElapsed(self.keyUpdate.confirmedAt, 3 * self.pto(for: self.applicationSpace), now) else {
            return false
        }
        self.rotateKeys(firstReadPacketNumber: PacketNumber.max, initiator: true)
        return true
    }

    func rotateKeys(firstReadPacketNumber: UInt64, initiator: Bool) {
        self.keyUpdate.oldRead = self.applicationSpace.readKeys
        self.applicationSpace.readKeys = self.keyUpdate.nextRead
        self.keyUpdate.nextRead = nil
        self.keyUpdate.readFirstPacketNumber = firstReadPacketNumber
        self.applicationSpace.writeKeys = self.keyUpdate.nextWrite
        self.keyUpdate.nextWrite = nil
        self.keyUpdate.writeFirstPacketNumber = self.applicationSpace.nextPacketNumber
        self.keyUpdate.encryptionCount = 0
        self.keyUpdate.currentPhase.toggle()
        self.keyUpdate.isPending = true
        self.keyUpdate.isInitiator = initiator
    }

    func confirmRemoteKeyUpdate(acknowledgedLargest: UInt64, now: Nanoseconds) {
        guard self.keyUpdate.isPending,
              !self.keyUpdate.isInitiator,
              acknowledgedLargest >= self.keyUpdate.readFirstPacketNumber else {
            return
        }
        self.keyUpdate.isPending = false
        self.keyUpdate.confirmedAt = now
    }

    func confirmLocalKeyUpdate(acknowledgedLargest: UInt64, now: Nanoseconds) {
        guard self.keyUpdate.isPending,
              self.keyUpdate.isInitiator,
              acknowledgedLargest >= self.keyUpdate.writeFirstPacketNumber else {
            return
        }
        self.keyUpdate.isPending = false
        self.keyUpdate.isInitiator = false
        self.keyUpdate.confirmedAt = now
    }
}
