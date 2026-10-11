//
//  ConnectionCore+ConnectionIDs.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    func handleNewConnectionID(
        sequence: UInt64,
        retirePriorTo: UInt64,
        id: QUICConnectionID,
        token: QUICStatelessResetToken,
        now: Nanoseconds
    ) throws(TransportError) {
        guard !self.active.connectionID.id.isEmpty else {
            throw TransportError(
                .protocolViolation,
                frameType: FrameType.newConnectionID,
                reason: "NEW_CONNECTION_ID with zero-length destination connection ID"
            )
        }
        var found = false
        guard self.destinationIDs.verifyUniqueness(
            sequence: sequence,
            id: id,
            token: token,
            against: self.active.connectionID
        ) else {
            throw TransportError(
                .protocolViolation,
                frameType: FrameType.newConnectionID,
                reason: "conflicting NEW_CONNECTION_ID"
            )
        }
        if self.active.connectionID.id == id {
            found = true
        }
        if let pathValidation = self.pathValidation {
            guard self.destinationIDs.verifyUniqueness(
                sequence: sequence,
                id: id,
                token: token,
                against: pathValidation.connectionID
            ) else {
                throw TransportError(
                    .protocolViolation,
                    frameType: FrameType.newConnectionID,
                    reason: "conflicting NEW_CONNECTION_ID"
                )
            }
            if pathValidation.connectionID.id == id {
                found = true
            }
        }
        let verification = self.destinationIDs.verifyUniqueness(sequence: sequence, id: id, token: token)
        guard verification.ok else {
            throw TransportError(
                .protocolViolation,
                frameType: FrameType.newConnectionID,
                reason: "conflicting NEW_CONNECTION_ID"
            )
        }
        found = found || verification.found
        if self.destinationIDs.retirePriorTo < retirePriorTo {
            self.destinationIDs.retirePriorTo = retirePriorTo
            for retired in self.destinationIDs.retireUnused(priorTo: retirePriorTo) {
                self.enqueueRetireConnectionID(retired)
            }
        } else if sequence < self.destinationIDs.retirePriorTo {
            if self.destinationIDs.trackRetireSequence(sequence) {
                self.applicationSpace.pendingControlFrames.append(.retireConnectionID(sequence: sequence))
            }
            return
        }
        if found {
            return
        }
        guard self.destinationIDs.markSeen(sequence) else {
            return
        }
        var extra = self.active.connectionID.sequence >= self.destinationIDs.retirePriorTo ? 1 : 0
        if let pathValidation = self.pathValidation,
           pathValidation.connectionID.sequence != self.active.connectionID.sequence,
           pathValidation.connectionID.sequence >= self.destinationIDs.retirePriorTo {
            extra += 1
        }
        guard self.localTransportParameters.activeConnectionIDLimit
            > UInt64(self.destinationIDs.unusedCount + extra) else {
            throw TransportError(
                .connectionIDLimitError,
                frameType: FrameType.newConnectionID,
                reason: "active_connection_id_limit exceeded"
            )
        }
        guard self.destinationIDs.unusedCount < DestinationIDTracker.maxUnused else {
            return
        }
        self.destinationIDs.pushUnused(RemoteConnectionID(id: id, sequence: sequence, token: token))
    }

    func enqueueRetireConnectionID(_ sequence: UInt64) {
        _ = self.destinationIDs.trackRetireSequence(sequence)
        self.applicationSpace.pendingControlFrames.append(.retireConnectionID(sequence: sequence))
    }

    func retireActiveConnectionID(_ connectionID: RemoteConnectionID, path: QUICPath, now: Nanoseconds) {
        self.destinationIDs.addRetired(connectionID, path: path, now: now)
        self.enqueueRetireConnectionID(connectionID.sequence)
    }

    func postProcessNewConnectionIDs(now: Nanoseconds) throws(TransportError) {
        if self.active.connectionID.sequence < self.destinationIDs.retirePriorTo {
            guard let replacement = self.destinationIDs.popUnused() else {
                return
            }
            self.retireActiveConnectionID(self.active.connectionID, path: self.active.path, now: now)
            if var pathValidation = self.pathValidation,
               pathValidation.connectionID.sequence == self.active.connectionID.sequence {
                pathValidation.connectionID = replacement
                self.pathValidation = pathValidation
            }
            self.active.connectionID = replacement
        }
        if var pathValidation = self.pathValidation,
           pathValidation.connectionID.sequence < self.destinationIDs.retirePriorTo {
            guard let replacement = self.destinationIDs.popUnused() else {
                self.abortPathValidation(now: now)
                return
            }
            self.retireActiveConnectionID(pathValidation.connectionID, path: pathValidation.path, now: now)
            pathValidation.connectionID = replacement
            self.pathValidation = pathValidation
        }
    }
}

extension ConnectionCore {
    func handleRetireConnectionID(
        sequence: UInt64,
        packetDestinationID: QUICConnectionID,
        now: Nanoseconds
    ) throws(TransportError) {
        guard !self.originalSourceID.isEmpty, sequence <= self.localLastSequence else {
            throw TransportError(
                .protocolViolation,
                frameType: FrameType.retireConnectionID,
                reason: "RETIRE_CONNECTION_ID for unknown sequence"
            )
        }
        guard let index = self.localIDs.firstIndex(where: { $0.sequence == sequence }) else {
            return
        }
        guard self.localIDs[index].id != packetDestinationID else {
            throw TransportError(
                .protocolViolation,
                frameType: FrameType.retireConnectionID,
                reason: "RETIRE_CONNECTION_ID refers to the packet's destination connection ID"
            )
        }
        if self.localIDs[index].retiredAt == nil {
            self.localIDs[index].retiredAt = now
        }
    }

    func removeExpiredLocalIDs(timeout: Nanoseconds, now: Nanoseconds) {
        self.localIDs.removeAll { local in
            guard let retiredAt = local.retiredAt else {
                return false
            }
            return Time.elapsed(retiredAt, timeout, now)
        }
    }

    func enqueueNewConnectionIDsIfNeeded() {
        guard !self.originalSourceID.isEmpty, self.remoteTransportParameters != nil else {
            return
        }
        let count = self.localIDs.count
        guard count < Self.maxLocalConnectionIDs else {
            return
        }
        let inFlightLimit = Self.maxLocalConnectionIDs - self.localInFlightCount
        guard inFlightLimit > 0 else {
            return
        }
        let target = Int(Swift.min(
            UInt64(Self.maxLocalConnectionIDs),
            self.peerActiveConnectionIDLimit + UInt64(self.localRetiredCount)
        ))
        guard target > count else {
            return
        }
        for _ in 0..<Swift.min(inFlightLimit, target - count) {
            self.localLastSequence += 1
            var id = QUICConnectionID.random(length: self.originalSourceID.count)
            while self.localIDs.contains(where: { $0.id == id }) {
                id = QUICConnectionID.random(length: self.originalSourceID.count)
            }
            let token = QUICStatelessResetToken.random()
            self.localIDs.append(LocalConnectionID(id: id, sequence: self.localLastSequence, token: token))
            self.applicationSpace.pendingControlFrames.append(
                .newConnectionID(sequence: self.localLastSequence, retirePriorTo: 0, id: id, token: token)
            )
            self.localInFlightCount += 1
        }
    }
}

extension ConnectionCore {
    func pathValidationTimeout() -> Nanoseconds {
        return 3 * Swift.max(self.pto(for: self.applicationSpace), self.initialPTO)
    }

    func handlePathResponse(_ data: UInt64, now: Nanoseconds) throws(TransportError) {
        guard let pathValidation = self.pathValidation, pathValidation.validate(data) else {
            return
        }
        if !pathValidation.ignoresResult {
            if pathValidation.connectionID.sequence != self.active.connectionID.sequence
                || pathValidation.path != self.active.path {
                if !self.active.connectionID.id.isEmpty,
                   pathValidation.connectionID.sequence != self.active.connectionID.sequence {
                    self.retireActiveConnectionID(self.active.connectionID, path: self.active.path, now: now)
                }
                self.active = ActivePath(
                    connectionID: pathValidation.connectionID,
                    path: pathValidation.path,
                    isValidated: true,
                    maxUDPPayloadSize: QUICSettings.minimumUDPPayloadSize
                )
                self.congestionState.maxSendUDPPayloadSize = self.pathMaxSendUDPPayloadSize
                self.resetCongestionState(now: now)
            }
            self.active.isValidated = true
            if self.settings.isPMTUDEnabled {
                self.pathMTUDiscovery = nil
                self.startPMTUD()
            }
            self.emit(.pathValidated(pathValidation.path))
        }
        self.stopPathValidation(now: now)
    }

    func stopPathValidation(now: Nanoseconds) {
        guard let pathValidation = self.pathValidation else {
            return
        }
        if pathValidation.connectionID.sequence != self.active.connectionID.sequence {
            self.retireActiveConnectionID(pathValidation.connectionID, path: pathValidation.path, now: now)
        }
        self.pathValidation = nil
    }

    func abortPathValidation(now: Nanoseconds) {
        guard let pathValidation = self.pathValidation else {
            return
        }
        if !pathValidation.ignoresResult {
            self.emit(.pathValidationAborted(pathValidation.path))
        }
        self.stopPathValidation(now: now)
    }

    func failPathValidation(now: Nanoseconds) {
        guard let pathValidation = self.pathValidation else {
            return
        }
        if !pathValidation.ignoresResult {
            self.emit(.pathValidationFailed(pathValidation.path))
        }
        self.stopPathValidation(now: now)
    }
}

extension ConnectionCore {
    func startPMTUD() {
        guard self.settings.isPMTUDEnabled,
              self.pathMTUDiscovery == nil,
              self.isTLSHandshakeComplete,
              let remote = self.remoteTransportParameters else {
            return
        }
        let hardMax = Swift.min(
            Int(Swift.min(remote.maxUDPPayloadSize, UInt64(QUICSettings.maximumUDPPayloadSize))),
            self.settings.maxSendUDPPayloadSize
        )
        let discovery = PMTUDiscovery(
            probes: self.settings.pmtudProbes,
            currentMaxUDPPayloadSize: self.active.maxUDPPayloadSize,
            hardMaxUDPPayloadSize: hardMax,
            firstPacketNumber: self.applicationSpace.nextPacketNumber
        )
        if !discovery.isFinished {
            self.pathMTUDiscovery = discovery
        }
    }
}

extension ConnectionCore {
    func migrate(to path: QUICPath, immediately: Bool, now: QUICInstant) throws(QUICError) {
        let now = self.updateTimestamp(now.nanoseconds)
        guard self.state == .established,
              self.isHandshakeConfirmed,
              !self.active.connectionID.id.isEmpty,
              let remote = self.remoteTransportParameters else {
            throw QUICError.invalidState
        }
        guard !remote.isActiveMigrationDisabled else {
            throw QUICError.migrationDisabled
        }
        guard self.destinationIDs.hasUnused else {
            throw QUICError.connectionIDBlocked
        }
        guard self.active.path.local != path.local else {
            throw QUICError.pathUnchanged
        }
        self.abortPathValidation(now: now)
        guard let connectionID = self.destinationIDs.popUnused() else {
            throw QUICError.connectionIDBlocked
        }
        if immediately {
            self.pathMTUDiscovery = nil
            self.retireActiveConnectionID(self.active.connectionID, path: self.active.path, now: now)
            self.active = ActivePath(
                connectionID: connectionID,
                path: path,
                isValidated: false,
                maxUDPPayloadSize: QUICSettings.minimumUDPPayloadSize
            )
            self.congestionState.maxSendUDPPayloadSize = self.pathMaxSendUDPPayloadSize
            self.resetCongestionState(now: now)
        }
        self.pathValidation = PathValidation(
            connectionID: connectionID,
            path: path,
            timeout: self.pathValidationTimeout()
        )
    }
}
