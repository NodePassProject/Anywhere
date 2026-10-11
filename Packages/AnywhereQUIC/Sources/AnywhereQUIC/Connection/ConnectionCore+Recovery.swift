//
//  ConnectionCore+Recovery.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    func forEachSpace(_ body: (PacketNumberSpace) -> Void) {
        if let initialSpace = self.initialSpace {
            body(initialSpace)
        }
        if let handshakeSpace = self.handshakeSpace {
            body(handshakeSpace)
        }
        body(self.applicationSpace)
    }

    func handleACK(
        _ ack: ACKFrame,
        space: PacketNumberSpace,
        ackDelay: Nanoseconds,
        receivedAt: Nanoseconds,
        now: Nanoseconds
    ) throws(TransportError) {
        guard ack.largestAcknowledged < space.nextPacketNumber else {
            throw TransportError(.protocolViolation, frameType: FrameType.ack, reason: "acknowledged unsent packet")
        }
        space.ackTracker.onACKFrameAcknowledged(ack)
        if space.isApplication {
            self.confirmLocalKeyUpdate(acknowledgedLargest: ack.largestAcknowledged, now: now)
        }
        self.acknowledgedScratch.removeAll(keepingCapacity: true)
        let result = try space.sent.processACK(ack, state: &self.congestionState, into: &self.acknowledgedScratch)
        var summary = QUICAcknowledgementSummary(
            bytesDelivered: 0,
            bytesLost: 0,
            largestAcknowledgedSentAt: nil,
            rtt: nil
        )
        summary.deliveryRate = self.deliveryRateSampler.onACK(self.acknowledgedScratch, now: now)
        if result.hasAcknowledgedACKElicitingPacket, result.largestAcknowledgedSentAt != Time.never {
            let sample = Swift.max(receivedAt.subtractingClamped(result.largestAcknowledgedSentAt), Time.nanosecond)
            _ = self.congestionState.updateRTT(
                sample: sample,
                ackDelay: ackDelay,
                now: now,
                isHandshakeConfirmed: self.isHandshakeConfirmed,
                peerMaxACKDelay: self.peerMaxACKDelay
            )
            summary.rtt = Duration(nanoseconds: sample)
            summary.largestAcknowledgedSentAt = QUICInstant(nanoseconds: result.largestAcknowledgedSentAt)
        }
        for packet in self.acknowledgedScratch {
            self.processAcknowledgedFrames(of: packet, space: space)
            if packet.countsTowardCongestion {
                summary.bytesDelivered += UInt64(packet.size)
                self.congestionController.onPacketAcknowledged(
                    packet.info,
                    state: &self.congestionState,
                    now: QUICInstant(nanoseconds: now)
                )
            }
            if !packet.isProbe, packet.isACKEliciting {
                self.ptoCount = 0
            }
        }
        if !self.acknowledgedScratch.isEmpty {
            let loss = space.sent.detectLost(
                now: now,
                state: &self.congestionState,
                peerMaxACKDelay: self.peerMaxACKDelay,
                persistentCongestionStart: Swift.max(
                    self.handshakeConfirmedAt == Time.never ? 0 : self.handshakeConfirmedAt,
                    self.congestionState.firstRTTSampleTimeNanoseconds == Time.never
                        ? 0 : self.congestionState.firstRTTSampleTimeNanoseconds
                ),
                isApplicationSpace: space.isApplication
            )
            summary.bytesLost = loss.bytesLost
            self.handleLoss(loss, space: space, now: now)
            space.sent.probePacketsLeft = 0
            if self.ptoCount > 0, self.isServerAddressVerified {
                self.ptoCount = Swift.min(self.ptoCount, 2)
            }
            self.setLossDetectionTimer(now: now)
        }
        self.congestionController.onAcknowledgementReceived(
            summary,
            state: &self.congestionState,
            now: QUICInstant(nanoseconds: now)
        )
    }

    func processAcknowledgedFrames(of packet: SentPacket, space: PacketNumberSpace) {
        if packet.isPMTUDProbe,
           var discovery = self.pathMTUDiscovery,
           discovery.firstPacketNumber <= packet.packetNumber {
            discovery.probeSucceeded(size: packet.size)
            if self.active.maxUDPPayloadSize < packet.size {
                self.active.maxUDPPayloadSize = packet.size
                self.congestionState.maxSendUDPPayloadSize = self.pathMaxSendUDPPayloadSize
            }
            self.pathMTUDiscovery = discovery.isFinished ? nil : discovery
        }
        for frame in packet.frames {
            switch frame {
            case .stream(let id, let offset, let length, let fin):
                guard let stream = self.streams[QUICStreamID(rawValue: id)], stream.send != nil else {
                    continue
                }
                _ = stream.send!.markAcknowledged(offset: offset, length: length, fin: fin)
                stream.hasAcknowledgedStreamFrame = true
                self.notifyWritableIfNeeded(stream)
                self.closeStreamIfDone(stream)
            case .crypto(let offset, let length):
                _ = space.cryptoSend.markAcknowledged(offset: offset, length: length, fin: false)
            case .resetStream(let id):
                guard let stream = self.streams[QUICStreamID(rawValue: id)] else {
                    continue
                }
                stream.isResetStreamAcknowledged = true
                self.closeStreamIfDone(stream)
            case .retireConnectionID(let sequence):
                self.destinationIDs.untrackRetireSequence(sequence)
            case .newConnectionID:
                self.localInFlightCount = Swift.max(0, self.localInFlightCount - 1)
            default:
                break
            }
        }
    }

    func handleLoss(_ loss: SentPacketTracker.LossDetectionResult, space: PacketNumberSpace, now: Nanoseconds) {
        for packet in loss.lost {
            self.packetsLost += 1
            if packet.countsTowardCongestion, !packet.isPMTUDProbe {
                self.congestionController.onPacketLost(
                    packet.info,
                    state: &self.congestionState,
                    now: QUICInstant(nanoseconds: now)
                )
            }
            if !packet.isPTOReclaimed {
                self.reclaimFrames(packet.frames, space: space)
            }
        }
        if loss.bytesLost > 0 {
            let summary = QUICAcknowledgementSummary(
                bytesDelivered: 0,
                bytesLost: loss.bytesLost,
                largestAcknowledgedSentAt: nil,
                rtt: nil
            )
            self.congestionController.onCongestionEvent(
                largestLostSentAt: QUICInstant(nanoseconds: loss.latestLostSentAt),
                summary: summary,
                state: &self.congestionState,
                now: QUICInstant(nanoseconds: now)
            )
        }
        if loss.hasPersistentCongestion {
            self.congestionState.resetRecovery()
            self.congestionController.onPersistentCongestion(
                state: &self.congestionState,
                now: QUICInstant(nanoseconds: now)
            )
        }
    }

    func reclaimFrames(_ frames: some Sequence<SentFrame>, space: PacketNumberSpace) {
        for frame in frames {
            switch frame {
            case .crypto(let offset, let length):
                space.cryptoSend.markLost(offset: offset, length: length, fin: false)
            case .stream(let id, let offset, let length, let fin):
                guard let stream = self.streams[QUICStreamID(rawValue: id)],
                      stream.send != nil,
                      !stream.hasSentResetStream else {
                    continue
                }
                stream.send!.markLost(offset: offset, length: length, fin: fin)
                if stream.hasPendingSendData {
                    self.enqueueStream(stream)
                }
            case .resetStream(let id):
                guard let stream = self.streams[QUICStreamID(rawValue: id)],
                      stream.hasSentResetStream,
                      !stream.isResetStreamAcknowledged,
                      !stream.isAllSendDataAcknowledged else {
                    continue
                }
                stream.isResetStreamPending = true
                self.enqueueStream(stream)
            case .stopSending(let id):
                guard let stream = self.streams[QUICStreamID(rawValue: id)],
                      stream.hasSentStopSending,
                      !(stream.isReadClosed && stream.receiveOffset == stream.receiveLastOffset) else {
                    continue
                }
                stream.isStopSendingPending = true
                self.enqueueStream(stream)
            case .maxData(let value):
                if value >= self.receiveMaxOffset {
                    self.applicationSpace.pendingControlFrames.append(.maxData(value))
                }
            case .maxStreamData(let id, let maximum):
                guard let stream = self.streams[QUICStreamID(rawValue: id)],
                      !stream.isReadClosed,
                      !stream.hasSentStopSending,
                      maximum >= stream.receiveMaxOffset else {
                    continue
                }
                self.applicationSpace.pendingControlFrames.append(.maxStreamData(id: id, maximum: maximum))
            case .maxStreams(let bidirectional, let maximum):
                let current = bidirectional ? self.remoteBidirectionalMaxStreams : self.remoteUnidirectionalMaxStreams
                if maximum >= current {
                    self.applicationSpace.pendingControlFrames.append(
                        .maxStreams(bidirectional: bidirectional, maximum: maximum)
                    )
                }
            case .dataBlocked(let limit):
                if limit == self.sendMaxOffset {
                    self.applicationSpace.pendingControlFrames.append(.dataBlocked(limit))
                }
            case .streamDataBlocked(let id, let limit):
                guard let stream = self.streams[QUICStreamID(rawValue: id)],
                      !stream.isWriteClosed,
                      limit == stream.sendMaxOffset else {
                    continue
                }
                self.applicationSpace.pendingControlFrames.append(.streamDataBlocked(id: id, limit: limit))
            case .streamsBlocked(let bidirectional, let limit):
                self.applicationSpace.pendingControlFrames.append(
                    .streamsBlocked(bidirectional: bidirectional, limit: limit)
                )
            case .newConnectionID(let sequence):
                guard let local = self.localIDs.first(where: { $0.sequence == sequence }), !local.isRetired else {
                    continue
                }
                self.applicationSpace.pendingControlFrames.append(
                    .newConnectionID(sequence: sequence, retirePriorTo: 0, id: local.id, token: local.token)
                )
            case .retireConnectionID(let sequence):
                self.applicationSpace.pendingControlFrames.append(.retireConnectionID(sequence: sequence))
            case .ack, .ping, .padding, .pathChallenge, .pathResponse, .connectionClose:
                break
            }
        }
    }

    func isControlFrameRelevant(_ frame: ControlFrame) -> Bool {
        switch frame {
        case .maxData(let value):
            return value >= self.receiveMaxOffset
        case .maxStreamData(let id, let maximum):
            guard let stream = self.streams[QUICStreamID(rawValue: id)] else {
                return false
            }
            return !stream.isReadClosed && !stream.hasSentStopSending && maximum >= stream.receiveMaxOffset
        case .maxStreams(let bidirectional, let maximum):
            return maximum >= (bidirectional ? self.remoteBidirectionalMaxStreams : self.remoteUnidirectionalMaxStreams)
        case .dataBlocked(let limit):
            return limit == self.sendMaxOffset
        case .streamDataBlocked(let id, let limit):
            guard let stream = self.streams[QUICStreamID(rawValue: id)] else {
                return false
            }
            return !stream.isWriteClosed && limit == stream.sendMaxOffset
        case .streamsBlocked:
            return true
        case .newConnectionID(let sequence, _, _, _):
            return self.localIDs.contains { $0.sequence == sequence && !$0.isRetired }
        case .retireConnectionID:
            return true
        case .resetStream(let id, _, _):
            guard let stream = self.streams[QUICStreamID(rawValue: id)] else {
                return false
            }
            return stream.hasSentResetStream && !stream.isResetStreamAcknowledged && !stream.isAllSendDataAcknowledged
        case .stopSending(let id, _):
            guard let stream = self.streams[QUICStreamID(rawValue: id)] else {
                return false
            }
            return stream.hasSentStopSending
                && !(stream.isReadClosed && stream.receiveOffset == stream.receiveLastOffset)
        }
    }

    func earliestLossTime() -> (time: Nanoseconds, space: PacketNumberSpace?) {
        var earliest: Nanoseconds = Time.never
        var result: PacketNumberSpace?
        self.forEachSpace { space in
            if space.sent.lossTime < earliest {
                earliest = space.sent.lossTime
                result = space
            }
        }
        return (earliest, result)
    }

    func setLossDetectionTimer(now: Nanoseconds) {
        let (lossTime, _) = self.earliestLossTime()
        if lossTime != Time.never {
            self.lossDetectionTimer = lossTime
            return
        }
        let initialEliciting = self.initialSpace?.sent.ptoElicitingCount ?? 0
        let handshakeEliciting = self.handshakeSpace?.sent.ptoElicitingCount ?? 0
        let applicationEliciting = self.applicationSpace.sent.ptoElicitingCount
        if initialEliciting == 0, handshakeEliciting == 0, applicationEliciting == 0 || !self.isHandshakeConfirmed,
           self.isServerAddressVerified || self.isHandshakeConfirmed {
            self.lossDetectionTimer = Time.never
            self.ptoCount = 0
            return
        }
        self.lossDetectionTimer = self.earliestPTOExpiry(now: now)
    }

    private func earliestPTOExpiry(now: Nanoseconds) -> Nanoseconds {
        let base = self.congestionState.pto(maxACKDelay: 0)
        let duration = self.ptoCount >= 60
            ? Nanoseconds.max
            : base.multipliedReportingOverflow(by: 1 << UInt64(self.ptoCount)).partialValue
        var earliest: Nanoseconds = Time.never
        self.forEachSpace { space in
            guard space.sent.ptoElicitingCount > 0, space.lastSentAt != Time.never else {
                return
            }
            if space.isApplication, !self.isHandshakeConfirmed {
                return
            }
            var expiry = space.lastSentAt.addingClamped(duration)
            if space.isApplication {
                expiry = expiry.addingClamped(
                    self.peerMaxACKDelay.multipliedReportingOverflow(
                        by: 1 << UInt64(Swift.min(self.ptoCount, 30))
                    ).partialValue
                )
            }
            earliest = Swift.min(earliest, expiry)
        }
        if earliest == Time.never {
            return now.addingClamped(duration)
        }
        return earliest
    }

    func onLossDetectionTimer(now: Nanoseconds) {
        switch self.state {
        case .closing, .draining, .closed:
            self.lossDetectionTimer = Time.never
            self.ptoCount = 0
            return
        default:
            break
        }
        guard self.lossDetectionTimer != Time.never else {
            return
        }
        let (lossTime, lossSpace) = self.earliestLossTime()
        if lossTime != Time.never, let lossSpace {
            let loss = lossSpace.sent.detectLost(
                now: now,
                state: &self.congestionState,
                peerMaxACKDelay: self.peerMaxACKDelay,
                persistentCongestionStart: Swift.max(
                    self.handshakeConfirmedAt == Time.never ? 0 : self.handshakeConfirmedAt,
                    self.congestionState.firstRTTSampleTimeNanoseconds == Time.never
                        ? 0 : self.congestionState.firstRTTSampleTimeNanoseconds
                ),
                isApplicationSpace: lossSpace.isApplication
            )
            self.handleLoss(loss, space: lossSpace, now: now)
            self.setLossDetectionTimer(now: now)
            return
        }
        if !self.isTLSHandshakeComplete {
            if let handshakeSpace = self.handshakeSpace, handshakeSpace.writeKeys != nil {
                handshakeSpace.sent.probePacketsLeft = 1
            } else if let initialSpace = self.initialSpace {
                initialSpace.sent.probePacketsLeft = 1
            }
        } else if let initialSpace = self.initialSpace, initialSpace.sent.ptoElicitingCount > 0 {
            initialSpace.sent.probePacketsLeft = 1
        } else if let handshakeSpace = self.handshakeSpace, handshakeSpace.sent.ptoElicitingCount > 0 {
            handshakeSpace.sent.probePacketsLeft = 2
        } else {
            self.applicationSpace.sent.probePacketsLeft = 2
        }
        self.ptoCount = Swift.min(self.ptoCount + 1, Recovery.maxPTOCount)
        self.setLossDetectionTimer(now: now)
    }

    func resetCongestionState(now: Nanoseconds) {
        self.deliveryRateSampler = DeliveryRateSampler()
        self.congestionState.resetCongestion()
        self.congestionController.reset(state: &self.congestionState, now: QUICInstant(nanoseconds: now))
        self.forEachSpace { space in
            space.sent.resetCongestionState(nextPacketNumber: space.nextPacketNumber)
        }
        self.pacer.reset()
    }

    var hasHandshakeProbesLeft: Bool {
        return (self.initialSpace?.sent.probePacketsLeft ?? 0) > 0
            || (self.handshakeSpace?.sent.probePacketsLeft ?? 0) > 0
    }

    var hasHandshakeRemnants: Bool {
        if !self.isTLSHandshakeComplete {
            return true
        }
        if let initialSpace = self.initialSpace,
           initialSpace.sent.ptoElicitingCount > 0 || initialSpace.hasPendingCryptoData {
            return true
        }
        if let handshakeSpace = self.handshakeSpace,
           handshakeSpace.sent.ptoElicitingCount > 0
               || handshakeSpace.hasPendingCryptoData
               || handshakeSpace.ackTracker.hasPendingACK {
            return true
        }
        return false
    }

    func idleExpiry() -> Nanoseconds {
        let local = self.localTransportParameters.maxIdleTimeout.clampedNanoseconds
        let remote = self.peerMaxIdleTimeout
        var timeout: Nanoseconds
        if !self.isTLSHandshakeComplete || remote == 0 || (local != 0 && local < remote) {
            timeout = local
        } else {
            timeout = remote
        }
        if timeout == 0 {
            return Time.never
        }
        let space = self.isTLSHandshakeComplete ? self.applicationSpace : (self.handshakeSpace ?? self.applicationSpace)
        timeout = Swift.max(timeout, 3 * self.pto(for: space))
        return self.idleTimestamp.addingClamped(timeout)
    }

    func handshakeExpiry() -> Nanoseconds {
        guard !self.isTLSHandshakeComplete, let timeout = self.settings.handshakeTimeout else {
            return Time.never
        }
        return self.startTime.addingClamped(timeout.clampedNanoseconds)
    }

    func ackDelayExpiry() -> Nanoseconds {
        var earliest: Nanoseconds = Time.never
        if let initialSpace = self.initialSpace {
            earliest = Swift.min(earliest, initialSpace.ackTracker.ackDelayExpiry(maxACKDelay: 0))
        }
        if let handshakeSpace = self.handshakeSpace {
            earliest = Swift.min(earliest, handshakeSpace.ackTracker.ackDelayExpiry(maxACKDelay: 0))
        }
        earliest = Swift.min(
            earliest,
            self.applicationSpace.ackTracker.ackDelayExpiry(maxACKDelay: self.computeACKDelay())
        )
        return earliest
    }

    func connectionIDExpiry() -> Nanoseconds {
        var earliest: Nanoseconds = Time.never
        let pto = self.pto(for: self.applicationSpace)
        let retirement = self.destinationIDs.nextRetirementExpiry
        if retirement != Time.never {
            earliest = Swift.min(earliest, retirement.addingClamped(pto))
        }
        for local in self.localIDs {
            if let retiredAt = local.retiredAt {
                earliest = Swift.min(earliest, retiredAt.addingClamped(pto))
            }
        }
        return earliest
    }

    func expiry(of kind: QUICTimeoutKind) -> Nanoseconds {
        switch self.state {
        case .closed:
            return Time.never
        case .closing, .draining:
            return kind == .closing ? self.closingEndsAt : Time.never
        case .handshaking, .established:
            break
        }
        switch kind {
        case .pacing:
            return self.pacer.nextSendTime
        case .ackDelay:
            return self.ackDelayExpiry()
        case .lossDetection:
            return self.lossDetectionTimer
        case .pathValidation:
            return self.pathValidation?.nextExpiry ?? Time.never
        case .pathMTUDiscovery:
            return self.pathMTUDiscovery?.expiry ?? Time.never
        case .connectionIDs:
            return self.connectionIDExpiry()
        case .keepAlive:
            return self.keepAliveExpiry
        case .handshake:
            return self.handshakeExpiry()
        case .idle:
            return self.idleExpiry()
        case .closing:
            return Time.never
        }
    }

    func computeExpiry() -> Nanoseconds {
        var earliest: Nanoseconds = Time.never
        for kind in QUICTimeoutKind.allCases {
            earliest = Swift.min(earliest, self.expiry(of: kind))
        }
        return earliest
    }

    var nextTimeout: QUICInstant? {
        let expiry = self.computeExpiry()
        return expiry == Time.never ? nil : QUICInstant(nanoseconds: expiry)
    }

    func nextTimeout(_ kind: QUICTimeoutKind) -> QUICInstant? {
        let expiry = self.expiry(of: kind)
        return expiry == Time.never ? nil : QUICInstant(nanoseconds: expiry)
    }

    func handleTimeout(now: QUICInstant) {
        let now = self.updateTimestamp(now.nanoseconds)
        switch self.state {
        case .closed:
            return
        case .closing, .draining:
            if self.closingEndsAt <= now {
                self.enterClosed(reason: self.closeReason ?? .idleTimeout, emitEvent: false)
            }
            return
        case .handshaking, .established:
            break
        }
        if self.idleExpiry() <= now {
            self.enterClosed(reason: .idleTimeout, emitEvent: true)
            return
        }
        if let initialSpace = self.initialSpace {
            initialSpace.ackTracker.cancelExpiredTimer(maxACKDelay: 0, now: now)
        }
        if let handshakeSpace = self.handshakeSpace {
            handshakeSpace.ackTracker.cancelExpiredTimer(maxACKDelay: 0, now: now)
        }
        self.applicationSpace.ackTracker.cancelExpiredTimer(maxACKDelay: self.computeACKDelay(), now: now)
        self.cancelExpiredKeepAliveTimer(now: now)
        self.pacer.cancelExpired(at: now)
        if var pathValidation = self.pathValidation {
            pathValidation.cancelExpiredTimer(now: now)
            self.pathValidation = pathValidation
        }
        if var discovery = self.pathMTUDiscovery {
            discovery.handleExpiry(now: now)
            self.pathMTUDiscovery = discovery.isFinished ? nil : discovery
        }
        if self.lossDetectionTimer <= now {
            self.onLossDetectionTimer(now: now)
        }
        let pto = self.pto(for: self.applicationSpace)
        self.destinationIDs.removeStaleRetired(timeout: pto, now: now)
        self.removeExpiredLocalIDs(timeout: pto, now: now)
        if self.handshakeExpiry() <= now {
            self.enterClosed(reason: .handshakeTimeout, emitEvent: true)
        }
    }

    func finishWriting(now: QUICInstant) {
        let now = self.updateTimestamp(now.nanoseconds)
        self.pacer.finishBatch(
            now: now,
            pacingRate: self.congestionState.pacingRate,
            sendQuantum: self.congestionState.sendQuantum
        )
    }
}
