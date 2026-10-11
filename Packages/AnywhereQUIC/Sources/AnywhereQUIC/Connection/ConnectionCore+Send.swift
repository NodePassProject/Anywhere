//
//  ConnectionCore+Send.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    struct PacketFlags {
        var isACKEliciting = false
        var isPTOEliciting = false
        var isRetransmittable = false
        var isProbe = false
        var isPMTUDProbe = false
        var frames = SentFrames()

        mutating func addRetransmittable(_ frame: SentFrame) {
            self.frames.append(frame)
            self.isACKEliciting = true
            self.isPTOEliciting = true
            self.isRetransmittable = true
        }
    }

    func write(into buffer: UnsafeMutableBufferPointer<UInt8>, now: QUICInstant) -> QUICOutgoingDatagram? {
        let now = self.updateTimestamp(now.nanoseconds)
        switch self.state {
        case .closed, .draining:
            return nil
        case .closing:
            return self.writeClosePacketIfNeeded(into: buffer, now: now)
        case .handshaking, .established:
            break
        }
        guard !self.isPacketNumberExhausted else {
            self.enterClosed(reason: .packetNumberExhausted, emitEvent: true)
            return nil
        }
        do {
            return try self.writeDatagram(into: buffer, now: now)
        } catch {
            self.closeLocally(error, now: now)
        }
        return self.writeClosePacketIfNeeded(into: buffer, now: now)
    }

    func write(now: QUICInstant) -> (datagram: Data, path: QUICPath)? {
        var storage = [UInt8](repeating: 0, count: self.settings.maxSendUDPPayloadSize)
        let result = storage.withUnsafeMutableBufferPointer { self.write(into: $0, now: now) }
        guard let result else {
            return nil
        }
        return (Data(storage.prefix(result.count)), result.path)
    }

    private func allowsPacedSending(at now: Nanoseconds) -> Bool {
        return self.pacer.allowsSending(at: now) && self.pacer.pendingBytes < self.congestionState.sendQuantum
    }

    var isPacketNumberExhausted: Bool {
        return (self.initialSpace?.nextPacketNumber ?? 0) > PacketNumber.max
            || (self.handshakeSpace?.nextPacketNumber ?? 0) > PacketNumber.max
            || self.applicationSpace.nextPacketNumber > PacketNumber.max
    }

    private func writeDatagram(
        into buffer: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> QUICOutgoingDatagram? {
        let maxLength = Swift.min(buffer.count, self.pathMaxSendUDPPayloadSize)
        guard maxLength > 0 else {
            return nil
        }
        let destination = UnsafeMutableBufferPointer(rebasing: buffer[0..<maxLength])
        var written = 0
        var requirePadding = false
        if self.state == .handshaking {
            guard self.allowsPacedSending(at: now) else {
                let count = try self.writeHandshakeACKPackets(into: destination, now: now)
                return count > 0 ? QUICOutgoingDatagram(count: count, path: self.active.path) : nil
            }
            let count = try self.writeClientHandshake(into: destination, now: now)
            if self.state != .established {
                return count > 0 ? QUICOutgoingDatagram(count: count, path: self.active.path) : nil
            }
            if count > 0 {
                if PacketType.longType(fromFirstByte: destination[0]) == .initial {
                    requirePadding = true
                }
                written = count
            }
        } else {
            guard self.allowsPacedSending(at: now) else {
                let count = try self.writeACKOnlyPacket(space: self.applicationSpace, into: destination, now: now)
                return count > 0 ? QUICOutgoingDatagram(count: count, path: self.active.path) : nil
            }
        }
        guard self.applicationSpace.writeKeys != nil else {
            return written > 0 ? QUICOutgoingDatagram(count: written, path: self.active.path) : nil
        }
        try self.prepareKeyUpdate(now: now)
        var remaining = maxLength - written
        let congestionBlocked = self.isCongestionWindowExhausted && self.applicationSpace.sent.probePacketsLeft == 0
        if congestionBlocked {
            remaining = 0
        } else if written == 0 {
            if let response = try self.writePathResponsePacket(into: destination, now: now) {
                return response
            }
            if self.pathValidation != nil,
               let challenge = try self.writePathChallengePacket(into: destination, now: now) {
                return challenge
            }
            if self.pathMTUDiscovery != nil,
               self.active.isValidated,
               self.handshakeSpace?.hasPendingCryptoData != true {
                let count = try self.writePMTUDProbe(into: buffer, now: now)
                if count > 0 {
                    return QUICOutgoingDatagram(count: count, path: self.active.path)
                }
            }
        }
        if written == 0, self.hasHandshakeRemnants {
            var handshakeLength = remaining
            if self.hasHandshakeProbesLeft
                || ((self.handshakeSpace?.sent.ptoElicitingCount ?? 0) == 0
                    && self.handshakeSpace?.hasPendingCryptoData == true) {
                handshakeLength = maxLength
            }
            let count = try self.writeHandshakePackets(into: destination, maxLength: handshakeLength, now: now)
            if count > 0 {
                if PacketType.longType(fromFirstByte: destination[0]) == .initial {
                    requirePadding = true
                }
                written = count
                remaining = Swift.max(0, handshakeLength - count)
                if self.isCongestionWindowExhausted, self.applicationSpace.sent.probePacketsLeft == 0 {
                    return QUICOutgoingDatagram(count: written, path: self.active.path)
                }
            } else if handshakeLength == 0 {
                let ackCount = try self.writeHandshakeACKPackets(into: destination, now: now)
                if ackCount > 0 {
                    return QUICOutgoingDatagram(count: ackCount, path: self.active.path)
                }
            }
        }
        let count = try self.writeApplicationPacket(
            into: destination,
            offset: written,
            maxLength: remaining,
            requirePadding: requirePadding,
            now: now
        )
        if count == 0, written == 0 {
            let ackCount = try self.writeACKOnlyPacket(space: self.applicationSpace, into: destination, now: now)
            return ackCount > 0 ? QUICOutgoingDatagram(count: ackCount, path: self.active.path) : nil
        }
        written += count
        return written > 0 ? QUICOutgoingDatagram(count: written, path: self.active.path) : nil
    }

    private func writeClientHandshake(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        switch self.handshakePhase {
        case .initial:
            try self.startHandshakeIfNeeded(now: now)
            let count = try self.writeHandshakePacket(
                type: .initial,
                into: destination,
                offset: 0,
                maxLength: destination.count,
                requirePadding: false,
                now: now
            )
            if count > 0 {
                self.handshakePhase = .waitingForHandshake
            }
            return count
        case .waitingForHandshake:
            var written = 0
            if self.hasHandshakeProbesLeft || !self.isCongestionWindowExhausted {
                written = try self.writeHandshakePackets(into: destination, maxLength: destination.count, now: now)
            }
            if !self.isTLSHandshakeComplete {
                if written == 0 {
                    written = try self.writeHandshakeACKPackets(into: destination, now: now)
                }
                return written
            }
            guard self.isHandshakeComplete, self.hasReceivedTransportParameters else {
                return written
            }
            self.state = .established
            self.startPMTUD()
            return written
        }
    }

    private func writeHandshakePackets(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        maxLength: Int,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        var written = 0
        var requirePadding = false
        if let handshakeSpace = self.handshakeSpace,
           handshakeSpace.writeKeys != nil,
           let initialSpace = self.initialSpace,
           !initialSpace.ackTracker.requiresACK(maxACKDelay: 0, now: now),
           handshakeSpace.ackTracker.requiresACK(maxACKDelay: 0, now: now)
               || handshakeSpace.sent.probePacketsLeft > 0 {
            self.discardInitialSpace(now: now)
        } else if self.initialSpace != nil {
            let count = try self.writeHandshakePacket(
                type: .initial,
                into: destination,
                offset: 0,
                maxLength: maxLength,
                requirePadding: false,
                now: now
            )
            if count > 0 {
                written = count
                requirePadding = true
            }
        }
        let count = try self.writeHandshakePacket(
            type: .handshake,
            into: destination,
            offset: written,
            maxLength: maxLength - written,
            requirePadding: requirePadding,
            now: now
        )
        written += count
        if let handshakeSpace = self.handshakeSpace, handshakeSpace.writeKeys != nil, count > 0 {
            self.discardInitialSpace(now: now)
        }
        return written
    }

    private func writeHandshakeACKPackets(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        guard let handshakeSpace = self.handshakeSpace, handshakeSpace.writeKeys != nil else {
            return 0
        }
        return try self.writeACKOnlyPacket(space: handshakeSpace, into: destination, now: now)
    }

    private func canSendNextPacket(left: Int, minimumPayload: Int) -> Bool {
        return left >= 11
            + self.active.connectionID.id.count
            + self.originalSourceID.count
            + minimumPayload
            + AEADAlgorithm.tagLength
    }

    private func shouldPadHandshakePacket(
        type: PacketType,
        left: Int,
        isACKEliciting: Bool,
        requirePadding: Bool
    ) -> Bool {
        if type == .initial {
            if let handshakeSpace = self.handshakeSpace,
               handshakeSpace.writeKeys != nil,
               handshakeSpace.sent.probePacketsLeft > 0
                   || handshakeSpace.hasPendingCryptoData
                   || handshakeSpace.ackTracker.hasPendingACK {
                return !self.canSendNextPacket(left: left, minimumPayload: Self.minimumCoalescedPayload)
            }
            return true
        }
        if !requirePadding {
            return self.applicationSpace.writeKeys != nil
                && !self.canSendNextPacket(left: left, minimumPayload: Self.minimumCoalescedPayload)
        }
        guard self.applicationSpace.writeKeys != nil else {
            return true
        }
        if self.isCongestionWindowExhausted, self.applicationSpace.sent.probePacketsLeft == 0 {
            return true
        }
        return !self.canSendNextPacket(left: left, minimumPayload: Self.minimumCoalescedPayload)
    }

    private func writeHandshakePacket(
        type: PacketType,
        into destination: UnsafeMutableBufferPointer<UInt8>,
        offset: Int,
        maxLength: Int,
        requirePadding: Bool,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        let space: PacketNumberSpace?
        switch type {
        case .initial:
            space = self.initialSpace
        case .handshake:
            space = self.handshakeSpace
        default:
            return 0
        }
        guard let space, let keys = space.writeKeys, maxLength > 0, offset + maxLength <= destination.count else {
            return 0
        }
        let region = UnsafeMutableBufferPointer(rebasing: destination[offset..<offset + maxLength])
        guard var builder = PacketBuilder(
            buffer: region,
            type: type,
            version: self.version,
            destinationID: self.active.connectionID.id,
            sourceID: self.originalSourceID,
            token: type == .initial ? self.retryToken : [],
            packetNumber: space.nextPacketNumber,
            packetNumberLength: space.selectPacketNumberLength(),
            keyPhase: false
        ) else {
            return 0
        }
        var flags = PacketFlags()
        if let ack = space.ackTracker.makeACKFrame(
            now: now,
            ackDelay: 0,
            ackDelayExponent: QUICTransportParameters.defaultACKDelayExponent,
            includeDelay: false
        ) {
            if builder.withWriter({ $0.writeACK(ack) }) {
                space.ackTracker.commitACK()
                space.ackTracker.onACKSent(
                    packetNumber: space.nextPacketNumber,
                    largestAcknowledged: ack.largestAcknowledged
                )
                flags.frames.append(.ack(largestAcknowledged: ack.largestAcknowledged))
            }
        }
        while true {
            self.writeCryptoFrames(space: space, builder: &builder, flags: &flags)
            if !flags.isACKEliciting, space.sent.retransmittableCount > 0, space.sent.probePacketsLeft > 0 {
                let reclaimed = space.sent.reclaimOnPTO(count: type == .initial ? 2 : 1)
                if !reclaimed.isEmpty {
                    self.reclaimFrames(reclaimed, space: space)
                    continue
                }
                if space.sent.ptoElicitingCount == 0, self.isServerAddressVerified {
                    space.sent.probePacketsLeft = 0
                    self.setLossDetectionTimer(now: now)
                }
            }
            break
        }
        if !flags.isACKEliciting, space.sent.probePacketsLeft > 0, builder.withWriter({ $0.writePing() }) {
            flags.isACKEliciting = true
            flags.isProbe = true
            flags.frames.append(.ping)
        }
        if !builder.isEmpty {
            if !flags.isACKEliciting {
                if Time.elapsed(space.nonACKElicitingStart, self.congestionState.smoothedRTTNanoseconds, now),
                   builder.withWriter({ $0.writePing() }) {
                    flags.isACKEliciting = true
                    flags.frames.append(.ping)
                    space.nonACKElicitingStart = Time.never
                } else if space.nonACKElicitingStart == Time.never {
                    space.nonACKElicitingStart = now
                }
            } else {
                space.nonACKElicitingStart = Time.never
            }
        }
        if builder.isEmpty, !requirePadding {
            return 0
        }
        var padded = false
        if self.shouldPadHandshakePacket(
            type: type,
            left: builder.writableBytes,
            isACKEliciting: flags.isACKEliciting,
            requirePadding: requirePadding
        ) {
            let padding = builder.pad(toPacketLength: Swift.max(QUICSettings.minimumUDPPayloadSize - offset, 0))
            padded = padding > 0 || flags.isACKEliciting
        } else if builder.isEmpty {
            return 0
        } else {
            let padding = builder.pad(toPacketLength: self.minimumPacketLength)
            padded = padding > 0 && flags.isACKEliciting
        }
        let length = builder.finish(keys: keys)
        if flags.isACKEliciting || padded {
            self.recordSentPacket(space: space, length: length, flags: flags, now: now)
        }
        self.finishPacket(space: space, length: length, isACKEliciting: flags.isACKEliciting, now: now)
        return length
    }

    private func writeCryptoFrames(space: PacketNumberSpace, builder: inout PacketBuilder, flags: inout PacketFlags) {
        if space.level == .initial, self.crumblesInitialCrypto {
            self.writeCrumbledCryptoFrames(space: space, builder: &builder, flags: &flags)
            return
        }
        while space.cryptoSend.hasPendingData, builder.writableBytes > 0 {
            guard let segment = space.cryptoSend.nextSegment(maxLength: Int.max), segment.length > 0 else {
                break
            }
            let capacity = OutputBuffer.cryptoDataCapacity(
                offset: segment.offset,
                available: builder.writableBytes,
                wanted: segment.length
            )
            guard let capacity, capacity > 0 else {
                break
            }
            let piece = SendBuffer.Segment(offset: segment.offset, length: capacity, fin: false)
            let wrote = space.cryptoSend.withBytes(offset: piece.offset, length: piece.length) { bytes in
                return builder.withWriter { $0.writeCrypto(offset: piece.offset, data: bytes) }
            }
            guard wrote else {
                break
            }
            space.cryptoSend.markSent(piece)
            flags.addRetransmittable(.crypto(offset: piece.offset, length: piece.length))
        }
    }

    private func writeCrumbledCryptoFrames(
        space: PacketNumberSpace,
        builder: inout PacketBuilder,
        flags: inout PacketFlags
    ) {
        var frames: [CrumbledFrame] = []
        while space.cryptoSend.hasPendingData,
              let crumbled = self.crumbleInitialCrypto(space: space, left: builder.writableBytes, into: &frames) {
            for frame in frames {
                switch frame {
                case .ping:
                    precondition(builder.withWriter { $0.writePing() })
                case .padding(let count):
                    precondition(builder.withWriter { $0.writePadding(count) })
                case .crypto(let offset, let length):
                    let wrote = space.cryptoSend.withBytes(offset: offset, length: length) { bytes in
                        return builder.withWriter { $0.writeCrypto(offset: offset, data: bytes) }
                    }
                    precondition(wrote)
                }
            }
            let popped = crumbled.popped
            let poppedLength = Int(popped.upperBound - popped.lowerBound)
            space.cryptoSend.markSent(SendBuffer.Segment(offset: popped.lowerBound, length: poppedLength, fin: false))
            guard let deferred = crumbled.deferred else {
                flags.addRetransmittable(.crypto(offset: popped.lowerBound, length: poppedLength))
                continue
            }
            let deferredLength = Int(deferred.upperBound - deferred.lowerBound)
            space.cryptoSend.markLost(offset: deferred.lowerBound, length: deferredLength, fin: false)
            flags.addRetransmittable(.crypto(
                offset: popped.lowerBound,
                length: Int(deferred.lowerBound - popped.lowerBound)
            ))
            if deferred.upperBound < popped.upperBound {
                flags.addRetransmittable(.crypto(
                    offset: deferred.upperBound,
                    length: Int(popped.upperBound - deferred.upperBound)
                ))
            }
        }
    }

    private func writeACKOnlyPacket(
        space: PacketNumberSpace,
        into destination: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        guard let keys = space.writeKeys else {
            return 0
        }
        let ackDelay = space.isApplication ? self.computeACKDelay() : 0
        let exponent = space.isApplication
            ? self.localTransportParameters.ackDelayExponent
            : QUICTransportParameters.defaultACKDelayExponent
        guard let ack = space.ackTracker.makeACKFrame(
            now: now,
            ackDelay: ackDelay,
            ackDelayExponent: exponent,
            includeDelay: space.isApplication
        ) else {
            return 0
        }
        let type: PacketType = space.level == .initial ? .initial : space.level == .handshake ? .handshake : .oneRTT
        guard var builder = PacketBuilder(
            buffer: destination,
            type: type,
            version: self.version,
            destinationID: self.active.connectionID.id,
            sourceID: self.originalSourceID,
            token: type == .initial ? self.retryToken : [],
            packetNumber: space.nextPacketNumber,
            packetNumberLength: space.selectPacketNumberLength(),
            keyPhase: space.isApplication && self.keyUpdate.currentPhase
        ) else {
            return 0
        }
        guard builder.withWriter({ $0.writeACK(ack) }) else {
            return 0
        }
        space.ackTracker.commitACK()
        space.ackTracker.onACKSent(packetNumber: space.nextPacketNumber, largestAcknowledged: ack.largestAcknowledged)
        if space.isApplication {
            self.confirmRemoteKeyUpdate(acknowledgedLargest: ack.largestAcknowledged, now: now)
        }
        builder.pad(toPacketLength: self.minimumPacketLength)
        let length = builder.finish(keys: keys)
        if space.isApplication {
            self.keyUpdate.encryptionCount += 1
        }
        self.finishPacket(space: space, length: length, isACKEliciting: false, now: now)
        return length
    }

    private func writeApplicationPacket(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        offset: Int,
        maxLength: Int,
        requirePadding: Bool,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        guard maxLength >= self.minimumPacketLength, offset + maxLength <= destination.count else {
            return 0
        }
        let space = self.applicationSpace
        guard let keys = space.writeKeys else {
            return 0
        }
        if self.isHandshakeComplete {
            self.enqueueNewConnectionIDsIfNeeded()
        }
        let region = UnsafeMutableBufferPointer(rebasing: destination[offset..<offset + maxLength])
        guard var builder = PacketBuilder(
            buffer: region,
            type: .oneRTT,
            version: self.version,
            destinationID: self.active.connectionID.id,
            sourceID: QUICConnectionID(),
            token: [],
            packetNumber: space.nextPacketNumber,
            packetNumberLength: space.selectPacketNumberLength(),
            keyPhase: self.keyUpdate.currentPhase
        ) else {
            return 0
        }
        var flags = PacketFlags()
        var requirePadding = requirePadding
        if let first = self.pendingPathResponses.first, first.path == self.active.path {
            if builder.withWriter({ $0.writePathResponse(first.data) }) {
                self.pendingPathResponses.removeFirst()
                flags.isACKEliciting = true
                flags.frames.append(.pathResponse(first.data))
                requirePadding = true
                if builder.withWriter({ $0.writePing() }) {
                    flags.frames.append(.ping)
                }
            }
        }
        var ackIncluded = false
        if let ack = space.ackTracker.makeACKFrame(
            now: now,
            ackDelay: self.computeACKDelay(),
            ackDelayExponent: self.localTransportParameters.ackDelayExponent,
            includeDelay: true
        ) {
            if builder.withWriter({ $0.writeACK(ack) }) {
                space.ackTracker.commitACK()
                space.ackTracker.onACKSent(
                    packetNumber: space.nextPacketNumber,
                    largestAcknowledged: ack.largestAcknowledged
                )
                self.confirmRemoteKeyUpdate(acknowledgedLargest: ack.largestAcknowledged, now: now)
                flags.frames.append(.ack(largestAcknowledged: ack.largestAcknowledged))
                ackIncluded = true
            }
        }
        var streamBlockedByConnection = false
        buildLoop: while true {
            if self.shouldSendMaxData {
                var delta: UInt64 = 0
                if self.settings.maxConnectionWindow > 0,
                   self.lastMaxDataSentAt != Time.never,
                   now - self.lastMaxDataSentAt
                       < Self.flowWindowRTTFactor * self.congestionState.smoothedRTTNanoseconds,
                   self.settings.maxConnectionWindow > self.receiveWindow {
                    let target = Swift.min(
                        Self.flowWindowScalingFactor * self.receiveWindow,
                        self.settings.maxConnectionWindow
                    )
                    delta = target - self.receiveWindow
                    if self.receiveUnsentMaxOffset.addingClamped(delta) > VarInt.max {
                        delta = VarInt.max - self.receiveUnsentMaxOffset
                    }
                    self.receiveWindow = target
                }
                self.lastMaxDataSentAt = now
                let value = self.receiveUnsentMaxOffset + delta
                space.pendingControlFrames.insert(.maxData(value), at: 0)
                self.receiveMaxOffset = value
                self.receiveUnsentMaxOffset = value
            }
            while let frame = space.pendingControlFrames.first {
                guard self.isControlFrameRelevant(frame) else {
                    space.pendingControlFrames.removeFirst()
                    continue
                }
                guard builder.withWriter({ frame.write(to: &$0) }) else {
                    break
                }
                space.pendingControlFrames.removeFirst()
                flags.addRetransmittable(frame.sentFrame)
            }
            if space.pendingControlFrames.isEmpty {
                self.writeCryptoFrames(space: space, builder: &builder, flags: &flags)
                self.writeDatagramFrames(builder: &builder, flags: &flags)
                streamBlockedByConnection = self.writeStreamFrames(builder: &builder, flags: &flags, now: now)
                if self.remoteBidirectionalUnsentMaxStreams > self.remoteBidirectionalMaxStreams,
                   builder.withWriter({
                       return $0.writeMaxStreams(
                           bidirectional: true,
                           maximum: self.remoteBidirectionalUnsentMaxStreams
                       )
                   }) {
                    self.remoteBidirectionalMaxStreams = self.remoteBidirectionalUnsentMaxStreams
                    flags.addRetransmittable(.maxStreams(
                        bidirectional: true,
                        maximum: self.remoteBidirectionalMaxStreams
                    ))
                }
                if self.remoteUnidirectionalUnsentMaxStreams > self.remoteUnidirectionalMaxStreams,
                   builder.withWriter({
                       return $0.writeMaxStreams(
                           bidirectional: false,
                           maximum: self.remoteUnidirectionalUnsentMaxStreams
                       )
                   }) {
                    self.remoteUnidirectionalMaxStreams = self.remoteUnidirectionalUnsentMaxStreams
                    flags.addRetransmittable(.maxStreams(
                        bidirectional: false,
                        maximum: self.remoteUnidirectionalMaxStreams
                    ))
                }
            }
            if space.pendingControlFrames.isEmpty,
               !flags.isACKEliciting,
               space.sent.retransmittableCount > 0,
               space.sent.probePacketsLeft > 0 {
                let reclaimed = space.sent.reclaimOnPTO(count: 1)
                if !reclaimed.isEmpty {
                    self.reclaimFrames(reclaimed, space: space)
                    continue buildLoop
                }
                if space.sent.ptoElicitingCount == 0 {
                    space.sent.probePacketsLeft = 0
                    self.setLossDetectionTimer(now: now)
                    if builder.isEmpty, self.isCongestionWindowExhausted, !requirePadding {
                        return 0
                    }
                }
            }
            break
        }
        if streamBlockedByConnection,
           self.shouldSendDataBlocked,
           builder.withWriter({ $0.writeDataBlocked(self.sendOffset) }) {
            self.sendLastBlockedOffset = self.sendMaxOffset
            flags.addRetransmittable(.dataBlocked(self.sendOffset))
        }
        if !ackIncluded,
           flags.isACKEliciting,
           space.ackTracker.hasPendingACK,
           let ack = space.ackTracker.makeACKFrame(
               now: now,
               ackDelay: 0,
               ackDelayExponent: self.localTransportParameters.ackDelayExponent,
               includeDelay: true
           ),
           builder.withWriter({ $0.writeACK(ack) }) {
            space.ackTracker.commitACK()
            space.ackTracker.onACKSent(
                packetNumber: space.nextPacketNumber,
                largestAcknowledged: ack.largestAcknowledged
            )
            self.confirmRemoteKeyUpdate(acknowledgedLargest: ack.largestAcknowledged, now: now)
            flags.frames.append(.ack(largestAcknowledged: ack.largestAcknowledged))
        }
        let keepAliveExpired = self.isKeepAliveExpired(now)
        if builder.isEmpty, space.sent.probePacketsLeft == 0, !keepAliveExpired, !requirePadding {
            return 0
        }
        if !flags.isACKEliciting {
            if Time.elapsed(space.nonACKElicitingStart, self.congestionState.smoothedRTTNanoseconds, now)
                || keepAliveExpired
                || space.sent.probePacketsLeft > 0 {
                if builder.withWriter({ $0.writePing() }) {
                    flags.isACKEliciting = true
                    if space.sent.probePacketsLeft > 0 {
                        flags.isProbe = true
                    } else {
                        flags.isPTOEliciting = true
                    }
                    flags.frames.append(.ping)
                    space.nonACKElicitingStart = Time.never
                }
            } else if space.nonACKElicitingStart == Time.never {
                space.nonACKElicitingStart = now
            }
        } else {
            space.nonACKElicitingStart = Time.never
        }
        var padded = false
        if requirePadding {
            let padding = builder.pad(toPacketLength: Swift.max(QUICSettings.minimumUDPPayloadSize - offset, 0))
            padded = padding > 0
        } else {
            let padding = builder.pad(toPacketLength: self.minimumPacketLength)
            padded = padding > 0 && flags.isACKEliciting
        }
        if builder.isEmpty, !padded {
            return 0
        }
        let length = builder.finish(keys: keys)
        self.keyUpdate.encryptionCount += 1
        if flags.isACKEliciting || padded {
            self.recordSentPacket(space: space, length: length, flags: flags, now: now)
            if flags.isACKEliciting {
                self.restartIdleTimerOnWriteIfNeeded(now)
            }
        }
        self.finishPacket(space: space, length: length, isACKEliciting: flags.isACKEliciting, now: now)
        return length
    }

    private func writeStreamFrames(builder: inout PacketBuilder, flags: inout PacketFlags, now: Nanoseconds) -> Bool {
        var blockedByConnection = false
        var visited = 0
        let queued = self.streamSendQueue.count
        while visited < queued, let id = self.streamSendQueue.first {
            visited += 1
            guard let stream = self.streams[id] else {
                self.streamSendQueue.removeFirst()
                continue
            }
            var outOfSpace = false
            if stream.isResetStreamPending, stream.isAllSendDataAcknowledged {
                stream.isResetStreamPending = false
            } else if stream.isResetStreamPending {
                let finalSize = stream.send?.sentOffset ?? 0
                if builder.withWriter({
                    return $0.writeResetStream(
                        streamID: id.rawValue,
                        errorCode: stream.resetStreamErrorCode,
                        finalSize: finalSize
                    )
                }) {
                    stream.isResetStreamPending = false
                    flags.addRetransmittable(.resetStream(id: id.rawValue))
                } else {
                    outOfSpace = true
                }
            }
            if !outOfSpace, stream.isStopSendingPending {
                if stream.isReadClosed, stream.receiveOffset == stream.receiveLastOffset {
                    stream.isStopSendingPending = false
                } else if builder.withWriter({
                    return $0.writeStopSending(streamID: id.rawValue, errorCode: stream.stopSendingErrorCode)
                }) {
                    stream.isStopSendingPending = false
                    flags.addRetransmittable(.stopSending(id: id.rawValue))
                } else {
                    outOfSpace = true
                }
            }
            if !outOfSpace, stream.shouldSendStreamDataBlocked {
                if builder.withWriter({
                    return $0.writeStreamDataBlocked(streamID: id.rawValue, limit: stream.sendMaxOffset)
                }) {
                    stream.sendLastBlockedOffset = stream.sendMaxOffset
                    flags.addRetransmittable(.streamDataBlocked(id: id.rawValue, limit: stream.sendMaxOffset))
                } else {
                    outOfSpace = true
                }
            }
            if !outOfSpace, stream.shouldSendMaxStreamData() {
                var delta: UInt64 = 0
                if self.settings.maxStreamWindow > 0,
                   stream.lastMaxStreamDataSentAt != Time.never,
                   now - stream.lastMaxStreamDataSentAt
                       < Self.flowWindowRTTFactor * self.congestionState.smoothedRTTNanoseconds,
                   self.settings.maxStreamWindow > stream.receiveWindow {
                    let target = Swift.min(
                        Self.flowWindowScalingFactor * stream.receiveWindow,
                        self.settings.maxStreamWindow
                    )
                    delta = target - stream.receiveWindow
                    if stream.receiveUnsentMaxOffset.addingClamped(delta) > VarInt.max {
                        delta = VarInt.max - stream.receiveUnsentMaxOffset
                    }
                    stream.receiveWindow = target
                }
                let value = stream.receiveUnsentMaxOffset + delta
                if builder.withWriter({ $0.writeMaxStreamData(streamID: id.rawValue, maximum: value) }) {
                    stream.lastMaxStreamDataSentAt = now
                    stream.receiveMaxOffset = value
                    stream.receiveUnsentMaxOffset = value
                    flags.addRetransmittable(.maxStreamData(id: id.rawValue, maximum: value))
                } else {
                    stream.receiveWindow -= delta
                    outOfSpace = true
                }
            }
            if !outOfSpace,
               stream.hasPendingSendData,
               let send = stream.send,
               let segment = send.nextSegment(maxLength: Int.max) {
                var length = segment.length
                var isNewData = false
                if segment.offset >= send.sentOffset {
                    isNewData = true
                    let streamCredit = stream.sendMaxOffset.subtractingClamped(segment.offset)
                    let connectionCredit = self.sendMaxOffset.subtractingClamped(self.sendOffset)
                    let credit = Swift.min(streamCredit, connectionCredit)
                    if credit == 0, length > 0 {
                        if connectionCredit == 0 {
                            blockedByConnection = true
                        }
                        length = -1
                    } else {
                        length = Int(Swift.min(UInt64(length), credit))
                    }
                }
                if length >= 0 {
                    if let capacity = OutputBuffer.streamDataCapacity(
                        streamID: id.rawValue,
                        offset: segment.offset,
                        available: builder.writableBytes,
                        wanted: length
                    ) {
                        if capacity == length || capacity >= 256 {
                            let fin = segment.fin && capacity == segment.length
                            let piece = SendBuffer.Segment(offset: segment.offset, length: capacity, fin: fin)
                            let wrote = send.withBytes(offset: piece.offset, length: piece.length) { bytes in
                                return builder.withWriter {
                                    return $0.writeStream(
                                        streamID: id.rawValue,
                                        offset: piece.offset,
                                        data: bytes,
                                        fin: fin
                                    )
                                }
                            }
                            if wrote {
                                let previousSent = send.sentOffset
                                stream.send!.markSent(piece)
                                if isNewData {
                                    self.sendOffset += stream.send!.sentOffset - previousSent
                                }
                                if fin {
                                    stream.isWriteClosed = true
                                }
                                stream.hasSentStreamFrame = true
                                flags.addRetransmittable(.stream(
                                    id: id.rawValue,
                                    offset: piece.offset,
                                    length: piece.length,
                                    fin: fin
                                ))
                                if stream.send!.sentOffset < stream.send!.endOffset {
                                    if self.sendOffset == self.sendMaxOffset {
                                        blockedByConnection = true
                                    }
                                    let limit = stream.sendMaxOffset
                                    if stream.shouldSendStreamDataBlocked,
                                       builder.withWriter({
                                           return $0.writeStreamDataBlocked(streamID: id.rawValue, limit: limit)
                                       }) {
                                        stream.sendLastBlockedOffset = limit
                                        flags.addRetransmittable(.streamDataBlocked(id: id.rawValue, limit: limit))
                                    }
                                }
                            } else {
                                outOfSpace = true
                            }
                        } else {
                            outOfSpace = true
                        }
                    } else {
                        outOfSpace = true
                    }
                }
            }
            if outOfSpace {
                break
            }
            self.streamSendQueue.removeFirst()
            if stream.hasPendingFrames {
                self.streamSendQueue.append(id)
            } else {
                stream.isQueued = false
            }
        }
        return blockedByConnection
    }

    private func writePathChallengePacket(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> QUICOutgoingDatagram? {
        guard var pathValidation = self.pathValidation else {
            return nil
        }
        if pathValidation.hasTimedOut(now: now) {
            self.failPathValidation(now: now)
            return nil
        }
        pathValidation.handleEntryExpiry(now: now)
        guard pathValidation.shouldSendProbe else {
            self.pathValidation = pathValidation
            return nil
        }
        let data = UInt64.random(in: .min ... .max)
        let timeout = Swift.max(self.pto(for: self.applicationSpace), self.initialPTO)
        let expiry = now.addingClamped(
            timeout.multipliedReportingOverflow(by: 1 << UInt64(pathValidation.round)).partialValue
        )
        pathValidation.addEntry(data: data, expiry: expiry, now: now)
        self.pathValidation = pathValidation
        let maxLength = Swift.min(destination.count, QUICSettings.minimumUDPPayloadSize)
        let region = UnsafeMutableBufferPointer(rebasing: destination[0..<maxLength])
        var flags = PacketFlags()
        flags.isACKEliciting = true
        flags.isPTOEliciting = true
        flags.frames = [.pathChallenge(data)]
        let track = pathValidation.path == self.active.path ? flags : nil
        let length = self.writeSingleFramePacket(
            space: self.applicationSpace,
            type: .oneRTT,
            destinationID: pathValidation.connectionID.id,
            into: region,
            offset: 0,
            padToDatagram: true,
            padToLength: nil,
            track: track,
            now: now
        ) { writer in
            return writer.writePathChallenge(data)
        }
        guard length > 0 else {
            return nil
        }
        return QUICOutgoingDatagram(count: length, path: pathValidation.path)
    }

    private func writePathResponsePacket(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> QUICOutgoingDatagram? {
        while let first = self.pendingPathResponses.first {
            if first.path == self.active.path {
                return nil
            }
            guard let pathValidation = self.pathValidation, pathValidation.path == first.path else {
                self.pendingPathResponses.removeFirst()
                continue
            }
            let maxLength = Swift.min(destination.count, QUICSettings.minimumUDPPayloadSize)
            let region = UnsafeMutableBufferPointer(rebasing: destination[0..<maxLength])
            let length = self.writeSingleFramePacket(
                space: self.applicationSpace,
                type: .oneRTT,
                destinationID: pathValidation.connectionID.id,
                into: region,
                offset: 0,
                padToDatagram: true,
                padToLength: nil,
                track: nil,
                now: now
            ) { writer in
                return writer.writePathResponse(first.data)
            }
            guard length > 0 else {
                return nil
            }
            self.pendingPathResponses.removeFirst()
            return QUICOutgoingDatagram(count: length, path: pathValidation.path)
        }
        return nil
    }

    private func writePMTUDProbe(
        into destination: UnsafeMutableBufferPointer<UInt8>,
        now: Nanoseconds
    ) throws(TransportError) -> Int {
        guard var discovery = self.pathMTUDiscovery, discovery.requiresProbe else {
            return 0
        }
        let probeLength = discovery.probeLength
        guard probeLength <= destination.count else {
            return 0
        }
        let region = UnsafeMutableBufferPointer(rebasing: destination[0..<probeLength])
        var flags = PacketFlags()
        flags.isACKEliciting = true
        flags.isPTOEliciting = true
        flags.isPMTUDProbe = true
        flags.frames = [.ping]
        let length = self.writeSingleFramePacket(
            space: self.applicationSpace,
            type: .oneRTT,
            destinationID: self.active.connectionID.id,
            into: region,
            offset: 0,
            padToDatagram: false,
            padToLength: probeLength,
            track: flags,
            now: now
        ) { writer in
            return writer.writePing()
        }
        guard length > 0 else {
            return 0
        }
        discovery.probeSent(pto: self.pto(for: self.applicationSpace), now: now)
        self.pathMTUDiscovery = discovery
        return length
    }

    func writeSingleFramePacket(
        space: PacketNumberSpace,
        type: PacketType,
        destinationID: QUICConnectionID,
        into destination: UnsafeMutableBufferPointer<UInt8>,
        offset: Int,
        padToDatagram: Bool,
        padToLength: Int?,
        track: PacketFlags?,
        now: Nanoseconds,
        _ writeFrame: (inout OutputBuffer) -> Bool
    ) -> Int {
        guard let keys = space.writeKeys, offset < destination.count else {
            return 0
        }
        let region = UnsafeMutableBufferPointer(rebasing: destination[offset...])
        guard var builder = PacketBuilder(
            buffer: region,
            type: type,
            version: self.version,
            destinationID: destinationID,
            sourceID: type == .oneRTT ? QUICConnectionID() : self.originalSourceID,
            token: type == .initial ? self.retryToken : [],
            packetNumber: space.nextPacketNumber,
            packetNumberLength: space.selectPacketNumberLength(),
            keyPhase: space.isApplication && self.keyUpdate.currentPhase
        ) else {
            return 0
        }
        guard builder.withWriter({ writeFrame(&$0) }) else {
            return 0
        }
        if let padToLength {
            builder.pad(toPacketLength: padToLength)
        } else if padToDatagram {
            builder.pad(toPacketLength: Swift.max(QUICSettings.minimumUDPPayloadSize - offset, 0))
        } else {
            builder.pad(toPacketLength: self.minimumPacketLength)
        }
        let length = builder.finish(keys: keys)
        if space.isApplication {
            self.keyUpdate.encryptionCount += 1
        }
        if let track {
            self.recordSentPacket(space: space, length: length, flags: track, now: now)
        }
        self.finishPacket(space: space, length: length, isACKEliciting: track?.isACKEliciting ?? false, now: now)
        return length
    }

    private func recordSentPacket(space: PacketNumberSpace, length: Int, flags: PacketFlags, now: Nanoseconds) {
        var packet = SentPacket(
            packetNumber: space.nextPacketNumber,
            sentAt: now,
            size: length,
            frames: flags.frames,
            isACKEliciting: flags.isACKEliciting,
            isPTOEliciting: flags.isPTOEliciting,
            isRetransmittable: flags.isRetransmittable,
            isProbe: flags.isProbe,
            isPMTUDProbe: flags.isPMTUDProbe
        )
        packet.deliverySnapshot = self.deliveryRateSampler.onSend(
            now: now,
            inFlight: self.congestionState.bytesInFlight,
            size: length,
            applicationLimited: self.isHandshakeComplete && self.pendingDatagrams.isEmpty
                && !self.hasPendingStreamData
        )
        space.sent.add(packet, state: &self.congestionState)
        self.congestionController.onPacketSent(
            packet.info,
            state: &self.congestionState,
            now: QUICInstant(nanoseconds: now)
        )
        if flags.isACKEliciting {
            space.lastSentAt = now
        }
        self.setLossDetectionTimer(now: now)
    }
    
    private var hasPendingStreamData: Bool {
        let hasPending = self.streamSendQueue.contains { self.streams[$0]?.hasPendingSendData == true }
        assert(hasPending == self.streams.values.contains { $0.hasPendingSendData })
        return hasPending
    }

    private func finishPacket(space: PacketNumberSpace, length: Int, isACKEliciting: Bool, now: Nanoseconds) {
        if space.sent.probePacketsLeft > 0, isACKEliciting {
            space.sent.probePacketsLeft -= 1
        }
        self.updateKeepAlive(now)
        self.active.bytesSent += UInt64(length)
        self.pacer.recordSent(bytes: length)
        self.packetsSent += 1
        self.bytesSent += UInt64(length)
        space.nextPacketNumber += 1
    }
}
