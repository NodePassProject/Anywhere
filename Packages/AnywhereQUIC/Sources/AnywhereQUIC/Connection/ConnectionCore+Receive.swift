//
//  ConnectionCore+Receive.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    enum PacketOutcome {
        case consumed(Int)
        case discarded
        case handoff
        case stop
    }

    func receive(_ datagram: Data, from path: QUICPath, now: QUICInstant) {
        datagram.withUnsafeBytes { self.receive($0, from: path, now: now) }
    }

    func receive(_ datagram: [UInt8], from path: QUICPath, now: QUICInstant) {
        datagram.withUnsafeBytes { self.receive($0, from: path, now: now) }
    }

    func receive(_ datagram: UnsafeRawBufferPointer, from path: QUICPath, now: QUICInstant) {
        let now = self.updateTimestamp(now.nanoseconds)
        guard !datagram.isEmpty else {
            return
        }
        switch self.state {
        case .closed, .draining:
            return
        case .closing:
            self.handleReceiveWhileClosing()
            return
        case .handshaking, .established:
            break
        }
        guard self.isKnownPath(path) else {
            self.packetsDiscarded += 1
            return
        }
        self.bytesReceived += UInt64(datagram.count)
        if self.active.path == path {
            self.active.bytesReceived += UInt64(datagram.count)
        }
        do {
            switch self.state {
            case .handshaking:
                try self.receiveHandshakeDatagram(datagram, path: path, now: now)
            case .established:
                try self.prepareKeyUpdate(now: now)
                try self.receiveProtectedPackets(datagram, from: 0, path: path, now: now)
            default:
                break
            }
        } catch {
            self.closeLocally(error, now: now)
        }
    }

    private func receiveHandshakeDatagram(
        _ datagram: UnsafeRawBufferPointer,
        path: QUICPath,
        now: Nanoseconds
    ) throws(TransportError) {
        var offset = 0
        while offset < datagram.count, self.state == .handshaking {
            let rest = UnsafeRawBufferPointer(rebasing: datagram[offset...])
            let outcome = try self.processHandshakePacket(
                rest,
                datagramLength: datagram.count,
                path: path,
                receivedAt: now,
                now: now
            )
            switch outcome {
            case .consumed(let count):
                offset += count
                self.packetsReceived += 1
            case .discarded:
                self.packetsDiscarded += 1
                return
            case .handoff:
                try self.receiveProtectedPackets(datagram, from: offset, path: path, now: now)
                return
            case .stop:
                return
            }
            try self.drainBufferedPackets(now: now)
        }
    }

    func drainBufferedPackets(now: Nanoseconds) throws(TransportError) {
        if self.shouldProcessBufferedHandshakePackets {
            self.shouldProcessBufferedHandshakePackets = false
            if let handshakeSpace = self.handshakeSpace, handshakeSpace.readKeys != nil {
                let buffered = handshakeSpace.bufferedPackets
                handshakeSpace.bufferedPackets.removeAll()
                for packet in buffered where self.state == .handshaking {
                    let outcome = try packet.bytes.withUnsafeBufferPointer { (buffer) throws(TransportError) in
                        return try self.processHandshakePacket(
                            UnsafeRawBufferPointer(buffer),
                            datagramLength: packet.datagramLength,
                            path: packet.path,
                            receivedAt: packet.receivedAt,
                            now: now
                        )
                    }
                    if case .discarded = outcome {
                        self.packetsDiscarded += 1
                    }
                }
            }
        }
        if self.shouldProcessBufferedApplicationPackets {
            self.shouldProcessBufferedApplicationPackets = false
            if self.applicationSpace.readKeys != nil {
                let buffered = self.applicationSpace.bufferedPackets
                self.applicationSpace.bufferedPackets.removeAll()
                for packet in buffered where self.state == .handshaking || self.state == .established {
                    let outcome = try packet.bytes.withUnsafeBufferPointer { (buffer) throws(TransportError) in
                        return try self.processProtectedPacket(
                            UnsafeRawBufferPointer(buffer),
                            datagramLength: packet.datagramLength,
                            path: packet.path,
                            receivedAt: packet.receivedAt,
                            now: now
                        )
                    }
                    if case .discarded = outcome {
                        self.packetsDiscarded += 1
                    }
                }
            }
        }
    }

    private func shouldBufferProtectedPacket(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard bytes.count >= StatelessResetPacket.minimumLength else {
            return false
        }
        return bytes.prefix(21).contains { $0 != 0 }
    }

    private func processHandshakePacket(
        _ bytes: UnsafeRawBufferPointer,
        datagramLength: Int,
        path: QUICPath,
        receivedAt: Nanoseconds,
        now: Nanoseconds
    ) throws(TransportError) -> PacketOutcome {
        guard let first = bytes.first else {
            return .discarded
        }
        if first & PacketHeader.formBit == 0 {
            if self.applicationSpace.readKeys != nil {
                return .handoff
            }
            if self.shouldBufferProtectedPacket(bytes) {
                self.applicationSpace.buffer(bytes, path: path, datagramLength: datagramLength, receivedAt: receivedAt)
            }
            return .consumed(bytes.count)
        }
        let header: PacketHeader
        do {
            header = try PacketHeader.parse(bytes, shortHeaderDestinationIDLength: 0)
        } catch {
            return .discarded
        }
        switch header.type {
        case .versionNegotiation:
            guard !self.hasProcessedInitialPacket,
                  header.destinationID == self.originalSourceID,
                  header.sourceID == self.active.connectionID.id else {
                return .discarded
            }
            guard let versions = VersionNegotiationPacket.versions(in: bytes, header: header),
                  !versions.contains(self.version.rawValue) else {
                return .discarded
            }
            self.enterClosed(reason: .versionNegotiation(offeredVersions: versions), emitEvent: true)
            return .stop
        case .retry:
            guard !self.hasProcessedInitialPacket,
                  header.version == self.version,
                  header.hasFixedBit,
                  self.handleRetry(bytes, header: header, now: now) else {
                return .discarded
            }
            return .consumed(bytes.count)
        default:
            break
        }
        guard header.version == self.version, header.hasFixedBit else {
            return .discarded
        }
        let packetLength = header.packetEnd
        if self.hasProcessedInitialPacket, header.sourceID != self.active.connectionID.id {
            return .discarded
        }
        let space: PacketNumberSpace
        switch header.type {
        case .initial:
            guard let initialSpace = self.initialSpace else {
                return .consumed(packetLength)
            }
            guard header.tokenRange.isEmpty else {
                return .discarded
            }
            space = initialSpace
        case .handshake:
            guard let handshakeSpace = self.handshakeSpace else {
                return .consumed(packetLength)
            }
            guard handshakeSpace.readKeys != nil else {
                handshakeSpace.buffer(
                    UnsafeRawBufferPointer(rebasing: bytes[0..<packetLength]),
                    path: path,
                    datagramLength: datagramLength,
                    receivedAt: receivedAt
                )
                return .consumed(packetLength)
            }
            space = handshakeSpace
        default:
            return .discarded
        }
        guard let keys = space.readKeys else {
            return .discarded
        }
        guard let unprotected = self.removeHeaderProtection(
            bytes,
            packetLength: packetLength,
            header: header,
            keys: keys
        ) else {
            return .discarded
        }
        let packetNumber = PacketNumber.decode(
            truncated: unprotected.truncatedPacketNumber,
            length: unprotected.packetNumberLength,
            largestReceived: space.ackTracker.largestReceived
        )
        guard packetNumber <= PacketNumber.max, !space.ackTracker.isDuplicate(packetNumber) else {
            return .discarded
        }
        let payloadStart = header.packetNumberOffset + unprotected.packetNumberLength
        guard let plaintextLength = self.decryptPayload(
            bytes,
            payloadStart: payloadStart,
            packetLength: packetLength,
            packetNumber: packetNumber,
            keys: keys
        ) else {
            return .discarded
        }
        guard unprotected.firstByte & PacketHeader.longReservedBits == 0 else {
            throw TransportError(.protocolViolation, reason: "reserved bits set")
        }
        guard self.verifyDestinationID(header.destinationID) else {
            return .discarded
        }
        guard plaintextLength > 0 else {
            if header.type == .initial {
                return .discarded
            }
            throw TransportError(.protocolViolation, reason: "packet without frames")
        }
        if header.type == .initial, !self.hasProcessedInitialPacket {
            self.hasProcessedInitialPacket = true
            self.active.connectionID.id = header.sourceID
        }
        var isACKEliciting = false
        try self.decryptBuffer.withUnsafeBufferPointer { (buffer) throws(TransportError) in
            var reader = InputBuffer(storage: UnsafeRawBufferPointer(UnsafeBufferPointer(rebasing: buffer[0..<plaintextLength])))
            while reader.byteCount > 0 {
                let frame = try reader.readFrame()
                guard frame.isAllowedInHandshakeLevels else {
                    throw TransportError(
                        .protocolViolation,
                        frameType: frame.type,
                        reason: "frame not allowed in \(header.type) packet"
                    )
                }
                if frame.isACKEliciting {
                    isACKEliciting = true
                }
                switch frame {
                case .ack(let ack):
                    if header.type == .handshake {
                        self.isServerAddressVerified = true
                    }
                    try self.handleACK(ack, space: space, ackDelay: 0, receivedAt: receivedAt, now: now)
                case .crypto(let offset, let data):
                    try self.handleCrypto(space: space, offset: offset, data: data, now: now)
                case .connectionClose(let close):
                    self.handlePeerClose(close, now: now)
                default:
                    break
                }
            }
        }
        if case .draining = self.state {
            space.ackTracker.recordReceived(
                packetNumber,
                isACKEliciting: isACKEliciting,
                now: receivedAt,
                ackThreshold: 1
            )
            return .stop
        }
        space.ackTracker.recordReceived(packetNumber, isACKEliciting: isACKEliciting, now: receivedAt, ackThreshold: 1)
        self.restartIdleTimerOnRead(now)
        return .consumed(packetLength)
    }

    func removeHeaderProtection(
        _ bytes: UnsafeRawBufferPointer,
        packetLength: Int,
        header: PacketHeader,
        keys: PacketKeys
    ) -> (firstByte: UInt8, packetNumberLength: Int, truncatedPacketNumber: UInt32)? {
        let sampleOffset = header.packetNumberOffset + 4
        guard packetLength >= sampleOffset + 16, bytes.count >= packetLength else {
            return nil
        }
        let headerLength = header.packetNumberOffset + 4
        if self.headerScratch.count < headerLength {
            self.headerScratch = [UInt8](repeating: 0, count: headerLength)
        }
        return self.headerScratch.withUnsafeMutableBytes { scratch in
            scratch.copyMemory(from: UnsafeRawBufferPointer(rebasing: bytes[0..<headerLength]))
            let sample = UnsafeRawBufferPointer(rebasing: bytes[sampleOffset..<sampleOffset + 16])
            return keys.removeHeaderProtection(
                header: UnsafeMutableRawBufferPointer(rebasing: scratch[0..<headerLength]),
                packetNumberOffset: header.packetNumberOffset,
                sample: sample
            )
        }
    }

    func decryptPayload(
        _ bytes: UnsafeRawBufferPointer,
        payloadStart: Int,
        packetLength: Int,
        packetNumber: UInt64,
        keys: PacketKeys
    ) -> Int? {
        self.ensureDecryptBuffer(packetLength)
        return self.decryptBuffer.withUnsafeMutableBytes { output -> Int? in
            return self.decryptPayload(
                bytes,
                payloadStart: payloadStart,
                packetLength: packetLength,
                packetNumber: packetNumber,
                keys: keys,
                into: output
            )
        }
    }

    func decryptPayload(
        _ bytes: UnsafeRawBufferPointer,
        payloadStart: Int,
        packetLength: Int,
        packetNumber: UInt64,
        keys: PacketKeys,
        into output: UnsafeMutableRawBufferPointer
    ) -> Int? {
        guard payloadStart <= packetLength else {
            return nil
        }
        let payload = UnsafeRawBufferPointer(rebasing: bytes[payloadStart..<packetLength])
        return self.headerScratch.withUnsafeBytes { scratch -> Int? in
            let aad = UnsafeRawBufferPointer(rebasing: scratch[0..<payloadStart])
            return try? keys.open(packetNumber: packetNumber, header: aad, payload: payload, into: output)
        }
    }

    private func handleRetry(_ bytes: UnsafeRawBufferPointer, header: PacketHeader, now: Nanoseconds) -> Bool {
        guard !self.hasReceivedRetry, let initialSpace = self.initialSpace else {
            return false
        }
        guard let retry = RetryPacket.parse(bytes, header: header) else {
            return false
        }
        guard RetryIntegrity.verify(retryPacket: bytes, originalDestinationID: self.active.connectionID.id) else {
            return false
        }
        guard !retry.token.isEmpty else {
            return false
        }
        if header.sourceID == self.active.connectionID.id {
            return true
        }
        self.active.connectionID.id = header.sourceID
        self.retrySourceID = header.sourceID
        self.hasReceivedRetry = true
        let keys = PacketKeys.initial(destinationID: header.sourceID, isClient: true)
        initialSpace.readKeys = keys.read
        initialSpace.writeKeys = keys.write
        self.handshakePhase = .initial
        for packet in initialSpace.sent.removeAll(state: &self.congestionState) {
            for frame in packet.frames {
                if case .crypto(let offset, let length) = frame {
                    initialSpace.cryptoSend.markLost(offset: offset, length: length, fin: false)
                }
            }
        }
        initialSpace.sent.probePacketsLeft = 0
        initialSpace.ackTracker = ACKTracker()
        self.retryToken = retry.token
        self.congestionState.resetRecovery()
        self.resetCongestionState(now: now)
        self.setLossDetectionTimer(now: now)
        return true
    }

    func handleCrypto(
        space: PacketNumberSpace,
        offset: UInt64,
        data: UnsafeRawBufferPointer,
        now: Nanoseconds
    ) throws(TransportError) {
        guard !data.isEmpty else {
            return
        }
        let end = offset + UInt64(data.count)
        guard end <= space.maxCryptoOffset else {
            throw TransportError(.cryptoBufferExceeded, reason: "CRYPTO offset too large")
        }
        let readOffset = space.cryptoReceive.readOffset
        if end <= readOffset {
            return
        }
        space.cryptoReceivedEnd = Swift.max(space.cryptoReceivedEnd, end)
        if offset > readOffset, end - readOffset > PacketNumberSpace.maxReorderedCryptoData {
            throw TransportError(.cryptoBufferExceeded, reason: "too much reordered CRYPTO data")
        }
        if let delivered = space.cryptoReceive.receive(offset: offset, data: data) {
            try self.deliverCryptoData(delivered, level: space.level, now: now)
        }
    }

    func receiveProtectedPackets(
        _ datagram: UnsafeRawBufferPointer,
        from offset: Int,
        path: QUICPath,
        now: Nanoseconds
    ) throws(TransportError) {
        var position = offset
        var isFirst = offset == 0
        while position < datagram.count, self.state == .handshaking || self.state == .established {
            let rest = UnsafeRawBufferPointer(rebasing: datagram[position...])
            let outcome = try self.processProtectedPacket(
                rest,
                datagramLength: datagram.count,
                path: path,
                receivedAt: now,
                now: now
            )
            switch outcome {
            case .consumed(let count):
                position += count
                self.packetsReceived += 1
            case .discarded:
                self.packetsDiscarded += 1
                if isFirst,
                   let token = StatelessResetPacket.token(in: datagram),
                   self.matchesStatelessResetToken(token, path: path) {
                    self.enterDraining(reason: .statelessReset, now: now)
                }
                return
            case .handoff, .stop:
                return
            }
            isFirst = false
            try self.drainBufferedPackets(now: now)
        }
    }

    func matchesStatelessResetToken(_ token: QUICStatelessResetToken, path: QUICPath) -> Bool {
        if self.active.connectionID.token == token, self.active.path == path {
            return true
        }
        if let pathValidation = self.pathValidation,
           pathValidation.connectionID.token == token,
           pathValidation.path == path {
            return true
        }
        return false
    }

    func processProtectedPacket(
        _ bytes: UnsafeRawBufferPointer,
        datagramLength: Int,
        path: QUICPath,
        receivedAt: Nanoseconds,
        now: Nanoseconds
    ) throws(TransportError) -> PacketOutcome {
        guard let first = bytes.first else {
            return .discarded
        }
        let header: PacketHeader
        let space: PacketNumberSpace
        if first & PacketHeader.formBit != 0 {
            do {
                header = try PacketHeader.parse(bytes, shortHeaderDestinationIDLength: 0)
            } catch {
                return .discarded
            }
            guard header.version == self.version, header.hasFixedBit else {
                return .discarded
            }
            guard header.sourceID == self.active.connectionID.id else {
                return .discarded
            }
            switch header.type {
            case .initial:
                return .consumed(header.packetEnd)
            case .handshake:
                guard let handshakeSpace = self.handshakeSpace, handshakeSpace.readKeys != nil else {
                    return .consumed(header.packetEnd)
                }
                space = handshakeSpace
            default:
                return .consumed(header.packetEnd)
            }
        } else {
            do {
                header = try PacketHeader.parse(bytes, shortHeaderDestinationIDLength: self.originalSourceID.count)
            } catch {
                return .discarded
            }
            guard header.hasFixedBit else {
                return .discarded
            }
            guard self.applicationSpace.readKeys != nil else {
                if self.shouldBufferProtectedPacket(bytes) {
                    self.applicationSpace.buffer(
                        bytes,
                        path: path,
                        datagramLength: datagramLength,
                        receivedAt: receivedAt
                    )
                }
                return .consumed(bytes.count)
            }
            space = self.applicationSpace
        }
        let packetLength = header.type == .oneRTT ? bytes.count : header.packetEnd
        guard var keys = space.readKeys else {
            return .discarded
        }
        guard let unprotected = self.removeHeaderProtection(
            bytes,
            packetLength: packetLength,
            header: header,
            keys: keys
        ) else {
            return .discarded
        }
        let packetNumber = PacketNumber.decode(
            truncated: unprotected.truncatedPacketNumber,
            length: unprotected.packetNumberLength,
            largestReceived: space.ackTracker.largestReceived
        )
        guard packetNumber <= PacketNumber.max else {
            return .discarded
        }
        var usingNextKeys = false
        var forceFailure = false
        if header.type == .oneRTT {
            let packetPhase = unprotected.firstByte & PacketHeader.keyPhaseBit != 0
            if packetPhase != self.keyUpdate.currentPhase {
                if self.keyUpdate.readFirstPacketNumber > packetNumber {
                    if let old = self.keyUpdate.oldRead {
                        keys = old
                    } else {
                        forceFailure = true
                    }
                } else if space.ackTracker.largestReceived == nil || space.ackTracker.largestReceived! < packetNumber {
                    if let next = self.keyUpdate.nextRead {
                        keys = next
                        usingNextKeys = true
                    } else {
                        forceFailure = true
                    }
                } else {
                    forceFailure = true
                }
            }
        }
        let payloadStart = header.packetNumberOffset + unprotected.packetNumberLength
        var plaintextLength: Int?
        var region: UnsafeMutableRawBufferPointer?
        if !forceFailure {
            if header.type == .oneRTT {
                let output = self.arena.region(
                    count: Swift.max(0, packetLength - payloadStart - AEADAlgorithm.tagLength)
                )
                region = output
                plaintextLength = self.decryptPayload(
                    bytes,
                    payloadStart: payloadStart,
                    packetLength: packetLength,
                    packetNumber: packetNumber,
                    keys: keys,
                    into: output
                )
            } else {
                plaintextLength = self.decryptPayload(
                    bytes,
                    payloadStart: payloadStart,
                    packetLength: packetLength,
                    packetNumber: packetNumber,
                    keys: keys
                )
            }
        }
        guard let plaintextLength else {
            if header.type == .oneRTT {
                self.decryptionFailures += 1
                if self.decryptionFailures >= keys.aead.integrityLimit {
                    throw TransportError(.aeadLimitReached, reason: "integrity limit reached")
                }
            }
            return .discarded
        }
        let reservedMask = header.type == .oneRTT ? PacketHeader.shortReservedBits : PacketHeader.longReservedBits
        guard unprotected.firstByte & reservedMask == 0 else {
            throw TransportError(.protocolViolation, reason: "reserved bits set")
        }
        guard !space.ackTracker.isDuplicate(packetNumber) else {
            return .discarded
        }
        guard plaintextLength > 0 else {
            throw TransportError(.protocolViolation, reason: "packet without frames")
        }
        guard self.verifyDestinationID(header.destinationID) else {
            return .discarded
        }
        if header.type == .handshake {
            try self.processDelayedHandshakePacket(
                space: space,
                packetNumber: packetNumber,
                plaintextLength: plaintextLength,
                receivedAt: receivedAt,
                now: now
            )
            return self.state == .draining ? .stop : .consumed(packetLength)
        }
        let outcome: FrameOutcome
        if let region {
            outcome = try self.processFrames(
                UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(region)[0..<plaintextLength]),
                header: header,
                space: space,
                path: path,
                receivedAt: receivedAt,
                now: now
            )
        } else {
            outcome = try self.decryptBuffer.withUnsafeBufferPointer { (buffer) throws(TransportError) in
                return try self.processFrames(
                    UnsafeRawBufferPointer(UnsafeBufferPointer(rebasing: buffer[0..<plaintextLength])),
                    header: header,
                    space: space,
                    path: path,
                    receivedAt: receivedAt,
                    now: now
                )
            }
        }
        if outcome.receivedNewConnectionID {
            try self.postProcessNewConnectionIDs(now: now)
            guard !self.destinationIDs.isRetireSequenceLimitExceeded else {
                throw TransportError(
                    .connectionIDLimitError,
                    frameType: FrameType.newConnectionID,
                    reason: "too many unacknowledged RETIRE_CONNECTION_ID frames"
                )
            }
        }
        if usingNextKeys {
            self.rotateKeys(firstReadPacketNumber: packetNumber, initiator: false)
        } else if self.keyUpdate.readFirstPacketNumber > packetNumber {
            self.keyUpdate.readFirstPacketNumber = packetNumber
        }
        if self.active.path == path {
            self.updateKeepAlive(now)
        }
        space.ackTracker.recordReceived(
            packetNumber,
            isACKEliciting: outcome.isACKEliciting,
            now: receivedAt,
            ackThreshold: self.settings.ackThreshold
        )
        self.restartIdleTimerOnRead(now)
        return self.state == .draining ? .stop : .consumed(packetLength)
    }

    struct FrameOutcome {
        var isACKEliciting = false
        var receivedNewConnectionID = false
    }

    private func processFrames(
        _ plaintext: UnsafeRawBufferPointer,
        header: PacketHeader,
        space: PacketNumberSpace,
        path: QUICPath,
        receivedAt: Nanoseconds,
        now: Nanoseconds
    ) throws(TransportError) -> FrameOutcome {
        var outcome = FrameOutcome()
        var reader = InputBuffer(storage: plaintext)
        while reader.byteCount > 0 {
            let frame = try reader.readFrame()
            if frame.isACKEliciting {
                outcome.isACKEliciting = true
            }
            switch frame {
            case .padding, .ping:
                break
            case .ack(let ack):
                self.isServerAddressVerified = true
                try self.handleACK(
                    ack,
                    space: space,
                    ackDelay: self.scaledACKDelay(ack.ackDelay),
                    receivedAt: receivedAt,
                    now: now
                )
            case .stream(let streamID, let offset, let data, let fin):
                try self.handleStreamFrame(
                    streamID: streamID,
                    offset: offset,
                    data: data,
                    fin: fin,
                    frameType: frame.type
                )
            case .crypto(let offset, let data):
                try self.handleCrypto(space: space, offset: offset, data: data, now: now)
            case .resetStream(let streamID, let errorCode, let finalSize):
                try self.handleResetStream(streamID: streamID, errorCode: errorCode, finalSize: finalSize)
            case .stopSending(let streamID, let errorCode):
                try self.handleStopSending(streamID: streamID, errorCode: errorCode)
            case .maxData(let maximum):
                self.handleMaxData(maximum)
            case .maxStreamData(let streamID, let maximum):
                try self.handleMaxStreamData(streamID: streamID, maximum: maximum)
            case .maxStreams(let bidirectional, let maximum):
                self.handleMaxStreams(bidirectional: bidirectional, maximum: maximum)
            case .dataBlocked(let limit):
                try self.handleDataBlocked(limit)
            case .streamDataBlocked(let streamID, let limit):
                try self.handleStreamDataBlocked(streamID: streamID, limit: limit)
            case .streamsBlocked(let bidirectional, let limit):
                try self.handleStreamsBlocked(bidirectional: bidirectional, limit: limit)
            case .newToken:
                break
            case .newConnectionID(let sequence, let retirePriorTo, let id, let token):
                try self.handleNewConnectionID(
                    sequence: sequence,
                    retirePriorTo: retirePriorTo,
                    id: id,
                    token: token,
                    now: now
                )
                outcome.receivedNewConnectionID = true
            case .retireConnectionID(let sequence):
                try self.handleRetireConnectionID(
                    sequence: sequence,
                    packetDestinationID: header.destinationID,
                    now: now
                )
            case .pathChallenge(let data):
                self.handlePathChallenge(data, path: path)
            case .pathResponse(let data):
                try self.handlePathResponse(data, now: now)
            case .connectionClose(let close):
                self.handlePeerClose(close, now: now)
            case .datagram(let data, let frameLength, _):
                guard self.localTransportParameters.maxDatagramFrameSize > 0,
                      UInt64(frameLength) <= self.localTransportParameters.maxDatagramFrameSize else {
                    throw TransportError(
                        .protocolViolation,
                        frameType: frame.type,
                        reason: "DATAGRAM exceeds advertised limit"
                    )
                }
                self.emit(.datagramReceived(self.arena.slice(data) ?? Data(data)))
            case .handshakeDone:
                self.confirmHandshake(now: now)
            }
        }
        return outcome
    }

    private func processDelayedHandshakePacket(
        space: PacketNumberSpace,
        packetNumber: UInt64,
        plaintextLength: Int,
        receivedAt: Nanoseconds,
        now: Nanoseconds
    ) throws(TransportError) {
        var isACKEliciting = false
        try self.decryptBuffer.withUnsafeBufferPointer { (buffer) throws(TransportError) in
            var reader = InputBuffer(storage: UnsafeRawBufferPointer(UnsafeBufferPointer(rebasing: buffer[0..<plaintextLength])))
            while reader.byteCount > 0 {
                let frame = try reader.readFrame()
                guard frame.isAllowedInHandshakeLevels else {
                    throw TransportError(
                        .protocolViolation,
                        frameType: frame.type,
                        reason: "frame not allowed in Handshake packet"
                    )
                }
                if frame.isACKEliciting {
                    isACKEliciting = true
                }
                switch frame {
                case .ack(let ack):
                    self.isServerAddressVerified = true
                    try self.handleACK(ack, space: space, ackDelay: 0, receivedAt: receivedAt, now: now)
                case .crypto(let offset, let data):
                    try self.handleCrypto(space: space, offset: offset, data: data, now: now)
                case .connectionClose(let close):
                    self.handlePeerClose(close, now: now)
                default:
                    break
                }
            }
        }
        space.ackTracker.recordReceived(packetNumber, isACKEliciting: isACKEliciting, now: receivedAt, ackThreshold: 1)
        self.restartIdleTimerOnRead(now)
    }

    func scaledACKDelay(_ raw: UInt64) -> Nanoseconds {
        let maxACKDelay = ((1 << 14) - 1) * Time.millisecond
        let unit = (1 << self.peerACKDelayExponent) * Time.microsecond
        if raw > maxACKDelay / unit {
            return maxACKDelay
        }
        return raw * unit
    }

    func handlePathChallenge(_ data: UInt64, path: QUICPath) {
        guard self.active.path == path || self.pathValidation?.path == path else {
            return
        }
        self.pendingPathResponses.insert((data, path), at: 0)
        if self.pendingPathResponses.count > Self.maxPendingPathResponses {
            self.pendingPathResponses.removeLast()
        }
    }

    private func handleReceiveWhileClosing() {
        self.packetsSinceCloseResend += 1
        guard self.closePacket != nil, self.packetsSinceCloseResend >= self.closeResendThreshold else {
            return
        }
        self.packetsSinceCloseResend = 0
        self.closeResendThreshold = Swift.min(self.closeResendThreshold * 2, 64)
        self.isCloseResendPending = true
    }
}
