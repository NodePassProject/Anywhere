//
//  ConnectionCore+Streams.swift
//  AnywhereQUIC
//
//  Created by NodePassProject on 10/5/26.
//

import Foundation

extension ConnectionCore {
    func openStream(bidirectional: Bool) throws(QUICError) -> QUICStreamID {
        guard self.state == .handshaking || self.state == .established,
              let remote = self.remoteTransportParameters else {
            throw QUICError.invalidState
        }
        let id: QUICStreamID
        let stream: Stream
        if bidirectional {
            guard self.localBidirectionalNextIndex < self.localBidirectionalMaxStreams else {
                throw QUICError.streamIDBlocked
            }
            id = QUICStreamID(index: self.localBidirectionalNextIndex, bidirectional: true, clientInitiated: true)
            self.localBidirectionalNextIndex += 1
            stream = Stream(
                id: id,
                isLocal: true,
                sendMaxOffset: remote.initialMaxStreamDataBidirectionalRemote,
                receiveMaxOffset: self.localTransportParameters.initialMaxStreamDataBidirectionalLocal,
                canSend: true,
                canReceive: true
            )
        } else {
            guard self.localUnidirectionalNextIndex < self.localUnidirectionalMaxStreams else {
                throw QUICError.streamIDBlocked
            }
            id = QUICStreamID(index: self.localUnidirectionalNextIndex, bidirectional: false, clientInitiated: true)
            self.localUnidirectionalNextIndex += 1
            stream = Stream(
                id: id,
                isLocal: true,
                sendMaxOffset: remote.initialMaxStreamDataUnidirectional,
                receiveMaxOffset: 0,
                canSend: true,
                canReceive: false
            )
            stream.isReadClosed = true
        }
        self.streams[id] = stream
        return id
    }

    var availableBidirectionalStreams: UInt64 {
        return self.localBidirectionalNextIndex >= self.localBidirectionalMaxStreams
            ? 0 : self.localBidirectionalMaxStreams - self.localBidirectionalNextIndex
    }

    var availableUnidirectionalStreams: UInt64 {
        return self.localUnidirectionalNextIndex >= self.localUnidirectionalMaxStreams
            ? 0 : self.localUnidirectionalMaxStreams - self.localUnidirectionalNextIndex
    }

    func sendCapacity(on streamID: QUICStreamID) -> Int {
        guard let stream = self.streams[streamID], let send = stream.send, !stream.isWriteClosed, !send.hasFIN else {
            return 0
        }
        return self.sendCapacity(of: stream)
    }

    func sendCapacity(of stream: Stream) -> Int {
        guard let send = stream.send else {
            return 0
        }
        return Swift.max(0, self.settings.maxStreamSendBufferSize - send.bufferedBytes)
    }

    @discardableResult
    func send(_ data: Data, on streamID: QUICStreamID, fin: Bool = false) throws(QUICError) -> Int {
        guard self.state == .handshaking || self.state == .established else {
            throw QUICError.invalidState
        }
        guard let stream = self.streams[streamID] else {
            throw QUICError.streamNotFound
        }
        guard stream.send != nil, !stream.isWriteClosed, !stream.hasSentResetStream, stream.send?.hasFIN == false else {
            throw QUICError.streamSendClosed
        }
        let capacity = self.sendCapacity(of: stream)
        let accepted = Swift.min(capacity, data.count)
        if accepted > 0 {
            data.prefix(accepted).withUnsafeBytes { stream.send!.append($0) }
        }
        if accepted < data.count {
            stream.wantsWritableEvent = true
        } else if fin {
            stream.send!.markFIN()
        }
        if stream.hasPendingSendData {
            self.enqueueStream(stream)
        }
        return accepted
    }

    func finishSending(on streamID: QUICStreamID) throws(QUICError) {
        try self.send(Data(), on: streamID, fin: true)
    }

    func resetStream(_ streamID: QUICStreamID, errorCode: UInt64) throws(QUICError) {
        guard let stream = self.streams[streamID] else {
            throw QUICError.streamNotFound
        }
        guard stream.send != nil else {
            throw QUICError.invalidArgument
        }
        self.shutdownWrite(of: stream, errorCode: errorCode)
    }

    func stopSending(on streamID: QUICStreamID, errorCode: UInt64) throws(QUICError) {
        guard let stream = self.streams[streamID] else {
            throw QUICError.streamNotFound
        }
        guard stream.receive != nil else {
            throw QUICError.invalidArgument
        }
        self.shutdownRead(of: stream, errorCode: errorCode)
    }

    func shutdownStream(_ streamID: QUICStreamID, errorCode: UInt64) {
        guard let stream = self.streams[streamID] else {
            return
        }
        if stream.receive != nil {
            self.shutdownRead(of: stream, errorCode: errorCode)
        }
        if stream.send != nil {
            self.shutdownWrite(of: stream, errorCode: errorCode)
        }
    }

    @discardableResult
    func extendReceiveWindow(for streamID: QUICStreamID, by count: Int) -> Bool {
        guard count > 0 else {
            return false
        }
        var isStreamUpdateDue = false
        if let stream = self.streams[streamID], stream.receive != nil {
            stream.receiveUnsentMaxOffset = Swift.min(
                stream.receiveUnsentMaxOffset.addingClamped(UInt64(count)),
                VarInt.max
            )
            if stream.shouldSendMaxStreamData() {
                self.enqueueStream(stream)
                isStreamUpdateDue = true
            }
        }
        self.extendConnectionReceiveWindow(by: UInt64(count))
        return isStreamUpdateDue || self.shouldSendMaxData
    }

    func extendConnectionReceiveWindow(by count: UInt64) {
        self.receiveUnsentMaxOffset = Swift.min(self.receiveUnsentMaxOffset.addingClamped(count), VarInt.max)
    }

    func shutdownWrite(of stream: Stream, errorCode: UInt64) {
        stream.setApplicationErrorCode(errorCode)
        if stream.hasSentResetStream || stream.isAllSendDataAcknowledged {
            return
        }
        stream.isWriteClosed = true
        stream.hasSentResetStream = true
        stream.isResetStreamPending = true
        stream.resetStreamErrorCode = errorCode
        stream.send?.discardAll()
        self.enqueueStream(stream)
    }

    func shutdownRead(of stream: Stream, errorCode: UInt64) {
        stream.setApplicationErrorCode(errorCode)
        if stream.hasSentStopSending || stream.hasReceivedResetStream {
            return
        }
        if stream.isReadClosed, stream.receiveOffset == stream.receiveLastOffset {
            return
        }
        stream.hasSentStopSending = true
        stream.isStopSendingPending = true
        stream.stopSendingErrorCode = errorCode
        stream.receive?.stopBuffering()
        self.enqueueStream(stream)
    }

    func enqueueStream(_ stream: Stream) {
        guard !stream.isQueued else {
            return
        }
        stream.isQueued = true
        self.streamSendQueue.append(stream.id)
    }

    func dequeueStream(_ stream: Stream) {
        guard stream.isQueued else {
            return
        }
        stream.isQueued = false
    }

    func closeStreamIfDone(_ stream: Stream) {
        guard stream.isClosed, self.streams[stream.id] != nil else {
            return
        }
        self.emit(.streamClosed(stream.id, applicationErrorCode: stream.applicationErrorCode))
        self.streams[stream.id] = nil
        self.dequeueStream(stream)
        if !stream.isLocal {
            if stream.id.isBidirectional {
                self.remoteBidirectionalUnsentMaxStreams = Swift.min(
                    self.remoteBidirectionalUnsentMaxStreams + 1,
                    StreamLimits.maxStreamCount
                )
            } else {
                self.remoteUnidirectionalUnsentMaxStreams = Swift.min(
                    self.remoteUnidirectionalUnsentMaxStreams + 1,
                    StreamLimits.maxStreamCount
                )
            }
        }
    }

    func notifyWritableIfNeeded(_ stream: Stream) {
        guard stream.wantsWritableEvent, !stream.isWriteClosed, self.sendCapacity(of: stream) > 0 else {
            return
        }
        stream.wantsWritableEvent = false
        self.emit(.streamWritable(stream.id))
    }

    private func resolveStream(
        _ rawID: UInt64,
        peerSendsToUs: Bool,
        frameType: FrameType
    ) throws(TransportError) -> Stream? {
        let id = QUICStreamID(rawValue: rawID)
        let isLocal = self.isLocalStream(id)
        if id.isBidirectional {
            if isLocal {
                guard id.index < self.localBidirectionalNextIndex else {
                    throw TransportError(
                        .streamStateError,
                        frameType: frameType,
                        reason: "frame for unopened local stream"
                    )
                }
            } else {
                guard id.ordinal <= self.remoteBidirectionalMaxStreams else {
                    throw TransportError(
                        .streamLimitError,
                        frameType: frameType,
                        reason: "peer exceeded bidirectional stream limit"
                    )
                }
            }
        } else if peerSendsToUs {
            guard !isLocal else {
                throw TransportError(
                    .streamStateError,
                    frameType: frameType,
                    reason: "frame received on send-only stream"
                )
            }
            guard id.ordinal <= self.remoteUnidirectionalMaxStreams else {
                throw TransportError(
                    .streamLimitError,
                    frameType: frameType,
                    reason: "peer exceeded unidirectional stream limit"
                )
            }
        } else {
            guard isLocal, id.index < self.localUnidirectionalNextIndex else {
                throw TransportError(
                    .streamStateError,
                    frameType: frameType,
                    reason: "frame received on receive-only stream"
                )
            }
        }
        if let stream = self.streams[id] {
            return stream
        }
        if isLocal {
            return nil
        }
        if id.isBidirectional {
            guard !self.remoteBidirectionalOpened.contains(id.index) else {
                return nil
            }
            self.remoteBidirectionalOpened.insert(id.index)
        } else {
            guard !self.remoteUnidirectionalOpened.contains(id.index) else {
                return nil
            }
            self.remoteUnidirectionalOpened.insert(id.index)
        }
        let remote = self.remoteTransportParameters
        let stream: Stream
        if id.isBidirectional {
            stream = Stream(
                id: id,
                isLocal: false,
                sendMaxOffset: remote?.initialMaxStreamDataBidirectionalLocal ?? 0,
                receiveMaxOffset: self.localTransportParameters.initialMaxStreamDataBidirectionalRemote,
                canSend: true,
                canReceive: true
            )
        } else {
            stream = Stream(
                id: id,
                isLocal: false,
                sendMaxOffset: 0,
                receiveMaxOffset: self.localTransportParameters.initialMaxStreamDataUnidirectional,
                canSend: false,
                canReceive: true
            )
            stream.isWriteClosed = true
        }
        self.streams[id] = stream
        self.emit(.streamOpened(id))
        return stream
    }

    func handleStreamFrame(
        streamID rawID: UInt64,
        offset: UInt64,
        data: UnsafeRawBufferPointer,
        fin: Bool,
        frameType: FrameType
    ) throws(TransportError) {
        guard VarInt.max - UInt64(data.count) >= offset else {
            throw TransportError(.flowControlError, frameType: frameType, reason: "stream offset overflow")
        }
        guard let stream = try self.resolveStream(rawID, peerSendsToUs: true, frameType: frameType) else {
            return
        }
        let end = offset + UInt64(data.count)
        guard stream.receiveMaxOffset >= end else {
            throw TransportError(.flowControlError, frameType: frameType, reason: "stream flow control violated")
        }
        if fin {
            if stream.isReadClosed {
                guard stream.receiveLastOffset == end else {
                    throw TransportError(.finalSizeError, frameType: frameType, reason: "final size changed")
                }
            } else if stream.receiveLastOffset > end {
                throw TransportError(.finalSizeError, frameType: frameType, reason: "final size below received data")
            }
        } else if stream.isReadClosed, stream.receiveLastOffset < end {
            throw TransportError(.finalSizeError, frameType: frameType, reason: "data beyond final size")
        }
        if stream.receiveLastOffset < end {
            let increase = end - stream.receiveLastOffset
            guard self.receiveMaxOffset - self.receiveOffset >= increase else {
                throw TransportError(
                    .flowControlError,
                    frameType: frameType,
                    reason: "connection flow control violated"
                )
            }
            self.receiveOffset += increase
        }
        let readOffset = stream.receiveOffset
        if fin {
            if stream.isReadClosed {
                if stream.hasReceivedResetStream {
                    return
                }
                if readOffset == end {
                    return
                }
            } else {
                stream.receiveLastOffset = end
                stream.isReadClosed = true
            }
        } else {
            stream.receiveLastOffset = Swift.max(stream.receiveLastOffset, end)
            if end <= readOffset {
                return
            }
            if stream.hasReceivedResetStream {
                return
            }
        }
        if stream.hasSentStopSending {
            if offset <= readOffset {
                let discarded = stream.receive!.discardOrderedData(upTo: end)
                self.extendConnectionReceiveWindow(by: discarded)
            } else {
                _ = stream.receive!.receive(offset: offset, data: data)
            }
            self.closeStreamIfDone(stream)
            return
        }
        if offset <= readOffset {
            let delivered = stream.receive!.receive(offset: offset, data: data) { self.arena.slice($0) } ?? Data()
            let finished = stream.isReadClosed && stream.receiveOffset == stream.receiveLastOffset
            if !delivered.isEmpty || finished {
                self.emit(.streamData(stream.id, delivered, fin: finished))
            }
        } else {
            _ = stream.receive!.receive(offset: offset, data: data)
        }
        self.closeStreamIfDone(stream)
    }

    func handleResetStream(
        streamID rawID: UInt64,
        errorCode: UInt64,
        finalSize: UInt64,
        frameType: FrameType = .resetStream
    ) throws(TransportError) {
        guard finalSize <= VarInt.max else {
            throw TransportError(.flowControlError, frameType: frameType, reason: "final size overflow")
        }
        guard let stream = try self.resolveStream(rawID, peerSendsToUs: true, frameType: frameType) else {
            return
        }
        if stream.isReadClosed {
            guard stream.receiveLastOffset == finalSize else {
                throw TransportError(.finalSizeError, frameType: frameType, reason: "RESET_STREAM final size mismatch")
            }
        } else if stream.receiveLastOffset > finalSize {
            throw TransportError(
                .finalSizeError,
                frameType: frameType,
                reason: "RESET_STREAM final size below received data"
            )
        }
        if stream.hasReceivedResetStream {
            return
        }
        guard stream.receiveMaxOffset >= finalSize else {
            throw TransportError(
                .flowControlError,
                frameType: frameType,
                reason: "RESET_STREAM exceeds stream flow control"
            )
        }
        let increase = finalSize - stream.receiveLastOffset
        guard self.receiveMaxOffset - self.receiveOffset >= increase else {
            throw TransportError(
                .flowControlError,
                frameType: frameType,
                reason: "RESET_STREAM exceeds connection flow control"
            )
        }
        self.emit(.streamReset(stream.id, errorCode: errorCode, finalSize: finalSize))
        self.receiveOffset += increase
        self.extendConnectionReceiveWindow(by: finalSize - stream.receiveOffset)
        stream.receiveLastOffset = finalSize
        stream.isReadClosed = true
        stream.hasReceivedResetStream = true
        stream.setApplicationErrorCode(errorCode)
        stream.receive?.stopBuffering()
        self.closeStreamIfDone(stream)
    }

    func handleStopSending(streamID rawID: UInt64, errorCode: UInt64) throws(TransportError) {
        guard let stream = try self.resolveStream(rawID, peerSendsToUs: false, frameType: FrameType.stopSending) else {
            return
        }
        if stream.hasReceivedStopSending {
            return
        }
        stream.setApplicationErrorCode(errorCode)
        if !stream.isAllSendDataAcknowledged, !stream.hasSentResetStream {
            stream.hasSentResetStream = true
            stream.isResetStreamPending = true
            stream.resetStreamErrorCode = errorCode
            self.enqueueStream(stream)
        }
        stream.isWriteClosed = true
        stream.hasReceivedStopSending = true
        self.emit(.streamSendingStopped(stream.id, errorCode: errorCode))
        stream.send?.discardAll()
        self.closeStreamIfDone(stream)
    }

    func handleStreamDataBlocked(streamID rawID: UInt64, limit: UInt64) throws(TransportError) {
        let frameType = FrameType.streamDataBlocked
        guard let stream = try self.resolveStream(rawID, peerSendsToUs: true, frameType: frameType) else {
            return
        }
        guard stream.receiveMaxOffset >= limit else {
            throw TransportError(
                .flowControlError,
                frameType: frameType,
                reason: "STREAM_DATA_BLOCKED exceeds stream flow control"
            )
        }
        guard limit > stream.receiveLastOffset else {
            return
        }
        guard !stream.isReadClosed else {
            throw TransportError(.finalSizeError, frameType: frameType, reason: "STREAM_DATA_BLOCKED beyond final size")
        }
        let increase = limit - stream.receiveLastOffset
        guard self.receiveMaxOffset - self.receiveOffset >= increase else {
            throw TransportError(
                .flowControlError,
                frameType: frameType,
                reason: "STREAM_DATA_BLOCKED exceeds connection flow control"
            )
        }
        self.receiveOffset += increase
        stream.receiveLastOffset = limit
    }

    func handleDataBlocked(_ limit: UInt64) throws(TransportError) {
        guard limit <= self.receiveMaxOffset else {
            throw TransportError(
                .flowControlError,
                frameType: FrameType.dataBlocked,
                reason: "DATA_BLOCKED exceeds flow control limit"
            )
        }
    }

    func handleStreamsBlocked(bidirectional: Bool, limit: UInt64) throws(TransportError) {
        let maximum = bidirectional ? self.remoteBidirectionalMaxStreams : self.remoteUnidirectionalMaxStreams
        let frameType = bidirectional ? FrameType.streamsBlockedBidirectional : FrameType.streamsBlockedUnidirectional
        guard limit <= maximum else {
            throw TransportError(
                .frameEncodingError,
                frameType: frameType,
                reason: "STREAMS_BLOCKED exceeds advertised limit"
            )
        }
    }

    func handleMaxStreamData(streamID rawID: UInt64, maximum: UInt64) throws(TransportError) {
        guard let stream = try self.resolveStream(
            rawID,
            peerSendsToUs: false,
            frameType: FrameType.maxStreamData
        ) else {
            return
        }
        guard stream.sendMaxOffset < maximum else {
            return
        }
        stream.sendMaxOffset = maximum
        if stream.hasPendingSendData {
            self.enqueueStream(stream)
        }
    }

    func handleMaxData(_ maximum: UInt64) {
        guard self.sendMaxOffset < maximum else {
            return
        }
        self.sendMaxOffset = maximum
        for stream in self.streams.values where stream.hasPendingSendData {
            self.enqueueStream(stream)
        }
    }

    func handleMaxStreams(bidirectional: Bool, maximum: UInt64) {
        if bidirectional {
            guard self.localBidirectionalMaxStreams < maximum else {
                return
            }
            self.localBidirectionalMaxStreams = maximum
        } else {
            guard self.localUnidirectionalMaxStreams < maximum else {
                return
            }
            self.localUnidirectionalMaxStreams = maximum
        }
        self.emit(.streamLimitUpdated(bidirectional: bidirectional, maximumStreams: maximum))
    }

    var shouldSendMaxData: Bool {
        return self.receiveWindow < 4 * (self.receiveUnsentMaxOffset - self.receiveMaxOffset)
    }

    var shouldSendDataBlocked: Bool {
        return self.sendOffset == self.sendMaxOffset && self.sendLastBlockedOffset != self.sendMaxOffset
    }
}
