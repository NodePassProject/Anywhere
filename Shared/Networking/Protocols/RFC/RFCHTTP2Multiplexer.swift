//
//  RFCHTTP2Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 9/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "RFCHTTP2Multiplexer")

nonisolated final class RFCHTTP2Multiplexer: Multiplexer, Sendable {

    // MARK: - Types

    enum Phase: PhaseTransitionable {
        case idle
        case ready
        case draining
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .ready),
                 (.idle, .draining),
                 (.ready, .draining):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }

        var acceptsNewStreams: Bool { self == .idle || self == .ready }
    }
    
    private struct StreamFlow {
        var sendWindow: Int
        var gate = H2FlowGate()
        var unconsumed = 0
        var pendingCredit = 0
    }
    
    private struct PendingOpen {
        let inbox = AsyncInbox<Int>()
        var watchdog: DeadlineToken?
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var streams: [UInt32: RFCHTTP2Stream] = [:]
        var flow: [UInt32: StreamFlow] = [:]
        var pendingOpens: [UInt32: PendingOpen] = [:]
        
        var nextStreamID: UInt32 = 1
        var reservations = 0
        
        var connectionSendWindow = 65_535
        var connectionGate = H2FlowGate()
        var connectionPendingCredit = 0
        
        var peerInitialWindowSize = 65_535
        var peerMaxFrameSize = 16_384
        var peerMaxConcurrentStreams = RFCProtocol.http2DefaultMaxConcurrentStreams
        
        var goawayLastStreamID: UInt32?

        var receiveBuffer = Data()
        var headerFragment: (streamID: UInt32, endStream: Bool, block: Data)?

        var readTask: Task<Void, Never>?
    }

    // MARK: - Properties

    private let inner: ProxyConnection
    private let outerTLSVersion: TLSVersion?
    private let state: Mutex<State>
    private let sendChain = SerialSender()
    private let terminated = OneShotLatch()

    let seq: UInt64

    private let onClose: (@Sendable (RFCHTTP2Multiplexer) -> Void)?
    
    private static let openTimeout: TimeInterval = 30

    // MARK: - Init

    init(
        inner: ProxyConnection,
        seq: UInt64 = 0,
        onClose: (@Sendable (RFCHTTP2Multiplexer) -> Void)? = nil
    ) {
        self.inner = inner
        self.outerTLSVersion = inner.outerTLSVersion
        self.seq = seq
        self.onClose = onClose
        self.state = Mutex(State())
    }

    // MARK: - Multiplexer

    var isClosed: Bool { state.withLock { $0.phase == .closed } }

    var activeStreamCount: Int { state.withLock { $0.streams.count + $0.reservations } }

    // MARK: - Capacity
    
    func tryReserveStream() -> Bool {
        state.withLock { state in
            guard state.phase.acceptsNewStreams else { return false }
            let limit = min(state.peerMaxConcurrentStreams, RFCProtocol.http2MaxConcurrentStreamsCap)
            guard state.streams.count + state.reservations < limit else { return false }
            state.reservations += 1
            return true
        }
    }

    func releaseReservation() {
        state.withLock { state in
            if state.reservations > 0 { state.reservations -= 1 }
        }
    }

    // MARK: - Lifecycle
    
    func start() async throws {
        guard state.withLock({ $0.transition(to: .ready) }) else { return }

        var preface = RFCProtocol.http2Preface
        preface.append(HTTP2Framer.settingsFrame([
            (id: RFCProtocol.HTTP2SettingID.enablePush, value: 0),
            (id: RFCProtocol.HTTP2SettingID.initialWindowSize, value: RFCProtocol.http2StreamWindowSize),
            (id: RFCProtocol.HTTP2SettingID.maxHeaderListSize, value: UInt32(HPACKDecoder.maxDecodedHeaderListSize)),
        ]).serialized)
        preface.append(HTTP2Framer.windowUpdateFrame(
            streamID: 0,
            increment: RFCProtocol.http2ConnectionWindowSize - 65_535
        ).serialized)

        let prologue = preface
        do {
            try await sendChain.run { [inner] in try await inner.send(prologue) }
        } catch {
            close(error: error)
            throw error
        }
        startReadLoop()
    }

    private func startReadLoop() {
        let task = Task { [weak self] in
            guard let self else { return }
            do {
                try await self.readLoop()
                self.close(error: AnywhereError.proxy(.http2, .connectionClosed(detail: "RFC session closed by peer")))
            } catch {
                self.close(error: error)
            }
        }
        state.withLock { $0.readTask = task }
    }

    func close(error: Error?) {
        guard terminated.claim() else { return }

        typealias Teardown = (
            streams: [RFCHTTP2Stream],
            pending: [PendingOpen],
            readTask: Task<Void, Never>?
        )
        let teardown: Teardown = state.withLock { state in
            state.transition(to: .closed)
            let streams = Array(state.streams.values)
            let pending = Array(state.pendingOpens.values)
            let readTask = state.readTask
            state.streams.removeAll()
            state.pendingOpens.removeAll()
            state.connectionGate.wakeAll()
            for id in Array(state.flow.keys) {
                state.flow[id]!.gate.wakeAll()
            }
            state.flow.removeAll()
            state.readTask = nil
            return (streams, pending, readTask)
        }

        for open in teardown.pending {
            open.watchdog?.cancel()
            open.inbox.finish(throwing: error ?? AnywhereError.proxy(.http2, .connectionClosed(detail: "RFC session closed")))
        }
        for stream in teardown.streams {
            stream.deliverClose(error: error)
        }
        teardown.readTask?.cancel()
        sendChain.cancel()
        inner.cancel()
        onClose?(self)
    }

    // MARK: - Opening a tunnel
    
    func openTunnel(
        authority: String,
        credentials: String?,
        onEnd: (@Sendable () -> Void)? = nil
    ) async throws -> RFCHTTP2Stream {
        typealias Opened = (
            stream: RFCHTTP2Stream,
            streamID: UInt32,
            handshake: AsyncInbox<Int>,
            headersSent: SerialSender.Pending
        )
        let headerBlock = RFCProtocol.http2ConnectHeaders(authority: authority, credentials: credentials)
        let outcome: Result<Opened, AnywhereError> = state.withLock { state in
            guard state.phase.acceptsNewStreams else { return .failure(.proxy(.http2, .notReady)) }
            guard state.nextStreamID <= 0x7FFF_FFFF else { return .failure(.proxy(.http2, .streamIDsExhausted)) }
            guard headerBlock.count <= state.peerMaxFrameSize else {
                return .failure(.proxy(.http2, .protocolViolation(detail: "CONNECT header block too large")))
            }
            let streamID = state.nextStreamID
            state.nextStreamID &+= 2

            let stream = RFCHTTP2Stream(
                streamID: streamID,
                multiplexer: self,
                outerTLSVersion: outerTLSVersion,
                onEnd: onEnd
            )
            state.streams[streamID] = stream
            state.flow[streamID] = StreamFlow(sendWindow: state.peerInitialWindowSize)
            let pending = PendingOpen()
            state.pendingOpens[streamID] = pending
            if state.reservations > 0 { state.reservations -= 1 }
            let frame = HTTP2Framer.headersFrame(streamID: streamID, headerBlock: headerBlock)
            let headersSent = sendChain.submit { [inner] in try await inner.send(frame.serialized) }
            return .success((stream, streamID, pending.inbox, headersSent))
        }

        let opened: Opened
        switch outcome {
        case .failure(let error):
            releaseReservation()
            throw error
        case .success(let value):
            opened = value
        }

        do {
            try await opened.headersSent.value()
        } catch {
            failOpen(streamID: opened.streamID, error: error)
            throw error
        }

        armOpenWatchdog(streamID: opened.streamID)

        let status: Int
        do {
            guard let awaited = try await opened.handshake.next() else {
                throw AnywhereError.proxy(.http2, .connectionClosed(detail: "RFC session closed during CONNECT"))
            }
            status = awaited
        } catch {
            failOpen(streamID: opened.streamID, error: error)
            throw error
        }

        if let error = RFCProtocol.tunnelError(status: status, reason: nil, wire: .http2) {
            failOpen(streamID: opened.streamID, error: error)
            throw error
        }
        
        return opened.stream
    }

    private func armOpenWatchdog(streamID: UInt32) {
        let watchdog = TickScheduler.shared.schedule(in: .seconds(Self.openTimeout), precision: .relaxed) { [weak self] in
            self?.failOpen(streamID: streamID, error: AnywhereError.proxy(.http2, .openTimeout))
        }
        let stale: DeadlineToken? = state.withLock { state in
            guard state.pendingOpens[streamID] != nil else { return watchdog }
            let previous = state.pendingOpens[streamID]?.watchdog
            state.pendingOpens[streamID]?.watchdog = watchdog
            return previous
        }
        stale?.cancel()
    }
    
    private func failOpen(streamID: UInt32, error: Error) {
        let pending: PendingOpen? = state.withLock { $0.pendingOpens.removeValue(forKey: streamID) }
        pending?.watchdog?.cancel()
        pending?.inbox.finish(throwing: error)
        let stream = state.withLock { $0.streams[streamID] }
        resetStream(streamID: streamID, errorCode: RFCProtocol.HTTP2ErrorCode.cancel)
        stream?.deliverClose(error: error)
    }

    // MARK: - Sending
    
    func sendData(streamID: UInt32, data: Data) async throws {
        var offset = data.startIndex
        while offset < data.endIndex {
            let grant = try await reserveSendWindow(streamID: streamID, wanted: data.distance(from: offset, to: data.endIndex))
            let end = data.index(offset, offsetBy: grant)
            let chunk = Data(data[offset..<end])
            offset = end

            let frame = HTTP2Framer.dataFrame(streamID: streamID, payload: chunk)
            do {
                try await sendChain.run { [inner] in try await inner.send(frame.serialized) }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                close(error: error)
                throw error
            }
        }
    }
    
    private func reserveSendWindow(streamID: UInt32, wanted: Int) async throws -> Int {
        enum Outcome {
            case granted(Int)
            case waitConnection(AsyncStream<Never>)
            case waitStream(AsyncStream<Never>)
            case failed(Error)
        }

        while true {
            let outcome: Outcome = state.withLock { state in
                guard state.phase != .closed else {
                    return .failed(AnywhereError.proxy(.http2, .connectionClosed(detail: "RFC session closed")))
                }
                guard let flow = state.flow[streamID] else {
                    return .failed(AnywhereError.proxy(.http2, .streamClosed))
                }
                if state.connectionSendWindow <= 0 {
                    return .waitConnection(state.connectionGate.enroll())
                }
                if flow.sendWindow <= 0 {
                    return .waitStream(state.flow[streamID]!.gate.enroll())
                }
                let grant = min(wanted, state.connectionSendWindow, flow.sendWindow, state.peerMaxFrameSize)
                state.connectionSendWindow -= grant
                state.flow[streamID]!.sendWindow -= grant
                return .granted(grant)
            }

            switch outcome {
            case .granted(let grant):
                return grant
            case .failed(let error):
                throw error
            case .waitConnection(let gate), .waitStream(let gate):
                for await _ in gate {}
                try Task.checkCancellation()
            }
        }
    }
    
    func resetStream(streamID: UInt32, errorCode: UInt32) {
        let taken: (live: Bool, owed: Int) = state.withLock { state in
            var flow = state.flow.removeValue(forKey: streamID)
            flow?.gate.wakeAll()
            state.streams.removeValue(forKey: streamID)
            return (state.phase != .closed, flow?.unconsumed ?? 0)
        }
        guard taken.live else { return }
        let frame = HTTP2Framer.rstStreamFrame(streamID: streamID, errorCode: errorCode)
        _ = sendChain.submit { [inner] in try await inner.send(frame.serialized) }
        creditConnection(bytes: taken.owed)
    }

    // MARK: - Receive-side flow control
    
    func streamDidConsume(streamID: UInt32, bytes: Int) {
        enum Credit {
            case none
            case update(stream: UInt32?, connection: UInt32?)
        }
        
        let streamThreshold = Int(RFCProtocol.http2StreamWindowSize) / 2
        let connectionThreshold = Int(RFCProtocol.http2ConnectionWindowSize) / 2

        let credit: Credit = state.withLock { state in
            guard state.phase != .closed else { return .none }
            guard state.flow[streamID] != nil else { return .none }
            var streamCredit: UInt32?
            state.flow[streamID]!.unconsumed = max(0, state.flow[streamID]!.unconsumed - bytes)
            state.flow[streamID]!.pendingCredit += bytes
            if state.flow[streamID]!.pendingCredit >= streamThreshold {
                streamCredit = UInt32(state.flow[streamID]!.pendingCredit)
                state.flow[streamID]!.pendingCredit = 0
            }
            var connectionCredit: UInt32?
            state.connectionPendingCredit += bytes
            if state.connectionPendingCredit >= connectionThreshold {
                connectionCredit = UInt32(state.connectionPendingCredit)
                state.connectionPendingCredit = 0
            }
            guard streamCredit != nil || connectionCredit != nil else { return .none }
            return .update(stream: streamCredit, connection: connectionCredit)
        }

        guard case .update(let streamCredit, let connectionCredit) = credit else { return }
        var updates = Data()
        if let connectionCredit {
            updates.append(HTTP2Framer.windowUpdateFrame(streamID: 0, increment: connectionCredit).serialized)
        }
        if let streamCredit {
            updates.append(HTTP2Framer.windowUpdateFrame(streamID: streamID, increment: streamCredit).serialized)
        }
        let frames = updates
        _ = sendChain.submit { [inner] in try await inner.send(frames) }
    }
    
    func creditConnection(bytes: Int) {
        guard bytes > 0 else { return }
        let credit: UInt32? = state.withLock { state in
            guard state.phase != .closed else { return nil }
            state.connectionPendingCredit += bytes
            let threshold = Int(RFCProtocol.http2ConnectionWindowSize) / 2
            guard state.connectionPendingCredit >= threshold else { return nil }
            let credit = UInt32(state.connectionPendingCredit)
            state.connectionPendingCredit = 0
            return credit
        }
        guard let credit else { return }
        let frame = HTTP2Framer.windowUpdateFrame(streamID: 0, increment: credit)
        _ = sendChain.submit { [inner] in try await inner.send(frame.serialized) }
    }
    
    func detachStream(streamID: UInt32) -> (stream: RFCHTTP2Stream?, owed: Int) {
        state.withLock { state in
            var flow = state.flow.removeValue(forKey: streamID)
            flow?.gate.wakeAll()
            let stream = state.streams.removeValue(forKey: streamID)
            return (stream, flow?.unconsumed ?? 0)
        }
    }
}

// MARK: - Frame Handling

nonisolated extension RFCHTTP2Multiplexer {
    private static var headersPriorityFlag: UInt8 { 0x20 }
    
    func readLoop() async throws {
        let decoder = HPACKDecoder()

        while true {
            guard let chunk = try await inner.receive() else { return }
            guard !chunk.isEmpty else { continue }

            let frames: [HTTP2Frame] = try state.withLock { state in
                state.receiveBuffer.appendCompacting(chunk)
                var frames: [HTTP2Frame] = []
                while let declaredLength = HTTP2Framer.declaredPayloadLength(in: state.receiveBuffer) {
                    guard declaredLength <= RFCProtocol.http2MaxFrameSize else {
                        throw AnywhereError.proxy(.http2, .protocolViolation(
                            detail: "Frame of \(declaredLength) bytes exceeds SETTINGS_MAX_FRAME_SIZE"
                        ))
                    }
                    let typeByte = state.receiveBuffer[state.receiveBuffer.startIndex + 3]
                    let known = HTTP2FrameType(rawValue: typeByte) != nil
                    guard let frame = HTTP2Framer.deserialize(from: &state.receiveBuffer) else { break }
                    if known { frames.append(frame) }
                }
                return frames
            }

            for frame in frames {
                try handle(frame, decoder: decoder)
            }
        }
    }

    private func handle(_ frame: HTTP2Frame, decoder: HPACKDecoder) throws {
        switch frame.type {
        case .data:
            try handleData(frame)
        case .headers:
            try handleHeaders(frame, decoder: decoder)
        case .continuation:
            try handleContinuation(frame, decoder: decoder)
        case .rstStream:
            handleRstStream(frame)
        case .settings:
            handleSettings(frame)
        case .ping:
            handlePing(frame)
        case .goaway:
            handleGoaway(frame)
        case .windowUpdate:
            try handleWindowUpdate(frame)
        }
    }

    // MARK: DATA

    private func handleData(_ frame: HTTP2Frame) throws {
        guard frame.streamID != 0 else {
            throw AnywhereError.proxy(.http2, .protocolViolation(detail: "DATA on stream 0"))
        }
        let flowBytes = frame.payload.count
        let payload = try strippedPadding(of: frame)

        let stream: RFCHTTP2Stream? = try state.withLock { state in
            guard let stream = state.streams[frame.streamID] else { return nil }
            let unconsumed = (state.flow[frame.streamID]?.unconsumed ?? 0) + flowBytes
            guard unconsumed <= Int(RFCProtocol.http2StreamWindowSize) else {
                throw AnywhereError.proxy(.http2, .protocolViolation(detail: "Peer exceeded the stream flow-control window"))
            }
            state.flow[frame.streamID]?.unconsumed = unconsumed
            return stream
        }

        guard let stream else {
            creditConnection(bytes: flowBytes)
            return
        }

        if !payload.isEmpty {
            stream.deliverData(payload)
        }
        let padding = flowBytes - payload.count
        if padding > 0 {
            streamDidConsume(streamID: frame.streamID, bytes: padding)
        }

        if frame.hasFlag(HTTP2FrameFlags.endStream) {
            let detached = detachStream(streamID: frame.streamID)
            creditConnection(bytes: detached.owed)
            if detached.stream != nil { closeLocalHalf(streamID: frame.streamID) }
            stream.deliverClose(error: nil)
        }
    }
    
    private func closeLocalHalf(streamID: UInt32) {
        guard !isClosed else { return }
        let frame = HTTP2Framer.rstStreamFrame(streamID: streamID, errorCode: RFCProtocol.HTTP2ErrorCode.noError)
        _ = sendChain.submit { [inner] in try await inner.send(frame.serialized) }
    }
    
    private func strippedPadding(of frame: HTTP2Frame) throws -> Data {
        var payload = frame.payload
        if frame.hasFlag(HTTP2FrameFlags.padded) {
            guard let padLength = payload.first.map({ Int($0) }),
                  payload.count >= padLength + 1 else {
                throw AnywhereError.proxy(.http2, .protocolViolation(detail: "Padding longer than frame payload"))
            }
            payload = Data(payload.dropFirst().dropLast(padLength))
        }
        if frame.type == .headers, frame.hasFlag(Self.headersPriorityFlag) {
            guard payload.count >= 5 else {
                throw AnywhereError.proxy(.http2, .protocolViolation(detail: "HEADERS shorter than its priority field"))
            }
            payload = Data(payload.dropFirst(5))
        }
        return payload
    }

    // MARK: HEADERS / CONTINUATION

    private func handleHeaders(_ frame: HTTP2Frame, decoder: HPACKDecoder) throws {
        guard frame.streamID != 0 else {
            throw AnywhereError.proxy(.http2, .protocolViolation(detail: "HEADERS on stream 0"))
        }
        let block = try strippedPadding(of: frame)
        let endStream = frame.hasFlag(HTTP2FrameFlags.endStream)

        guard frame.hasFlag(HTTP2FrameFlags.endHeaders) else {
            state.withLock { $0.headerFragment = (frame.streamID, endStream, block) }
            return
        }
        try completeHeaders(streamID: frame.streamID, endStream: endStream, block: block, decoder: decoder)
    }

    private func handleContinuation(_ frame: HTTP2Frame, decoder: HPACKDecoder) throws {
        enum Fragment {
            case pending
            case complete(streamID: UInt32, endStream: Bool, block: Data)
            case unexpected
            case oversize
        }

        let fragment: Fragment = state.withLock { state in
            guard var open = state.headerFragment, open.streamID == frame.streamID else {
                return .unexpected
            }
            open.block.append(frame.payload)
            guard open.block.count <= HPACKDecoder.maxDecodedHeaderListSize else {
                state.headerFragment = nil
                return .oversize
            }
            guard frame.hasFlag(HTTP2FrameFlags.endHeaders) else {
                state.headerFragment = open
                return .pending
            }
            state.headerFragment = nil
            return .complete(streamID: open.streamID, endStream: open.endStream, block: open.block)
        }

        switch fragment {
        case .pending:
            return
        case .unexpected:
            throw AnywhereError.proxy(.http2, .protocolViolation(detail: "Unexpected CONTINUATION on stream \(frame.streamID)"))
        case .oversize:
            throw AnywhereError.proxy(.http2, .protocolViolation(
                detail: "Header block exceeded \(HPACKDecoder.maxDecodedHeaderListSize) bytes"
            ))
        case .complete(let streamID, let endStream, let block):
            try completeHeaders(streamID: streamID, endStream: endStream, block: block, decoder: decoder)
        }
    }
    
    private func completeHeaders(streamID: UInt32, endStream: Bool, block: Data, decoder: HPACKDecoder) throws {
        guard let decoded = decoder.decodeHeaders(from: block) else {
            throw AnywhereError.proxy(.http2, .protocolViolation(detail: "Undecodable HPACK header block"))
        }

        let pending: PendingOpen? = state.withLock { $0.pendingOpens.removeValue(forKey: streamID) }

        var openAccepted = false
        if let pending {
            pending.watchdog?.cancel()
            guard let status = RFCProtocol.http2Status(from: decoded.fields) else {
                pending.inbox.finish(throwing: AnywhereError.proxy(.http2, .protocolViolation(
                    detail: "CONNECT response carried no :status"
                )))
                return
            }
            pending.inbox.yield(status)
            pending.inbox.finish()
            openAccepted = RFCProtocol.tunnelError(status: status, reason: nil, wire: .http2) == nil
        }

        if endStream {
            let detached = detachStream(streamID: streamID)
            creditConnection(bytes: detached.owed)
            if pending == nil || openAccepted, detached.stream != nil { closeLocalHalf(streamID: streamID) }
            detached.stream?.deliverClose(error: nil)
        }
    }

    // MARK: RST_STREAM

    private func handleRstStream(_ frame: HTTP2Frame) {
        let code = HTTP2Framer.parseRstStream(payload: frame.payload) ?? RFCProtocol.HTTP2ErrorCode.cancel
        let error: Error? = code == RFCProtocol.HTTP2ErrorCode.noError
            ? nil
            : AnywhereError.proxy(.http2, .streamReset(code: code))

        let pending: PendingOpen? = state.withLock { $0.pendingOpens.removeValue(forKey: frame.streamID) }
        if let pending {
            pending.watchdog?.cancel()
            pending.inbox.finish(throwing: error ?? AnywhereError.proxy(.http2, .streamClosed))
        }
        
        let detached = detachStream(streamID: frame.streamID)
        creditConnection(bytes: detached.owed)
        detached.stream?.deliverClose(error: error)
    }

    // MARK: SETTINGS

    private func handleSettings(_ frame: HTTP2Frame) {
        guard !frame.hasFlag(HTTP2FrameFlags.ack) else { return }

        let settings = HTTP2Framer.parseSettings(payload: frame.payload)
        _ = state.withLock { state in
            var windowChanged = false
            for setting in settings {
                switch setting.id {
                case RFCProtocol.HTTP2SettingID.maxConcurrentStreams:
                    state.peerMaxConcurrentStreams = Int(min(setting.value, UInt32(Int32.max)))
                case RFCProtocol.HTTP2SettingID.initialWindowSize:
                    let updated = Int(min(setting.value, UInt32(Int32.max)))
                    let delta = updated - state.peerInitialWindowSize
                    state.peerInitialWindowSize = updated
                    if delta != 0 {
                        for id in Array(state.flow.keys) {
                            state.flow[id]!.sendWindow += delta
                        }
                        if delta > 0 { windowChanged = true }
                    }
                case RFCProtocol.HTTP2SettingID.maxFrameSize:
                    state.peerMaxFrameSize = Int(max(16_384, min(setting.value, 16_777_215)))
                default:
                    break
                }
            }
            guard windowChanged else { return false }
            for id in Array(state.flow.keys) {
                state.flow[id]!.gate.wakeAll()
            }
            return true
        }

        let ack = HTTP2Framer.settingsAckFrame()
        _ = sendChain.submit { [inner] in try await inner.send(ack.serialized) }
    }

    // MARK: PING

    private func handlePing(_ frame: HTTP2Frame) {
        guard !frame.hasFlag(HTTP2FrameFlags.ack), frame.payload.count == 8 else { return }
        let ack = HTTP2Framer.pingAckFrame(opaqueData: frame.payload)
        _ = sendChain.submit { [inner] in try await inner.send(ack.serialized) }
    }

    // MARK: GOAWAY

    private func handleGoaway(_ frame: HTTP2Frame) {
        let parsed = HTTP2Framer.parseGoaway(payload: frame.payload)
        let lastStreamID = parsed?.lastStreamID ?? 0
        
        typealias Abandoned = (streams: [RFCHTTP2Stream], pending: [PendingOpen])
        let abandoned: Abandoned = state.withLock { state in
            state.transition(to: .draining)
            state.goawayLastStreamID = lastStreamID
            let ids = state.streams.keys.filter { $0 > lastStreamID }
            var streams: [RFCHTTP2Stream] = []
            var pending: [PendingOpen] = []
            for id in ids {
                if let stream = state.streams.removeValue(forKey: id) { streams.append(stream) }
                if let open = state.pendingOpens.removeValue(forKey: id) { pending.append(open) }
                if var flow = state.flow.removeValue(forKey: id) { flow.gate.wakeAll() }
            }
            return (streams, pending)
        }

        for open in abandoned.pending {
            open.watchdog?.cancel()
            open.inbox.finish(throwing: AnywhereError.proxy(.http2, .goaway))
        }
        for stream in abandoned.streams {
            stream.deliverClose(error: AnywhereError.proxy(.http2, .goaway))
        }
    }

    // MARK: WINDOW_UPDATE

    private func handleWindowUpdate(_ frame: HTTP2Frame) throws {
        guard let increment = HTTP2Framer.parseWindowUpdate(payload: frame.payload), increment > 0 else {
            guard frame.streamID != 0 else {
                throw AnywhereError.proxy(.http2, .protocolViolation(detail: "WINDOW_UPDATE with a zero increment"))
            }
            resetStream(streamID: frame.streamID, errorCode: RFCProtocol.HTTP2ErrorCode.cancel)
            return
        }
        
        let maxWindow = Int(Int32.max)
        enum Update { case none, stream(UInt32), connection, overflow }

        let update: Update = state.withLock { state in
            guard state.phase != .closed else { return .none }
            if frame.streamID == 0 {
                let updated = state.connectionSendWindow + Int(increment)
                guard updated <= maxWindow else { return .overflow }
                state.connectionSendWindow = updated
                state.connectionGate.wakeAll()
                return .connection
            }
            guard state.flow[frame.streamID] != nil else { return .none }
            let updated = state.flow[frame.streamID]!.sendWindow + Int(increment)
            guard updated <= maxWindow else { return .overflow }
            state.flow[frame.streamID]!.sendWindow = updated
            state.flow[frame.streamID]!.gate.wakeAll()
            return .stream(frame.streamID)
        }

        switch update {
        case .none, .connection, .stream:
            return
        case .overflow:
            guard frame.streamID != 0 else {
                throw AnywhereError.proxy(.http2, .protocolViolation(detail: "Connection send window overflowed"))
            }
            resetStream(streamID: frame.streamID, errorCode: RFCProtocol.HTTP2ErrorCode.cancel)
        }
    }
}
