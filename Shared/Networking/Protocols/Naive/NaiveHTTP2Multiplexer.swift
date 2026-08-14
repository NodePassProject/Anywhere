//
//  NaiveHTTP2Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Multiplexer")

nonisolated final class NaiveHTTP2Multiplexer: Multiplexer, Sendable {

    // MARK: - Phase

    enum Phase: PhaseTransitionable {
        case idle
        case connecting
        case prefaceSent
        case ready
        case goingAway
        case closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .prefaceSent),
                 (.prefaceSent, .ready):
                return true
            case (_, .goingAway):
                return old != .goingAway && old != .closed
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    // MARK: - Properties

    let host: String
    let port: UInt16
    let sni: String

    private let transport: TLSStreamTransport

    private let sendChain = SerialSender()
    private func chainSend(_ data: Data) -> SerialSender.Pending {
        let transport = self.transport
        return sendChain.submit { try await transport.send(data) }
    }

    private let connectHeaders: @Sendable () -> [(name: String, value: String)]

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var streams: [UInt32: NaiveHTTP2Stream] = [:]
        var reservedStreams = 0
        var liveStreamCount: Int { streams.count + reservedStreams }
        var sendWindows: [UInt32: Int] = [:]
        var nextStreamID: UInt32 = 1
        var maxConcurrentStreams: UInt32 = 100

        var connectionSendWindow: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize
        var connectionReceiveConsumed: Int = 0
        var connectionReceiveWindowSize: Int = NaiveHTTP2FlowControl.naiveSessionMaxReceiveWindow
        var peerInitialWindowSize: Int = NaiveHTTP2FlowControl.defaultInitialWindowSize

        var receiveBuffer = Data()

        var flowGate = H2FlowGate()

        var sessionTask: Task<Void, Never>?
    }
    private let state = Mutex(State())

    private static let maxReceiveBufferSize = 2_097_152


    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    private let onClose: (@Sendable (NaiveHTTP2Multiplexer) -> Void)?

    // MARK: - Initialization

    init(host: String, port: UInt16, sni: String, tunnel: ProxyConnection?,
         connectHeaders: @escaping @Sendable () -> [(name: String, value: String)],
         onClose: (@Sendable (NaiveHTTP2Multiplexer) -> Void)? = nil) {
        self.host = host
        self.port = port
        self.sni = sni
        self.connectHeaders = connectHeaders
        self.onClose = onClose
        self.transport = TLSStreamTransport(
            host: host,
            port: port,
            sni: sni,
            alpn: ["h2"],
            tunnel: tunnel
        )
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
    }

    // MARK: - Capacity

    var activeStreamCount: Int { state.withLock { $0.liveStreamCount } }

    var isClosed: Bool { state.withLock { $0.phase == .closed } }
    var poolIsGoingAway: Bool { state.withLock { $0.phase == .goingAway } }

    func tryReserveStream() -> Bool {
        state.withLock { state in
            switch state.phase {
            case .idle, .connecting, .prefaceSent, .ready:
                break
            case .goingAway, .closed:
                return false
            }
            guard UInt32(state.liveStreamCount) < state.maxConcurrentStreams else { return false }
            state.reservedStreams += 1
            return true
        }
    }

    // MARK: - Session Setup

    func ensureReady() async throws {
        enum Action { case ready; case park; case beginAndPark; case fail }
        let action: Action = state.withLock { state in
            switch state.phase {
            case .ready:
                return .ready
            case .idle:
                state.transition(to: .connecting)
                return .beginAndPark
            case .connecting, .prefaceSent:
                return .park
            case .goingAway, .closed:
                return .fail
            }
        }
        switch action {
        case .ready:
            return
        case .fail:
            throw AnywhereError.proxy(.naive, .notReady)
        case .beginAndPark:
            beginSetup()
            try await readyTask.value
        case .park:
            try await readyTask.value
        }
    }

    private func beginSetup() {
        let task = Task {
            do {
                try await transport.connect()
            } catch {
                teardown(reason: error)
                return
            }
            guard await sendConnectionPreface() else { return }
            await runReadLoop()
        }
        state.withLock { state in
            if state.phase == .closed {
                task.cancel()
            } else {
                state.sessionTask = task
            }
        }
    }

    // MARK: - Stream Lifecycle

    func openStream(destination: String) -> NaiveHTTP2Stream {
        state.withLock { state in
            state.reservedStreams = max(0, state.reservedStreams - 1)
            let streamID = state.nextStreamID
            state.nextStreamID += 2  // Client streams are odd-numbered
            let stream = NaiveHTTP2Stream(
                streamID: streamID,
                multiplexer: self,
                destination: destination
            )
            switch state.phase {
            case .goingAway, .closed:
                break
            case .idle, .connecting, .prefaceSent, .ready:
                state.streams[streamID] = stream
                state.sendWindows[streamID] = state.peerInitialWindowSize
            }
            return stream
        }
    }

    func removeStream(_ stream: NaiveHTTP2Stream) {
        let shouldClose: Bool = state.withLock { state in
            state.streams.removeValue(forKey: stream.streamID)
            state.sendWindows.removeValue(forKey: stream.streamID)
            return state.phase == .goingAway && state.streams.isEmpty && state.reservedStreams == 0
        }
        if shouldClose {
            close()
        }
    }

    func reseedStreamSendWindow(_ streamID: UInt32) {
        state.withLock { state in
            if state.sendWindows[streamID] != nil {
                state.sendWindows[streamID] = state.peerInitialWindowSize
            }
        }
    }

    // MARK: - Connection Preface

    private static let connectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".data(using: .ascii)!

    private func sendConnectionPreface() async -> Bool {
        var data = Data()

        data.append(Self.connectionPreface)

        let settings = NaiveHTTP2Framer.settingsFrame([
            (id: 0x1, value: 65536),     // HEADER_TABLE_SIZE
            (id: 0x2, value: 0),         // ENABLE_PUSH
            (id: 0x3, value: 100),       // MAX_CONCURRENT_STREAMS
            (id: 0x4, value: UInt32(NaiveHTTP2FlowControl.naiveInitialWindowSize)),
            (id: 0x5, value: 16384),     // MAX_FRAME_SIZE
            (id: 0x6, value: 262144),    // MAX_HEADER_LIST_SIZE
        ])
        data.append(settings.serialized)

        let windowUpdate = NaiveHTTP2Framer.windowUpdateFrame(
            streamID: 0,
            increment: NaiveHTTP2FlowControl.connectionWindowUpdateIncrement
        )
        data.append(windowUpdate.serialized)

        let prefaceSend = chainSend(data)
        do {
            try await prefaceSend.value()
        } catch {
            teardown(reason: error)
            return false
        }
        return state.withLock { $0.transition(to: .prefaceSent) }
    }

    // MARK: - Read Loop

    private func runReadLoop() async {
        let hpackDecoder = HPACKDecoder()
        while true {
            if state.withLock({ $0.phase == .closed }) { return }

            let data: Data?
            do { data = try await transport.receive() }
            catch { handleSessionError(error); return }

            guard let data, !data.isEmpty else {
                handleSessionError(AnywhereError.proxy(.naive, .connectionClosed(detail: "Connection closed")))
                return
            }

            let overflow: Bool = state.withLock { state in
                guard state.phase != .closed else { return false }
                state.receiveBuffer.append(data)
                if state.receiveBuffer.count > Self.maxReceiveBufferSize {
                    state.receiveBuffer.removeAll()
                    return true
                }
                return false
            }
            if overflow {
                handleSessionError(AnywhereError.proxy(.naive, .connectionClosed(detail: "Receive buffer exceeded \(Self.maxReceiveBufferSize) bytes")))
                return
            }

            drainFrames(hpackDecoder: hpackDecoder)
        }
    }

    private func drainFrames(hpackDecoder: HPACKDecoder) {
        while true {
            let frame: NaiveHTTP2Frame? = state.withLock { state in
                guard state.phase != .closed else { return nil }
                return NaiveHTTP2Framer.deserialize(from: &state.receiveBuffer)
            }
            guard let frame else { break }
            routeFrame(frame, hpackDecoder: hpackDecoder)
        }
        state.withLock { state in
            if state.receiveBuffer.isEmpty { state.receiveBuffer = Data() }
        }
    }

    private func routeFrame(_ frame: NaiveHTTP2Frame, hpackDecoder: HPACKDecoder) {
        switch frame.type {
        case .settings:
            handleSettings(frame)

        case .ping:
            if !frame.hasFlag(NaiveHTTP2FrameFlags.ack) {
                sendControlFrame(NaiveHTTP2Framer.pingAckFrame(opaqueData: frame.payload))
            }

        case .goaway:
            handleGoaway(frame)

        case .windowUpdate:
            handleWindowUpdate(frame)

        case .headers:
            let stream: NaiveHTTP2Stream? = state.withLock { $0.streams[frame.streamID] }
            guard let stream else { break }
            if let decoded = hpackDecoder.decodeHeaders(from: frame.payload) {
                stream.handleHeaders(fields: decoded.fields)
            } else {
                stream.handleStreamError(AnywhereError.proxy(.naive, .protocolViolation(detail: "Failed to decode headers on stream \(frame.streamID)")))
            }

        case .data:
            let endStream = frame.hasFlag(NaiveHTTP2FrameFlags.endStream)
            let stream: NaiveHTTP2Stream? = state.withLock { $0.streams[frame.streamID] }
            stream?.handleData(frame.payload, endStream: endStream)

        case .rstStream:
            let stream: NaiveHTTP2Stream? = state.withLock { $0.streams[frame.streamID] }
            if let stream {
                let errorCode = NaiveHTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                stream.handleReset(errorCode: errorCode)
            }

        case .continuation:
            break
        }
    }

    // MARK: - Frame Handlers

    private func handleSettings(_ frame: NaiveHTTP2Frame) {
        if frame.hasFlag(NaiveHTTP2FrameFlags.ack) { return }

        var becameReady = false
        state.withLock { state in
            let settings = NaiveHTTP2Framer.parseSettings(payload: frame.payload)
            for (id, value) in settings {
                switch id {
                case 0x3: // MAX_CONCURRENT_STREAMS
                    state.maxConcurrentStreams = value
                case 0x4: // INITIAL_WINDOW_SIZE — adjusts every live stream's send window.
                    let delta = Int(value) - state.peerInitialWindowSize
                    state.peerInitialWindowSize = Int(value)
                    for sid in state.sendWindows.keys { state.sendWindows[sid]! += delta }
                    if delta > 0 { state.flowGate.wakeAll() }
                default:
                    break
                }
            }
            becameReady = state.transition(to: .ready)
        }

        sendControlFrame(NaiveHTTP2Framer.settingsAckFrame())

        if becameReady {
            completeReadyContinuations(nil)
        }
    }

    private func handleGoaway(_ frame: NaiveHTTP2Frame) {
        let parsed = NaiveHTTP2Framer.parseGoaway(payload: frame.payload)
        if let parsed {
            logger.warning("[NaiveHTTP2Multiplexer] GOAWAY: lastStreamID=\(parsed.lastStreamID), errorCode=\(parsed.errorCode)")
        }

        var doomed: [NaiveHTTP2Stream] = []
        let outcome: (failReady: Bool, shouldClose: Bool) = state.withLock { state in
            let previousState = state.phase
            guard previousState != .closed else { return (false, false) }
            state.transition(to: .goingAway)
            if let parsed {
                for (id, stream) in state.streams where id > parsed.lastStreamID {
                    doomed.append(stream)
                }
            }
            return (
                previousState == .prefaceSent || previousState == .connecting,
                state.streams.isEmpty && state.reservedStreams == 0
            )
        }

        for stream in doomed { stream.handleSessionError(AnywhereError.proxy(.naive, .goaway)) }
        if outcome.failReady {
            completeReadyContinuations(AnywhereError.proxy(.naive, .goaway))
        }
        if outcome.shouldClose {
            close()
        }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload) else { return }
        state.withLock { state in
            if frame.streamID == 0 {
                state.connectionSendWindow += Int(increment)
            } else if state.sendWindows[frame.streamID] != nil {
                state.sendWindows[frame.streamID]! += Int(increment)
            }
            // A re-opened window (connection- or stream-level) wakes parked sends; each re-checks its
            // own min(connection, stream) window before building frames.
            state.flowGate.wakeAll()
        }
    }

    func acknowledgeReceivedData(count: Int) {
        let update: NaiveHTTP2Frame? = state.withLock { state in
            state.connectionReceiveConsumed += count
            guard state.connectionReceiveConsumed >= state.connectionReceiveWindowSize / 2 else { return nil }
            let increment = UInt32(state.connectionReceiveConsumed)
            state.connectionReceiveConsumed = 0
            return NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment)
        }
        if let update { sendControlFrame(update) }
    }

    // MARK: - Send

    func sendConnect(stream: NaiveHTTP2Stream) async throws {
        let extraHeaders = connectHeaders()

        let headerBlock = HPACKEncoder.encodeConnectRequest(
            authority: stream.destination,
            extraHeaders: extraHeaders
        )
        let headersFrame = NaiveHTTP2Framer.headersFrame(
            streamID: stream.streamID,
            headerBlock: headerBlock,
            endStream: false
        )

        try await enqueueOrdered(headersFrame.serialized)
    }

    private enum SendStep {
        case closed
        case park
        case built(frames: Data, nextOffset: Int, debit: Int)
    }

    func sendData(_ data: Data, on stream: NaiveHTTP2Stream) async throws {
        var offset = 0
        while offset < data.count {
            let step = buildDataStep(data, on: stream, offset: offset)
            switch step {
            case .closed:
                throw AnywhereError.proxy(.naive, .notReady)
            case .park:
                await parkForFlow(stream: stream)
                try Task.checkCancellation()
            case .built(let frames, let nextOffset, let debit):
                do {
                    try await enqueueOrdered(frames)
                } catch {
                    if !AnywhereError.isTermination(error) {
                        refundFlowDebit(debit, streamID: stream.streamID)
                    }
                    throw error
                }
                offset = nextOffset
            }
        }
    }

    private func refundFlowDebit(_ debit: Int, streamID: UInt32) {
        guard debit > 0 else { return }
        state.withLock { state in
            guard state.phase != .closed else { return }
            state.connectionSendWindow += debit
            if state.sendWindows[streamID] != nil {
                state.sendWindows[streamID]! += debit
            }
            state.flowGate.wakeAll()
        }
    }

    private func buildDataStep(_ data: Data, on stream: NaiveHTTP2Stream, offset: Int) -> SendStep {
        state.withLock { state in
            guard state.phase != .closed else { return .closed }
            guard let streamSendWindow = state.sendWindows[stream.streamID] else { return .closed }

            let maxPayload = NaiveHTTP2Framer.maxDataPayload
            var currentOffset = offset
            var frames = Data()
            var streamWindow = streamSendWindow

            while currentOffset < data.count {
                let remaining = data.count - currentOffset
                let maxByFlow = min(state.connectionSendWindow, streamWindow)
                let chunkSize = min(remaining, min(maxPayload, maxByFlow))

                guard chunkSize > 0 else { break }

                state.connectionSendWindow -= chunkSize
                streamWindow -= chunkSize

                let chunk = Data(data[data.startIndex + currentOffset ..< data.startIndex + currentOffset + chunkSize])
                let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk)
                frames.append(frame.serialized)
                currentOffset += chunkSize
            }
            state.sendWindows[stream.streamID] = streamWindow

            if frames.isEmpty {
                return .park
            } else {
                return .built(frames: frames, nextOffset: currentOffset, debit: currentOffset - offset)
            }
        }
    }

    private func parkForFlow(stream: NaiveHTTP2Stream) async {
        await H2FlowGate.park {
            state.withLock { state -> AsyncStream<Never>? in
                if state.phase == .closed { return nil }
                guard let streamSendWindow = state.sendWindows[stream.streamID] else { return nil }
                if min(state.connectionSendWindow, streamSendWindow) > 0 { return nil }
                return state.flowGate.enroll()
            }
        }
    }

    private func enqueueOrdered(_ data: Data) async throws {
        try await chainSend(data).value()
    }

    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        let pending = chainSend(frame.serialized)
        Task {
            do {
                try await pending.value()
            } catch {
                logger.warning("[NaiveHTTP2Multiplexer] Failed to send control frame: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - Error Handling

    private func handleSessionError(_ error: Error) {
        teardown(reason: error)
    }

    private func completeReadyContinuations(_ error: Error?) {
        if let error { readySignal.finish(throwing: error) } else { readySignal.finish() }
    }

    func close(error: Error? = nil) {
        teardown(reason: error ?? AnywhereError.proxy(.naive, .connectionClosed(detail: "Session closed")))
    }

    private func teardown(reason: Error) {
        typealias Teardown = (victims: [NaiveHTTP2Stream], sessionTask: Task<Void, Never>?)
        let teardownState: Teardown? = state.withLock { state in
            guard state.transition(to: .closed) else { return nil }
            state.flowGate.wakeAll()
            let victims = Array(state.streams.values)
            state.streams.removeAll()
            state.sendWindows.removeAll()
            state.reservedStreams = 0
            let session = state.sessionTask
            state.sessionTask = nil
            return (victims, session)
        }
        guard let (victims, sessionTask) = teardownState else { return }
        sessionTask?.cancel()
        sendChain.cancel()
        transport.cancel()
        completeReadyContinuations(reason)
        for stream in victims { stream.handleSessionError(reason) }
        onClose?(self)
    }
}
