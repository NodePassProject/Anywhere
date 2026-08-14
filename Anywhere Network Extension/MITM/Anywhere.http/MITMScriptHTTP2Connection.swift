//
//  MITMScriptHTTP2Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMScriptHTTP2")

nonisolated final class MITMScriptHTTP2Connection: Multiplexer, Sendable {

    // MARK: Phase

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

    // MARK: Flow-control / SETTINGS profile

    private static let streamReceiveWindow = 4 * 1024 * 1024
    private static let connectionReceiveWindow = 16 * 1024 * 1024
    private static let maxFrameSize: UInt32 = 16_384
    private static let headerTableSize: UInt32 = 65_536
    private static let maxHeaderListSize = 262_144
    private static let ownMaxConcurrentStreams: UInt32 = 32

    private static let httpVersionDefaultWindow = 65_535
    private static let priorityFlag: UInt8 = 0x20
    private static let connectionPreface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    private static let maxReceiveBufferSize = 2 * 1024 * 1024

    // MARK: Origin

    let host: String
    let port: UInt16
    let insecure: Bool

    // MARK: Serial state

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var reserved = 0

        var dialed: OutboundConnector.Dialed?
        var tlsClient: TLSClient?
        var connection: ProxyConnection?

        var streams: [UInt32: MITMScriptHTTP2Stream] = [:]
        var sendWindows: [UInt32: Int] = [:]
        var nextStreamID: UInt32 = 1
        var maxConcurrentStreams: UInt32 = MITMScriptHTTP2Connection.ownMaxConcurrentStreams

        var connectionSendWindow = MITMScriptHTTP2Connection.httpVersionDefaultWindow
        var connectionRecvConsumed = 0
        var peerInitialWindowSize = MITMScriptHTTP2Connection.httpVersionDefaultWindow

        var receiveBuffer = Data()
        var pendingHeaders: (streamID: UInt32, flags: UInt8, block: Data)?

        var flowGate = H2FlowGate()

        var negotiatedHTTP1 = false

        var rootTask: Task<Void, Never>?

        var hpackDecoder = HPACKDecoder()
    }
    private let state = Mutex(State())

    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    private let onClose: (@Sendable (MITMScriptHTTP2Connection) -> Void)?

    private let onNegotiatedHTTP1: (@Sendable () -> Void)?

    // MARK: Init

    init(host: String, port: UInt16, insecure: Bool,
         onClose: (@Sendable (MITMScriptHTTP2Connection) -> Void)? = nil,
         onNegotiatedHTTP1: (@Sendable () -> Void)? = nil) {
        self.host = host
        self.port = port
        self.insecure = insecure
        self.onClose = onClose
        self.onNegotiatedHTTP1 = onNegotiatedHTTP1
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
        (self.jobs, self.jobContinuation) = AsyncStream.makeStream(of: ConnectionJob.self)
    }

    // MARK: - Task tree

    private enum ConnectionJob: Sendable {
        case setup
        case setupDeadline
        case readLoop
        case streamSend(MITMScriptHTTP2Stream)
        case streamDeadline(MITMScriptHTTP2Stream)
        case streamIdle(MITMScriptHTTP2Stream)
        case controlSend(Data, transport: ProxyConnection)
    }
    private let jobs: AsyncStream<ConnectionJob>
    private let jobContinuation: AsyncStream<ConnectionJob>.Continuation

    private let setupDonePoke = AsyncInbox<Void>(capacity: 1)

    private func spawn(_ job: ConnectionJob) {
        jobContinuation.yield(job)
    }

    private func run() async {
        await withDiscardingTaskGroup { group in
            for await job in jobs {
                group.addTask { await self.runJob(job) }
            }
            group.cancelAll()
        }
    }

    private func runJob(_ job: ConnectionJob) async {
        switch job {
        case .setup: await runSetup()
        case .setupDeadline: await runSetupDeadline()
        case .readLoop: await runReadLoop()
        case .streamSend(let stream): await stream.runSend()
        case .streamDeadline(let stream): await stream.runDeadline()
        case .streamIdle(let stream): await stream.runIdleLoop()
        case .controlSend(let data, let transport): await runControlSend(data, on: transport)
        }
    }

    private func startStreamJobs(for stream: MITMScriptHTTP2Stream) {
        spawn(.streamDeadline(stream))
        spawn(.streamIdle(stream))
        spawn(.streamSend(stream))
    }

    // MARK: - Multiplexer

    var isClosed: Bool { state.withLock { $0.phase == .closed } }
    var activeStreamCount: Int { state.withLock { $0.streams.count + $0.reserved } }
    var poolIsGoingAway: Bool { state.withLock { $0.phase == .goingAway } }

    func tryReserveStream() -> Bool {
        state.withLock { state in
            switch state.phase {
            case .idle, .connecting, .prefaceSent, .ready: break
            case .goingAway, .closed: return false
            }
            guard state.streams.count + state.reserved < Int(state.maxConcurrentStreams) else { return false }
            state.reserved += 1
            return true
        }
    }

    private func releaseReservation() {
        state.withLock { if $0.reserved > 0 { $0.reserved -= 1 } }
    }

    // MARK: - Request entry point

    func perform(
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval
    ) async throws -> MITMScriptHTTPClient.Response {
        do {
            try await ensureReady()
        } catch {
            releaseReservation()
            throw error
        }

        let (responseStream, responseSignal) = AsyncThrowingStream.makeStream(of: MITMScriptHTTPClient.Response.self)
        enum Start { case rejected(Error); case go(MITMScriptHTTP2Stream) }
        let outcome: Start = state.withLock { state in
            if state.reserved > 0 { state.reserved -= 1 }
            guard state.phase != .closed else {
                return .rejected(state.negotiatedHTTP1 ? AnywhereError.mitm(.needsHTTP1Fallback)
                                                       : AnywhereError.proxy(.http2, .connectionClosed(detail: "connection closed")))
            }
            let sid = state.nextStreamID
            state.nextStreamID &+= 2
            let stream = MITMScriptHTTP2Stream(
                streamID: sid,
                connection: self,
                request: request,
                hostHeader: hostHeader,
                maxBytes: maxBytes,
                resourceTimeout: resourceTimeout,
                responseSignal: responseSignal
            )
            state.streams[sid] = stream
            state.sendWindows[sid] = state.peerInitialWindowSize
            return .go(stream)
        }

        switch outcome {
        case .rejected(let error):
            responseSignal.finish(throwing: error)
        case .go(let stream):
            startStreamJobs(for: stream)
        }
        for try await response in responseStream { return response }
        throw AnywhereError.proxy(.http2, .connectionClosed(detail: "stream ended without a response"))
    }

    // MARK: - Setup

    private func ensureReady() async throws {
        enum Kick { case awaitReady; case begin; case fail(Error) }
        let kick: Kick = state.withLock { state in
            switch state.phase {
            case .ready:
                return .awaitReady
            case .idle:
                state.transition(to: .connecting)
                return .begin
            case .connecting, .prefaceSent:
                return .awaitReady
            case .goingAway, .closed:
                return .fail(state.negotiatedHTTP1 ? AnywhereError.mitm(.needsHTTP1Fallback)
                                                   : AnywhereError.proxy(.http2, .connectionClosed(detail: "connection closed")))
            }
        }
        switch kick {
        case .awaitReady:
            break
        case .begin:
            beginSetup()
        case .fail(let error):
            throw error
        }
        try await readyTask.value
    }

    private func beginSetup() {
        state.withLock { if $0.rootTask == nil { $0.rootTask = Task { await self.run() } } }
        spawn(.setupDeadline)
        spawn(.setup)
    }

    private func runSetup() async {
        let dialed: OutboundConnector.Dialed
        do {
            dialed = try await OutboundConnector.dial(host: host, port: port)
        } catch {
            failSetup(error)
            return
        }
        let proceed = state.withLock { state -> Bool in
            guard state.phase == .connecting else { return false }
            state.dialed = dialed
            return true
        }
        guard proceed else {
            dialed.connection.cancel()
            await dialed.proxyClient?.cancel()
            return
        }

        let configuration = TLSConfiguration(serverName: host, alpn: ["h2", "http/1.1"], insecureSkipVerify: insecure)
        let client = TLSClient(configuration: configuration)
        state.withLock { $0.tlsClient = client }
        let tlsConnection: TLSRecordConnection
        do {
            tlsConnection = try await client.connect(overTunnel: dialed.connection)
        } catch {
            failSetup(error)
            return
        }
        enum TLSOutcome { case stale; case http1; case proceed }
        let outcome: TLSOutcome = state.withLock { state in
            guard state.phase == .connecting else { return .stale }
            guard tlsConnection.negotiatedALPN == "h2" else {
                state.negotiatedHTTP1 = true
                return .http1
            }
            state.connection = TLSProxyConnection(tlsConnection: tlsConnection)
            return .proceed
        }
        switch outcome {
        case .stale:
            return
        case .http1:
            onNegotiatedHTTP1?()
            failSetup(AnywhereError.mitm(.needsHTTP1Fallback))
            return
        case .proceed:
            break
        }

        let transport: ProxyConnection? = state.withLock { $0.connection }
        guard let transport else { failSetup(AnywhereError.proxy(.http2, .notReady)); return }

        var data = Data()
        data.append(Self.connectionPreface)
        data.append(NaiveHTTP2Framer.settingsFrame([
            (id: 0x1, value: Self.headerTableSize),
            (id: 0x2, value: 0),                                   // ENABLE_PUSH off
            (id: 0x3, value: Self.ownMaxConcurrentStreams),        // server-initiated streams
            (id: 0x4, value: UInt32(Self.streamReceiveWindow)),    // INITIAL_WINDOW_SIZE
            (id: 0x5, value: Self.maxFrameSize),
            (id: 0x6, value: UInt32(Self.maxHeaderListSize)),
        ]).serialized)
        let bump = UInt32(Self.connectionReceiveWindow - Self.httpVersionDefaultWindow)
        data.append(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: bump).serialized)

        do {
            try await transport.send(data)
        } catch {
            failSetup(error)
            return
        }
        let started = state.withLock { $0.transition(to: .prefaceSent) }
        guard started else { return }
        spawn(.readLoop)
    }

    private func runSetupDeadline() async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { try? await Task.sleep(for: .seconds(TunnelConstants.handshakeTimeout)) }
            group.addTask { _ = try? await self.setupDonePoke.next() }
            _ = await group.next()
            group.cancelAll()
        }
        let stillSettingUp = state.withLock { $0.phase == .connecting || $0.phase == .prefaceSent }
        guard stillSettingUp else { return }
        failSetup(AnywhereError.proxy(.http2, .connectionClosed(detail: "handshake/SETTINGS timed out")))
    }

    // MARK: - Read loop

    private func runReadLoop() async {
        while true {
            let transport: ProxyConnection? = state.withLock { $0.phase != .closed ? $0.connection : nil }
            guard let transport else { return }

            let data: Data?
            do { data = try await transport.receive() }
            catch { handleSessionError(error); return }

            guard let data, !data.isEmpty else {
                handleSessionError(AnywhereError.proxy(.http2, .connectionClosed(detail: "connection closed by peer")))
                return
            }

            let overflow: Bool = state.withLock { state in
                guard state.phase != .closed else { return false }
                state.receiveBuffer.append(data)
                return state.receiveBuffer.count > Self.maxReceiveBufferSize
            }
            if overflow {
                handleSessionError(AnywhereError.proxy(.http2, .protocolViolation(detail: "receive buffer exceeded \(Self.maxReceiveBufferSize) bytes")))
                return
            }

            drainFrames()
            if state.withLock({ $0.phase == .closed }) { return }
        }
    }

    private func drainFrames() {
        while true {
            let frame: NaiveHTTP2Frame? = state.withLock { state in
                guard state.phase != .closed else { return nil }
                return NaiveHTTP2Framer.deserialize(from: &state.receiveBuffer)
            }
            guard let frame else { break }
            routeFrame(frame)
        }
        state.withLock { state in
            if state.receiveBuffer.isEmpty { state.receiveBuffer = Data() }   // release backing store
        }
    }

    private func routeFrame(_ frame: NaiveHTTP2Frame) {
        let pending: (streamID: UInt32, flags: UInt8, block: Data)? = state.withLock { $0.pendingHeaders }
        if let pending {
            guard frame.type == .continuation, frame.streamID == pending.streamID else {
                connectionError("expected CONTINUATION on stream \(pending.streamID)")
                return
            }
            appendContinuation(frame)
            return
        }

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
            beginHeaders(frame)
        case .data:
            handleData(frame)
        case .rstStream:
            let stream: MITMScriptHTTP2Stream? = state.withLock { state in
                guard let stream = state.streams[frame.streamID] else { return nil }
                state.streams.removeValue(forKey: stream.streamID)
                state.sendWindows.removeValue(forKey: stream.streamID)
                return stream
            }
            if let stream {
                let code = NaiveHTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                stream.handleReset(errorCode: code)
            }
        case .continuation:
            connectionError("unexpected CONTINUATION on stream \(frame.streamID)")
        }
    }

    // MARK: - HEADERS

    private func beginHeaders(_ frame: NaiveHTTP2Frame) {
        guard let fragment = strippedHeaderBlockFragment(frame) else {
            connectionError("malformed HEADERS framing")
            return
        }
        if frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
            completeHeaderBlock(streamID: frame.streamID, flags: frame.flags, block: fragment)
        } else {
            guard fragment.count <= Self.maxHeaderListSize else {
                connectionError("header block exceeds \(Self.maxHeaderListSize) bytes")
                return
            }
            state.withLock { $0.pendingHeaders = (frame.streamID, frame.flags, fragment) }
        }
    }

    private func appendContinuation(_ frame: NaiveHTTP2Frame) {
        enum Step { case none; case overflow; case complete(streamID: UInt32, flags: UInt8, block: Data) }
        let step: Step = state.withLock { state in
            guard var pending = state.pendingHeaders else { return .none }
            pending.block.append(frame.payload)
            guard pending.block.count <= Self.maxHeaderListSize else {
                return .overflow
            }
            if frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
                state.pendingHeaders = nil
                return .complete(streamID: pending.streamID, flags: pending.flags, block: pending.block)
            } else {
                state.pendingHeaders = pending
                return .none
            }
        }
        switch step {
        case .none:
            break
        case .overflow:
            connectionError("header block exceeds \(Self.maxHeaderListSize) bytes")
        case .complete(let streamID, let flags, let block):
            completeHeaderBlock(streamID: streamID, flags: flags, block: block)
        }
    }

    private func completeHeaderBlock(streamID: UInt32, flags: UInt8, block: Data) {
        guard let decoded = state.withLock({ $0.hpackDecoder.decodeHeaders(from: block) }) else {
            connectionError("HPACK decode failed")
            return
        }
        let endStream = (flags & NaiveHTTP2FrameFlags.endStream) != 0
        let stream: MITMScriptHTTP2Stream? = state.withLock { $0.streams[streamID] }
        stream?.handleHeaders(fields: decoded.fields, endStream: endStream)
    }

    private func strippedHeaderBlockFragment(_ frame: NaiveHTTP2Frame) -> Data? {
        var bytes = frame.payload[...]
        if frame.hasFlag(NaiveHTTP2FrameFlags.padded) {
            guard let padLength = bytes.first else { return nil }
            bytes = bytes.dropFirst()
            guard bytes.count >= Int(padLength) else { return nil }
            bytes = bytes.dropLast(Int(padLength))
        }
        if (frame.flags & Self.priorityFlag) != 0 {
            guard bytes.count >= 5 else { return nil }
            bytes = bytes.dropFirst(5)
        }
        return Data(bytes)
    }

    // MARK: - DATA (connection-scoped flow control)

    private func handleData(_ frame: NaiveHTTP2Frame) {
        let endStream = frame.hasFlag(NaiveHTTP2FrameFlags.endStream)
        let body = Self.unpaddedDataPayload(frame)

        let (windowUpdate, transport, stream): (NaiveHTTP2Frame?, ProxyConnection?, MITMScriptHTTP2Stream?) = state.withLock { state in
            var update: NaiveHTTP2Frame?
            if frame.payload.count > 0 {
                state.connectionRecvConsumed += frame.payload.count
                if state.connectionRecvConsumed >= Self.connectionReceiveWindow / 2 {
                    let increment = UInt32(state.connectionRecvConsumed)
                    state.connectionRecvConsumed = 0
                    update = NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment)
                }
            }
            return (update, state.connection, state.streams[frame.streamID])
        }
        if let windowUpdate, let transport {
            sendFrame(windowUpdate, on: transport)
        }
        stream?.handleData(body, fullPayloadCount: frame.payload.count, endStream: endStream)
    }

    private static func unpaddedDataPayload(_ frame: NaiveHTTP2Frame) -> Data {
        guard frame.hasFlag(NaiveHTTP2FrameFlags.padded) else { return frame.payload }
        guard let padLength = frame.payload.first else { return Data() }
        let withoutPadByte = frame.payload.dropFirst()
        guard withoutPadByte.count >= Int(padLength) else { return Data(withoutPadByte) }
        return Data(withoutPadByte.dropLast(Int(padLength)))
    }

    // MARK: - Control-frame handlers

    private func handleSettings(_ frame: NaiveHTTP2Frame) {
        if frame.hasFlag(NaiveHTTP2FrameFlags.ack) { return }

        var becameReady = false
        let transport: ProxyConnection? = state.withLock { state in
            for (id, value) in NaiveHTTP2Framer.parseSettings(payload: frame.payload) {
                switch id {
                case 0x3: // MAX_CONCURRENT_STREAMS
                    state.maxConcurrentStreams = min(Self.ownMaxConcurrentStreams, value)
                case 0x4: // INITIAL_WINDOW_SIZE — adjusts every live stream's send window.
                    let delta = Int(value) - state.peerInitialWindowSize
                    state.peerInitialWindowSize = Int(value)
                    for sid in state.sendWindows.keys { state.sendWindows[sid]! += delta }
                default:
                    break
                }
            }
            becameReady = state.transition(to: .ready)
            return state.connection
        }

        if let transport {
            sendFrame(NaiveHTTP2Framer.settingsAckFrame(), on: transport)
        }
        if becameReady {
            setupDonePoke.yield(())
            readySignal.finish()
        }
    }

    private func handleGoaway(_ frame: NaiveHTTP2Frame) {
        let parsed = NaiveHTTP2Framer.parseGoaway(payload: frame.payload)
        if let parsed {
            logger.warning("[MITMScriptHTTP2] GOAWAY lastStreamID=\(parsed.lastStreamID) errorCode=\(parsed.errorCode)")
        }

        var failReadiness = false
        var doomed: [MITMScriptHTTP2Stream] = []
        let closeNow: Bool = state.withLock { state in
            let previous = state.phase
            guard previous != .closed else { return false }
            state.transition(to: .goingAway)
            if let parsed {
                for (id, stream) in state.streams where id > parsed.lastStreamID {
                    state.streams.removeValue(forKey: id)
                    state.sendWindows.removeValue(forKey: id)
                    doomed.append(stream)
                }
            }
            if previous == .connecting || previous == .prefaceSent {
                failReadiness = true
            }
            return state.streams.isEmpty
        }

        for stream in doomed { stream.failFromSession(AnywhereError.proxy(.http2, .goaway)) }
        if failReadiness { readySignal.finish(throwing: AnywhereError.proxy(.http2, .goaway)) }
        if closeNow { close(error: AnywhereError.proxy(.http2, .goaway)) }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload), increment > 0 else { return }

        enum Update { case ok; case overflow }
        let result: Update = state.withLock { state in
            if frame.streamID == 0 {
                let updated = state.connectionSendWindow + Int(increment)
                guard updated <= 0x7FFF_FFFF else { return .overflow }
                state.connectionSendWindow = updated
            } else if state.sendWindows[frame.streamID] != nil {
                state.sendWindows[frame.streamID]! += Int(increment)
            }
            state.flowGate.wakeAll()
            return .ok
        }
        switch result {
        case .overflow:
            connectionError("connection send window overflow")
        case .ok:
            break
        }
    }

    func wakeFlowParks() {
        state.withLock { $0.flowGate.wakeAll() }
    }

    // MARK: - Sending

    func sendHeaders(streamID: UInt32, headerBlock: Data, endStream: Bool) async throws {
        guard headerBlock.count <= Int(Self.maxFrameSize) else {
            throw AnywhereError.mitm(.requestHeadersTooLarge)
        }
        let frame = NaiveHTTP2Framer.headersFrame(streamID: streamID, headerBlock: headerBlock, endStream: endStream)
        let transport = try currentTransport()
        try await transport.send(frame.serialized)
    }

    private enum DataSendStep {
        case notReady
        case streamGone(UInt32)
        case done
        case park
        case send(frame: Data, nextOffset: Int, isLast: Bool, transport: ProxyConnection)
    }

    func sendData(_ data: Data, on stream: MITMScriptHTTP2Stream, endStream: Bool) async throws {
        var offset = 0
        while true {
            let step = buildDataStep(data, on: stream, offset: offset, endStream: endStream)
            switch step {
            case .notReady:
                throw AnywhereError.proxy(.http2, .notReady)
            case .streamGone(let sid):
                throw AnywhereError.proxy(.http2, .streamReset(code: sid))
            case .done:
                return
            case .park:
                await parkForFlow(stream: stream)
            case .send(let frame, let nextOffset, let isLast, let transport):
                try await transport.send(frame)
                if isLast { return }
                offset = nextOffset
            }
        }
    }

    private func buildDataStep(_ data: Data, on stream: MITMScriptHTTP2Stream, offset: Int, endStream: Bool) -> DataSendStep {
        state.withLock { state in
            guard state.phase == .ready || state.phase == .goingAway else { return .notReady }
            guard let streamSendWindow = state.sendWindows[stream.streamID] else { return .streamGone(stream.streamID) }
            guard let connection = state.connection else { return .notReady }

            if offset >= data.count {
                if endStream {
                    let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: Data(), endStream: true)
                    return .send(frame: frame.serialized, nextOffset: offset, isLast: true, transport: connection)
                }
                return .done
            }

            let maxByFlow = min(state.connectionSendWindow, streamSendWindow)
            let chunkSize = min(data.count - offset, min(NaiveHTTP2Framer.maxDataPayload, maxByFlow))
            guard chunkSize > 0 else { return .park }

            state.connectionSendWindow -= chunkSize
            state.sendWindows[stream.streamID]! -= chunkSize
            let start = data.startIndex + offset
            let chunk = data.subdata(in: start..<(start + chunkSize))
            let isLast = offset + chunkSize >= data.count
            let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk, endStream: endStream && isLast)
            return .send(frame: frame.serialized, nextOffset: offset + chunkSize, isLast: isLast, transport: connection)
        }
    }

    private func parkForFlow(stream: MITMScriptHTTP2Stream) async {
        await H2FlowGate.park {
            state.withLock { state -> AsyncStream<Never>? in
                if state.phase == .closed { return nil }
                guard let streamSendWindow = state.sendWindows[stream.streamID] else { return nil }
                if min(state.connectionSendWindow, streamSendWindow) > 0 { return nil }
                return state.flowGate.enroll()
            }
        }
    }

    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        let transport: ProxyConnection? = state.withLock { $0.connection }
        guard let transport else { return }
        sendFrame(frame, on: transport)
    }

    private func sendFrame(_ frame: NaiveHTTP2Frame, on transport: ProxyConnection) {
        spawn(.controlSend(frame.serialized, transport: transport))
    }

    private func runControlSend(_ data: Data, on transport: ProxyConnection) async {
        do { try await transport.send(data) }
        catch { logger.debug("[MITMScriptHTTP2] control frame send failed: \(AnywhereError.describe(error))") }
    }

    private func currentTransport() throws -> ProxyConnection {
        guard let connection = state.withLock({ $0.connection }) else {
            throw AnywhereError.proxy(.http2, .notReady)
        }
        return connection
    }

    // MARK: - Stream teardown

    func removeStream(_ stream: MITMScriptHTTP2Stream, sendRST: Bool) {
        enum Outcome { case gone; case removed(rst: Bool, closeGoaway: Bool, transport: ProxyConnection?) }
        let outcome: Outcome = state.withLock { state in
            guard state.streams.removeValue(forKey: stream.streamID) != nil else { return .gone }
            state.sendWindows.removeValue(forKey: stream.streamID)
            let rst = sendRST && (state.phase == .ready || state.phase == .goingAway)
            let closeGoaway = state.phase == .goingAway && state.streams.isEmpty
            return .removed(rst: rst, closeGoaway: closeGoaway, transport: state.connection)
        }
        guard case .removed(let rst, let closeGoaway, let transport) = outcome else { return }

        if rst, let transport {
            sendFrame(NaiveHTTP2Framer.rstStreamFrame(streamID: stream.streamID, errorCode: 0x8 /* CANCEL */), on: transport)
        }
        if closeGoaway {
            close(error: AnywhereError.proxy(.http2, .goaway))
        }
    }

    // MARK: - Errors / teardown

    private func connectionError(_ message: String) {
        logger.warning("[MITMScriptHTTP2] \(message)")
        handleSessionError(AnywhereError.proxy(.http2, .protocolViolation(detail: message)))
    }

    private func handleSessionError(_ error: Error) {
        teardown(reason: error)
    }

    private func failSetup(_ error: Error) {
        teardown(reason: error)
    }

    private func teardown(reason: Error) {
        typealias Teardown = (victims: [MITMScriptHTTP2Stream], rootTask: Task<Void, Never>?)
        let teardownState: Teardown? = state.withLock { state in
            guard state.transition(to: .closed) else { return nil }
            state.flowGate.wakeAll()
            let victims = Array(state.streams.values)
            state.streams.removeAll()
            state.sendWindows.removeAll()
            state.reserved = 0
            state.pendingHeaders = nil
            let root = state.rootTask
            state.rootTask = nil
            return (victims, root)
        }
        guard let (victims, rootTask) = teardownState else { return }

        jobContinuation.finish()
        setupDonePoke.yield(())
        rootTask?.cancel()
        teardownTransport()
        readySignal.finish(throwing: reason)
        for stream in victims { stream.failFromSession(reason) }
        onClose?(self)
    }

    private func teardownTransport() {
        let (connection, tlsClient, dialed): (ProxyConnection?, TLSClient?, OutboundConnector.Dialed?) = state.withLock { state in
            let captured = (state.connection, state.tlsClient, state.dialed)
            state.connection = nil
            state.tlsClient = nil
            state.dialed = nil
            return captured
        }
        if let connection {
            connection.cancel()
        } else {
            dialed?.connection.cancel()
        }
        tlsClient?.cancel()
        dialed?.proxyClient?.cancel()
    }

    // MARK: - Multiplexer.close

    func close(error: Error?) {
        teardown(reason: error ?? AnywhereError.proxy(.http2, .connectionClosed(detail: "connection closed")))
    }
}
