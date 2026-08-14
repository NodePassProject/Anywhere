//
//  HTTP3Multiplexer.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HTTP3Multiplexer")

nonisolated final class HTTP3Multiplexer: Multiplexer, Sendable {

    // MARK: - State

    enum Phase: PhaseTransitionable {
        case idle, connecting, ready, draining, closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .ready),
                 (.ready, .draining):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    struct StreamEvents: Sendable {
        let data: @Sendable (Data, Bool) -> Void
        let error: @Sendable (Error) -> Void
    }

    // MARK: - Properties

    private let quic: QUICConnection

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var streams: [Int64: StreamEvents] = [:]

        var reservedStreams = 0
        var startedStreams = 0
        var isStreamBlocked = false
        var pendingGoaway = false

        var isDrainedIdle: Bool {
            phase == .draining && streams.isEmpty && startedStreams == 0 && reservedStreams == 0
        }

        var onClose: (@Sendable () -> Void)?

        var serverControlStreamID: Int64?
        var serverControlBuffer = Data()
        var pendingServerStreams: [Int64: Data] = [:]
        var serverSettingsReceived = false

        var peerMaxFieldSectionSize: UInt64 = UInt64.max
        var peerSupportsExtendedConnect = false
        var peerSupportsH3Datagram = false
    }
    private let state = Mutex(State())

    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    var peerMaxFieldSectionSize: UInt64 { state.withLock { $0.peerMaxFieldSectionSize } }
    var peerSupportsExtendedConnect: Bool { state.withLock { $0.peerSupportsExtendedConnect } }
    var peerSupportsH3Datagram: Bool { state.withLock { $0.peerSupportsH3Datagram } }

    private let maxConcurrentStreams = 512

    var isClosed: Bool {
        state.withLock { $0.phase == .closed }
    }

    var poolIsStreamBlocked: Bool {
        state.withLock { $0.isStreamBlocked }
    }

    var hasActiveStreams: Bool {
        state.withLock { $0.startedStreams > 0 || $0.reservedStreams > 0 }
    }

    // MARK: - Init

    init(
        host: String,
        port: UInt16,
        serverName: String,
        tuning: QUICTuning = .naive,
        transport: QUICDatagramTransport? = nil
    ) {
        self.quic = QUICConnection(
            host: host,
            port: port,
            serverName: serverName,
            alpn: ["h3"],
            tuning: tuning,
            transport: transport
        )
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
    }

    // MARK: - Pool Interface

    func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        let fireNow: Bool = state.withLock { session in
            guard session.phase != .closed else { return true }
            session.onClose = hook
            return false
        }
        if fireNow { Task { hook() } }
    }

    var isRetired: Bool {
        state.withLock { $0.phase == .draining || $0.phase == .closed }
    }

    func tryReserveStream() -> Bool {
        state.withLock { session in
            guard session.phase != .closed && !session.isStreamBlocked else { return false }
            let count = session.startedStreams + session.reservedStreams
            guard count < maxConcurrentStreams else { return false }
            session.reservedStreams += 1
            return true
        }
    }

    func forceReserveStream() -> Bool {
        state.withLock { session in
            guard session.phase != .closed && !session.isStreamBlocked else { return false }
            session.reservedStreams += 1
            return true
        }
    }

    var activeStreamCount: Int {
        state.withLock { $0.startedStreams + $0.reservedStreams }
    }

    func noteStreamStarted() -> Bool {
        state.withLock { session in
            session.reservedStreams = max(0, session.reservedStreams - 1)
            guard session.phase != .closed else { return false }
            session.startedStreams += 1
            return true
        }
    }

    // MARK: - Stream Creation

    func openStream(events: StreamEvents) async -> Int64? {
        await quic.run { () -> Int64? in
            guard let sid = self.quic.openBidiStream() else {
                self.markStreamBlocked()
                return nil
            }
            let accepted: Bool = self.state.withLock { session in
                guard session.phase == .ready else { return false }
                session.streams[sid] = events
                return true
            }
            guard accepted else {
                self.quic.shutdownStream(sid, appErrorCode: HTTP3ErrorCode.requestCancelled.rawValue)
                return nil
            }
            return sid
        }
    }

    func releaseUnopenedStream() {
        let shouldClose: Bool = state.withLock { session in
            guard session.phase != .closed else { return false }
            session.startedStreams = max(0, session.startedStreams - 1)
            return session.isDrainedIdle
        }
        if shouldClose {
            close()
        }
    }

    func removeStream(_ streamID: Int64) {
        let shouldClose: Bool = state.withLock { session in
            let removed = session.streams.removeValue(forKey: streamID) != nil
            if removed {
                session.startedStreams = max(0, session.startedStreams - 1)
            }
            return session.isDrainedIdle
        }
        if shouldClose {
            close()
        }
    }

    func markStreamBlocked() {
        state.withLock { $0.isStreamBlocked = true }
    }

    // MARK: - Connection Lifecycle

    func ensureReady() async throws {
        enum Action { case ready; case park; case beginAndPark; case drainingFail; case closedFail }
        let action: Action = state.withLock { session in
            switch session.phase {
            case .ready:
                return .ready
            case .draining:
                return .drainingFail
            case .closed:
                return .closedFail
            case .connecting:
                return .park
            case .idle:
                session.transition(to: .connecting)
                return .beginAndPark
            }
        }
        switch action {
        case .ready:
            return
        case .drainingFail:
            throw AnywhereError.proxy(.http3, .connectionClosed(detail: "Session draining (GOAWAY)"))
        case .closedFail:
            throw AnywhereError.proxy(.http3, .connectionClosed(detail: "Session closed"))
        case .beginAndPark:
            startConnection()
            try await readyTask.value
        case .park:
            try await readyTask.value
        }
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.handlers.withLock { handlers in
            handlers.connectionClosed = { [weak self] error in
                self?.failSession(error)
            }
            handlers.streamData = { [weak self] streamID, data, fin in
                self?.handleStreamData(streamID: streamID, data: data, fin: fin)
            }
        }

        Task { [self] in
            do {
                try await quic.connect()
            } catch {
                failSession(error)
                return
            }
            await quic.run { self.openControlStreams() }

            let outcome: (ready: Bool, goaway: (activeStreams: Int, shouldClose: Bool)?) = state.withLock { session in
                guard session.transition(to: .ready) else { return (false, nil) }
                guard session.pendingGoaway else { return (true, nil) }
                session.pendingGoaway = false
                guard session.transition(to: .draining) else { return (true, nil) }
                session.isStreamBlocked = true
                return (true, (session.streams.count, session.isDrainedIdle))
            }
            if outcome.ready {
                readySignal.finish()
            }
            if let goaway = outcome.goaway {
                logger.debug("[HTTP3Multiplexer] Received GOAWAY, draining \(goaway.activeStreams) active streams")
                if goaway.shouldClose {
                    close()
                }
            }
        }
    }

    private func openControlStreams() {
        if let sid = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00)
            payload.append(HTTP3Framer.clientSettingsFrame())
            quic.writeStreamOnQueue(sid, data: payload)
        }
        if let sid = quic.openUniStream() {
            quic.writeStreamOnQueue(sid, data: Data([0x02]))
        }
        if let sid = quic.openUniStream() {
            quic.writeStreamOnQueue(sid, data: Data([0x03]))
        }
    }

    // MARK: - Stream Operations

    func writeStream(_ streamID: Int64, data: Data, fin: Bool = false) async throws {
        try await quic.writeStream(streamID, data: data, fin: fin)
    }

    func extendStreamOffset(_ streamID: Int64, count: Int) {
        quic.extendStreamOffset(streamID, count: count)
    }

    func shutdownStream(_ streamID: Int64, code: HTTP3ErrorCode = .noError) {
        quic.shutdownStream(streamID, appErrorCode: code.rawValue)
    }

    // MARK: - Stream Data Demux

    private enum DemuxEffect {
        case fail(Error)
        case goaway(activeStreams: Int, shouldClose: Bool)
        case abortStream(Int64, HTTP3ErrorCode)
    }

    private func handleStreamData(streamID: Int64, data: Data, fin: Bool) {
        if let sink = state.withLock({ $0.streams[streamID] }) {
            sink.data(data, fin)
            return
        }

        let isServerUni = (streamID & 0x03) == 0x03
        guard isServerUni, !data.isEmpty else { return }

        quic.extendStreamOffset(streamID, count: data.count)

        let effects: [DemuxEffect] = state.withLock { session in
            if streamID == session.serverControlStreamID {
                session.serverControlBuffer.append(data)
                return Self.processServerControlFrames(&session)
            }

            var buffer = session.pendingServerStreams.removeValue(forKey: streamID) ?? Data()
            buffer.append(data)
            guard !buffer.isEmpty else { return [] }
            let streamType = buffer[buffer.startIndex]
            switch streamType {
            case 0x00:
                guard session.serverControlStreamID == nil else {
                    return [.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Duplicate server control stream")))]
                }
                session.serverControlStreamID = streamID
                session.serverControlBuffer = Data(buffer.dropFirst())
                return Self.processServerControlFrames(&session)
            case 0x01:
                return [.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Server opened push stream without MAX_PUSH_ID")))]
            case 0x02, 0x03:
                return []
            default:
                if !Self.isReservedStreamType(streamType) {
                    return [.abortStream(streamID, .streamCreationError)]
                }
                return []
            }
        }

        perform(effects)
    }

    private func perform(_ effects: [DemuxEffect]) {
        for effect in effects {
            switch effect {
            case .fail(let error):
                failSession(error)
            case .goaway(let activeStreams, let shouldClose):
                logger.debug("[HTTP3Multiplexer] Received GOAWAY, draining \(activeStreams) active streams")
                if shouldClose {
                    close()
                }
            case .abortStream(let streamID, let code):
                quic.shutdownStream(streamID, appErrorCode: code.rawValue)
            }
        }
    }

    private static func isReservedStreamType(_ streamType: UInt8) -> Bool {
        streamType >= 0x21 && (UInt64(streamType) - 0x21) % 0x1f == 0
    }

    private static func processServerControlFrames(_ session: inout State) -> [DemuxEffect] {
        var effects: [DemuxEffect] = []
        while !session.serverControlBuffer.isEmpty {
            guard let (frame, consumed) = HTTP3Framer.parseFrame(from: session.serverControlBuffer) else {
                break
            }
            session.serverControlBuffer = Data(session.serverControlBuffer.dropFirst(consumed))

            if !session.serverSettingsReceived {
                guard frame.type == HTTP3FrameType.settings.rawValue else {
                    effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "First control-stream frame was not SETTINGS"))))
                    return effects
                }
                session.serverSettingsReceived = true
                if !parseServerSettings(frame.payload, into: &session) {
                    effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Malformed SETTINGS frame"))))
                    return effects
                }
                continue
            }

            switch frame.type {
            case HTTP3FrameType.goaway.rawValue:
                if session.transition(to: .draining) {
                    session.isStreamBlocked = true
                    effects.append(.goaway(activeStreams: session.streams.count, shouldClose: session.isDrainedIdle))
                } else if session.phase == .connecting {
                    session.pendingGoaway = true
                }
            case HTTP3FrameType.settings.rawValue:
                effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Duplicate SETTINGS frame"))))
                return effects
            case HTTP3FrameType.data.rawValue,
                HTTP3FrameType.headers.rawValue,
                HTTP3FrameType.pushPromise.rawValue:
                effects.append(.fail(AnywhereError.proxy(.http3, .connectionClosed(detail: "Forbidden frame type \(frame.type) on control stream"))))
                return effects
            default:
                break
            }
        }
        return effects
    }

    private static func parseServerSettings(_ payload: Data, into session: inout State) -> Bool {
        var offset = 0
        var seen = Set<UInt64>()
        while offset < payload.count {
            guard let (id, idLen) = QUICVarInt.decode(from: payload, offset: offset) else {
                return false
            }
            offset += idLen
            guard let (value, valLen) = QUICVarInt.decode(from: payload, offset: offset) else {
                return false
            }
            offset += valLen

            if !seen.insert(id).inserted { return false }

            switch id {
            case HTTP3SettingsID.maxFieldSectionSize.rawValue:
                session.peerMaxFieldSectionSize = value
            case HTTP3SettingsID.enableConnectProtocol.rawValue:
                guard value == 0 || value == 1 else { return false }
                session.peerSupportsExtendedConnect = (value == 1)
            case HTTP3SettingsID.h3Datagram.rawValue:
                guard value == 0 || value == 1 else { return false }
                session.peerSupportsH3Datagram = (value == 1)
            case HTTP3SettingsID.qpackMaxTableCapacity.rawValue,
                 HTTP3SettingsID.qpackBlockedStreams.rawValue:
                break
            default:
                break
            }
        }
        return true
    }

    func isWithinPeerFieldSectionLimit(_ headers: [(name: String, value: String)]) -> Bool {
        let limit = peerMaxFieldSectionSize
        if limit == UInt64.max { return true }
        var total: UInt64 = 0
        for header in headers {
            total = total &+ UInt64(header.name.utf8.count) &+ UInt64(header.value.utf8.count) &+ 32
            if total > limit { return false }
        }
        return true
    }

    // MARK: - Close

    func close(error: Error? = nil) {
        failSession(error ?? AnywhereError.proxy(.http3, .connectionClosed(detail: "Session closed")))
    }

    private func failSession(_ error: Error) {
        typealias Teardown = (victims: [StreamEvents], onClose: (@Sendable () -> Void)?)
        let teardown: Teardown? = state.withLock { session in
            guard session.transition(to: .closed) else { return nil }
            let victims = Array(session.streams.values)
            session.streams.removeAll()
            session.startedStreams = 0
            session.reservedStreams = 0
            let hook = session.onClose
            session.onClose = nil
            return (victims, hook)
        }
        guard let (victims, onClose) = teardown else { return }

        readySignal.finish(throwing: error)

        for sink in victims {
            sink.error(error)
        }

        quic.close()
        onClose?()
    }
}
