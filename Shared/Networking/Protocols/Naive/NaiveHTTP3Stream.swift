//
//  NaiveHTTP3Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 4/11/26.
//

import Foundation
import Synchronization

nonisolated final class NaiveHTTP3Stream: NaiveTunnel, Sendable {

    // MARK: - Phase

    enum Phase: PhaseTransitionable {
        case idle, opening, connectSent, open, closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .connectSent),
                 (.connectSent, .open):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    // MARK: - Properties

    let destination: String

    private struct WeakMultiplexer { weak var value: HTTP3Multiplexer? }
    private let multiplexerBox: Mutex<WeakMultiplexer>

    private let configuration: NaiveConfiguration

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var quicStreamID: Int64?
        var headersReceived = false

        var frameBuffer = Data()
        var frameBufferOffset = 0

        var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType = .none
    }
    private let state = Mutex(State())

    private let inbox = AsyncInbox<Data>()

    private let connectSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let connectTask: Task<Void, Error>

    var isConnected: Bool { state.withLock { $0.phase == .open } }

    var quicStreamID: Int64? { state.withLock { $0.quicStreamID } }

    var negotiatedPaddingType: NaivePaddingNegotiator.PaddingType {
        state.withLock { $0.negotiatedPaddingType }
    }

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer, configuration: NaiveConfiguration, destination: String) {
        self.multiplexerBox = Mutex(WeakMultiplexer(value: multiplexer))
        self.configuration = configuration
        self.destination = destination
        let (connectStream, connectSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.connectSignal = connectSignal
        self.connectTask = Task { for try await _ in connectStream {} }
    }

    // MARK: - NaiveTunnel

    func openTunnel() async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw AnywhereError.proxy(.http3, .connectionClosed(detail: "No multiplexer"))
        }
        try await multiplexer.ensureReady()

        let events = HTTP3Multiplexer.StreamEvents(
            data: { [weak self] data, fin in
                self?.handleStreamData(data, fin: fin)
            },
            error: { [weak self] error in
                self?.handleSessionError(error)
            }
        )

        let claimed = state.withLock { $0.transition(to: .opening) }
        guard claimed else {
            try await connectTask.value
            return
        }

        guard let streamID = await multiplexer.openStream(events: events) else {
            let error: AnywhereError = multiplexer.isRetired
                ? .proxy(.http3, .connectionClosed(detail: "Session retiring"))
                : .proxy(.http3, .streamIDsExhausted)
            handleStreamError(error)
            detachFromMultiplexer(sid: nil, code: .requestCancelled)
            try await connectTask.value
            return
        }
        let accepted: Bool = state.withLock { state in
            guard state.transition(to: .connectSent) else { return false }
            state.quicStreamID = streamID
            return true
        }
        guard accepted else {
            detachFromMultiplexer(sid: streamID, code: .requestCancelled)
            try await connectTask.value
            return
        }

        var extraHeaders: [(name: String, value: String)] = []
        extraHeaders.append((name: "user-agent", value: "Chrome/128.0.0.0"))
        if let auth = configuration.basicAuth {
            extraHeaders.append((name: "proxy-authorization", value: "Basic \(auth)"))
        }
        let cachedType = NaivePaddingNegotiator.cachedPaddingType(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.effectiveSNI
        )
        extraHeaders.append(contentsOf: NaivePaddingNegotiator.requestHeaders(
            fastOpen: cachedType != nil
        ))

        var allHeaders = extraHeaders
        allHeaders.insert((name: ":method", value: "CONNECT"), at: 0)
        allHeaders.insert((name: ":authority", value: destination), at: 1)
        guard multiplexer.isWithinPeerFieldSectionLimit(allHeaders) else {
            handleStreamError(AnywhereError.proxy(.http3, .connectionClosed(detail: "Request headers exceed peer MAX_FIELD_SECTION_SIZE")))
            try await connectTask.value
            return
        }

        let headerBlock = QPACKEncoder.encodeConnectHeaders(
            authority: destination, extraHeaders: extraHeaders
        )
        let headersFrame = HTTP3Framer.headersFrame(headerBlock: headerBlock)

        Task {
            do {
                try await multiplexer.writeStream(streamID, data: headersFrame)
            } catch {
                self.handleStreamError(error)
            }
        }
        try await connectTask.value
    }

    func sendData(_ data: Data) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
        enum Gate { case ok(Int64); case closed; case notReady }
        let gate: Gate = state.withLock { state in
            guard state.phase == .open, let sid = state.quicStreamID else {
                return state.phase == .closed ? .closed : .notReady
            }
            return .ok(sid)
        }
        switch gate {
        case .closed:
            throw AnywhereError.proxy(.http3, .streamClosed)
        case .notReady:
            throw AnywhereError.proxy(.http3, .notReady)
        case .ok(let sid):
            let frame = HTTP3Framer.dataFrame(payload: data)
            try await multiplexer.writeStream(sid, data: frame)
        }
    }

    func receiveData() async throws -> Data? {
        guard multiplexerBox.withLock({ $0.value }) != nil else { throw AnywhereError.proxy(.http3, .streamClosed) }
        let data = try await nextInboxChunk()
        guard let data else {
            closeAndShutdown()
            return nil
        }
        ackQuicBytes(data.count)
        return data
    }

    func close() {
        enum Outcome { case alreadyClosed, closed(detach: (sid: Int64?, code: HTTP3ErrorCode)?) }
        let outcome: Outcome = state.withLock { state in
            let code: HTTP3ErrorCode = state.headersReceived ? .noError : .requestCancelled
            let prior = state.phase
            guard state.transition(to: .closed) else { return .alreadyClosed }
            return .closed(detach: prior == .opening ? nil : (state.quicStreamID, code))
        }
        guard case .closed(let detach) = outcome else { return }
        if let detach {
            detachFromMultiplexer(sid: detach.sid, code: detach.code)
        }
        connectSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
        inbox.finish()
    }

    private func nextInboxChunk() async throws -> Data? {
        try await inbox.next()
    }

    // MARK: - Demux events

    private func handleStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty {
            processInbound(data)
        }

        if fin {
            inbox.finish()
        }
    }

    private func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    // MARK: - HTTP/3 Frame Processing

    private enum HeadersOutcome {
        case none
        case opened(padding: NaivePaddingNegotiator.PaddingType)
        case failed(Error)
    }

    private func processInbound(_ data: Data) {
        var controlBytes = 0
        var deliveries: [Data] = []
        var outcome: HeadersOutcome = .none

        let dropped: Bool = state.withLock { state in
            guard state.phase != .closed else { return true }
            state.frameBuffer.append(data)
            while state.frameBufferOffset < state.frameBuffer.count {
                guard let (frame, consumed) = HTTP3Framer.parseFrame(
                    from: state.frameBuffer, offset: state.frameBufferOffset
                ) else {
                    break
                }
                state.frameBufferOffset += consumed

                if !state.headersReceived {
                    outcome = Self.processResponseHeaders(frame, state: &state)
                    controlBytes += consumed
                    if case .failed = outcome { break }
                } else if frame.type == HTTP3FrameType.data.rawValue {
                    if frame.payload.isEmpty {
                        controlBytes += consumed
                    } else {
                        controlBytes += consumed - frame.payload.count
                        deliveries.append(Data(frame.payload))
                    }
                } else {
                    controlBytes += consumed
                }
            }

            if state.frameBufferOffset >= state.frameBuffer.count {
                state.frameBuffer = Data()
                state.frameBufferOffset = 0
            } else if state.frameBufferOffset > 64 * 1024 {
                state.frameBuffer = Data(state.frameBuffer[(state.frameBuffer.startIndex + state.frameBufferOffset)...])
                state.frameBufferOffset = 0
            }
            return false
        }

        if dropped {
            ackQuicBytes(data.count)
            return
        }

        switch outcome {
        case .none:
            break
        case .opened(let padding):
            NaivePaddingNegotiator.cachePaddingType(
                padding,
                host: configuration.proxyHost,
                port: configuration.proxyPort,
                sni: configuration.effectiveSNI
            )
            connectSignal.finish()
        case .failed(let error):
            handleStreamError(error)
        }

        for payload in deliveries {
            inbox.yield(payload)
        }
        if controlBytes > 0 {
            ackQuicBytes(controlBytes)
        }
    }

    private static func processResponseHeaders(_ frame: HTTP3Framer.Frame, state: inout State) -> HeadersOutcome {
        guard frame.type == HTTP3FrameType.headers.rawValue else {
            return .failed(AnywhereError.proxy(.http3, .connectionClosed(detail: "Expected HEADERS, got type \(frame.type)")))
        }

        guard let headers = QPACKEncoder.decodeHeaders(from: frame.payload) else {
            return .failed(AnywhereError.proxy(.http3, .connectionClosed(detail: "Malformed QPACK header block")))
        }
        let statusHeader = headers.first(where: { $0.name == ":status" })

        guard let status = statusHeader?.value, status == "200" else {
            let code = statusHeader?.value ?? "unknown"
            if code == "407" {
                return .failed(AnywhereError.proxy(.http3, .authenticationRequired))
            } else {
                return .failed(AnywhereError.proxy(.http3, .tunnelRejected(detail: code)))
            }
        }

        let paddingTuples = headers.map { (name: $0.name, value: $0.value) }
        let negotiated = NaivePaddingNegotiator.parseResponse(headers: paddingTuples)
        guard state.transition(to: .open) else { return .none }
        state.negotiatedPaddingType = negotiated
        state.headersReceived = true
        return .opened(padding: negotiated)
    }

    private func ackQuicBytes(_ count: Int) {
        guard count > 0 else { return }
        guard let streamID = state.withLock({ $0.quicStreamID }) else { return }
        multiplexerBox.withLock { $0.value }?.extendStreamOffset(streamID, count: count)
    }

    private func handleStreamError(_ error: Error) {
        enum Outcome { case alreadyClosed, closed(detach: (sid: Int64?, code: HTTP3ErrorCode)?) }
        let outcome: Outcome = state.withLock { state in
            let code: HTTP3ErrorCode
            if case AnywhereError.proxy(.http3, .tunnelRejected) = error {
                code = .connectError
            } else if case AnywhereError.proxy(.http3, _) = error {
                code = .requestCancelled
            } else {
                code = .internalError
            }
            let prior = state.phase
            guard state.transition(to: .closed) else { return .alreadyClosed }
            return .closed(detach: prior == .opening ? nil : (state.quicStreamID, code))
        }
        guard case .closed(let detach) = outcome else { return }
        if let detach {
            detachFromMultiplexer(sid: detach.sid, code: detach.code)
        }
        connectSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        enum Outcome { case alreadyClosed, closed(detach: (sid: Int64?, code: HTTP3ErrorCode)?) }
        let outcome: Outcome = state.withLock { state in
            let prior = state.phase
            guard state.transition(to: .closed) else { return .alreadyClosed }
            return .closed(detach: prior == .opening ? nil : (state.quicStreamID, code))
        }
        guard case .closed(let detach) = outcome else { return }
        if let detach {
            detachFromMultiplexer(sid: detach.sid, code: detach.code)
        }
        connectSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
        inbox.finish()
    }

    private func detachFromMultiplexer(sid: Int64?, code: HTTP3ErrorCode) {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else { return }
        guard let sid else {
            multiplexer.releaseUnopenedStream()
            return
        }
        multiplexer.removeStream(sid)
        multiplexer.shutdownStream(sid, code: code)
    }
}
