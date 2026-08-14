//
//  XHTTPH3RequestStream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation
import Synchronization

nonisolated final class XHTTPH3RequestStream: Sendable {

    // MARK: - State

    enum Phase: PhaseTransitionable {
        case idle, opening, requestSent, open, closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .requestSent),
                 (.requestSent, .open):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private struct WeakMultiplexer { weak var value: HTTP3Multiplexer? }
    private let multiplexerBox: Mutex<WeakMultiplexer>

    private struct State: PhaseHolding {
        var phase: Phase = .idle
        var quicStreamID: Int64?
        var headersReceived = false
        var responseStatus: Int?
        var frameBuffer = Data()
        var frameBufferOffset = 0
    }
    private let state = Mutex(State())

    var quicStreamID: Int64? { state.withLock { $0.quicStreamID } }
    var responseStatus: Int? { state.withLock { $0.responseStatus } }

    // MARK: - Response

    private let responseSignal: AsyncThrowingStream<Int, Error>.Continuation
    private let responseTask: Task<Int, Error>

    // MARK: - Receive buffering

    private let inbox = AsyncInbox<Data>()

    // MARK: - Init

    init(multiplexer: HTTP3Multiplexer) {
        self.multiplexerBox = Mutex(WeakMultiplexer(value: multiplexer))
        let (responseStream, responseSignal) = AsyncThrowingStream.makeStream(of: Int.self)
        self.responseSignal = responseSignal
        self.responseTask = Task {
            for try await status in responseStream { return status }
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
    }

    // MARK: - Request

    func sendRequest(headerBlock: Data, endStream: Bool) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
        guard state.withLock({ $0.transition(to: .opening) }) else {
            throw AnywhereError.proxy(.http3, .streamClosed)
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

        guard let sid = await multiplexer.openStream(events: events) else {
            let error: AnywhereError = multiplexer.isRetired
                ? .proxy(.http3, .connectionClosed(detail: "Session retiring"))
                : .proxy(.http3, .streamIDsExhausted)
            handleStreamError(error)
            throw error
        }
        let adopted: Bool = state.withLock { state in
            guard state.transition(to: .requestSent) else { return false }
            state.quicStreamID = sid
            return true
        }
        guard adopted else {
            detachFromMultiplexer(sid: sid, code: .requestCancelled)
            throw AnywhereError.proxy(.http3, .streamClosed)
        }

        let frame = HTTP3Framer.headersFrame(headerBlock: headerBlock)
        do {
            try await multiplexer.writeStream(sid, data: frame, fin: endStream)
        } catch {
            handleStreamError(error)
            throw error
        }
    }

    func awaitResponseStatus() async throws -> Int {
        guard multiplexerBox.withLock({ $0.value }) != nil else { throw AnywhereError.proxy(.http3, .streamClosed) }
        return try await responseTask.value
    }

    func sendBody(_ data: Data, fin: Bool) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else {
            throw AnywhereError.proxy(.http3, .streamClosed)
        }
        let sid: Int64? = state.withLock { state in
            state.phase == .closed ? nil : state.quicStreamID
        }
        guard let sid else { throw AnywhereError.proxy(.http3, .streamClosed) }
        if data.isEmpty && !fin { return }
        let frame = data.isEmpty ? Data() : HTTP3Framer.dataFrame(payload: data)
        try await multiplexer.writeStream(sid, data: frame, fin: fin)
    }

    func receive() async throws -> Data? {
        guard multiplexerBox.withLock({ $0.value }) != nil else { throw AnywhereError.proxy(.http3, .streamClosed) }
        let data = try await nextInboxChunk()
        guard let data else {
            closeAndShutdown()
            return nil
        }
        ackQuicBytes(data.count)
        return data
    }

    func drainResponse() {
        Task {
            while true {
                let data: Data?
                do { data = try await self.receive() } catch { return }
                guard data != nil else { return }
            }
        }
    }

    func close() {
        enum Outcome { case alreadyClosed, closed(sid: Int64?, code: HTTP3ErrorCode) }
        let outcome: Outcome = state.withLock { state in
            let code: HTTP3ErrorCode = state.headersReceived ? .noError : .requestCancelled
            guard state.transition(to: .closed) else { return .alreadyClosed }
            return .closed(sid: state.quicStreamID, code: code)
        }
        guard case .closed(let sid, let code) = outcome else { return }
        detachFromMultiplexer(sid: sid, code: code)
        responseSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
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
        if case AnywhereError.quic(.closed(graceful: true)) = error {
            responseSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
            inbox.finish()
            return
        }
        handleStreamError(error)
    }

    // MARK: - Frame processing

    private enum HeadersOutcome {
        case none
        case status(Int)
        case missingStatus
        case failed(Error)
    }

    private func processInbound(_ data: Data) {
        var controlBytes = 0
        var deliveries: [Data] = []
        var outcome: HeadersOutcome = .none

        state.withLock { state in
            guard state.phase != .closed else { return }
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
                    if case .missingStatus = outcome { break }
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
        }

        switch outcome {
        case .none:
            break
        case .status(let status):
            responseSignal.yield(status)
            responseSignal.finish()
        case .missingStatus:
            responseSignal.finish(throwing: AnywhereError.proxy(.http3, .connectionClosed(detail: "Response missing :status")))
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

        let statusValue = headers.first(where: { $0.name == ":status" })?.value
        let status = statusValue.flatMap { Int($0) }
        guard state.transition(to: .open) else { return .none }
        state.responseStatus = status
        state.headersReceived = true

        if let status {
            return .status(status)
        } else {
            return .missingStatus
        }
    }

    private func ackQuicBytes(_ count: Int) {
        guard count > 0 else { return }
        guard let sid = state.withLock({ $0.quicStreamID }) else { return }
        multiplexerBox.withLock { $0.value }?.extendStreamOffset(sid, count: count)
    }

    private func handleStreamError(_ error: Error) {
        enum Outcome { case alreadyClosed, closed(sid: Int64?) }
        let outcome: Outcome = state.withLock { state in
            guard state.transition(to: .closed) else { return .alreadyClosed }
            return .closed(sid: state.quicStreamID)
        }
        guard case .closed(let sid) = outcome else { return }
        detachFromMultiplexer(sid: sid, code: .internalError)
        responseSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    private func closeAndShutdown(code: HTTP3ErrorCode = .noError) {
        enum Outcome { case alreadyClosed, closed(sid: Int64?) }
        let outcome: Outcome = state.withLock { state in
            guard state.transition(to: .closed) else { return .alreadyClosed }
            return .closed(sid: state.quicStreamID)
        }
        guard case .closed(let sid) = outcome else { return }
        detachFromMultiplexer(sid: sid, code: code)
        responseSignal.finish(throwing: AnywhereError.proxy(.http3, .streamClosed))
        inbox.finish()
    }

    private func detachFromMultiplexer(sid: Int64?, code: HTTP3ErrorCode) {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }), let sid else { return }
        multiplexer.removeStream(sid)
        multiplexer.shutdownStream(sid, code: code)
    }
}
