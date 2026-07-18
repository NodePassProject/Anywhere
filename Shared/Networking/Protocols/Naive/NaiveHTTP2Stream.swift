//
//  NaiveHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Stream")

nonisolated final class NaiveHTTP2Stream: HTTPTunnel, Sendable {

    // MARK: - Phase

    enum Phase {
        case idle
        /// CONNECT HEADERS sent, waiting for response.
        case connectSent
        /// 200 received, data can flow.
        case open
        case closed
    }

    // MARK: - Properties

    let streamID: UInt32
    let destination: String

    /// Weak back-reference to the owning multiplexer, boxed so the stream stays `Sendable`; set once at init.
    private struct WeakMultiplexer { weak var value: NaiveHTTP2Multiplexer? }
    private let multiplexerBox: Mutex<WeakMultiplexer>

    /// Receive/response state, guarded by ``lock``. The *send* flow window lives on the multiplexer
    /// (folded there for atomic build passes), so this stream never manages it.
    private struct State {
        var phase: Phase = .idle
        var recvConsumed: Int = 0
        /// CONNECT response headers exposed for proxy-layer negotiation.
        var responseHeaders: [(name: String, value: String)] = []
    }
    private let lock = Mutex(State())

    /// Advertised per-stream receive window; constant.
    private let recvWindowSize = NaiveHTTP2FlowControl.naiveInitialWindowSize

    /// Inbound DATA payloads / EOF / error from the multiplexer's read loop. Producer side (`inbox`)
    /// is `Sendable` and driven by the read loop; the single consumer pulls `inboxIterator` from
    /// ``receiveData()``. The `Mutex` guards the iterator *value*: this stream stays a Mutex-guarded
    /// `Sendable` class rather than an actor because its phase state machine is driven by the
    /// multiplexer's *nonisolated* read-loop callbacks (`handleData`/`handleHeaders`/…) and by the
    /// synchronous ``HTTPTunnel`` requirements (`isConnected`/`close()`), all of which would force
    /// `phase` back into a nonisolated `Mutex` even under an actor. The iterator-in-`Mutex` is honest
    /// because ``receiveData()`` is the *sole* consumer — never called concurrently — so the
    /// take-mutate-store in ``nextInboxChunk()`` can't race a second reader (the same single-consumer
    /// contract an actor would rely on across `next()`'s suspension). Backpressure is preserved:
    /// flow-control credit is returned only once the app takes the bytes. H2 flow control counts DATA
    /// payload octets (RFC 7540 §6.9.1), so `data.count` is the exact amount to credit.
    /// Single consumer (one serial `receiveData` caller); `Sendable` producer via `yield`/`finish`.
    private let inbox = AsyncInbox<Data>()

    /// Resolves when the CONNECT response (200) arrives, or the stream fails first. The waiter
    /// continuation lives in the promise (async infra), bridging the multiplexer's read loop.
    /// One-shot connect signal, resolved by the demux/callback path; the awaiter is `connectTask.value`.
    private let connectSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let connectTask: Task<Void, Error>

    /// CONNECT response headers exposed for proxy-layer negotiation.
    var responseHeaders: [(name: String, value: String)] { lock.withLock { $0.responseHeaders } }

    var isConnected: Bool { lock.withLock { $0.phase == .open } }

    // MARK: - Init

    init(streamID: UInt32, multiplexer: NaiveHTTP2Multiplexer, destination: String) {
        self.streamID = streamID
        self.multiplexerBox = Mutex(WeakMultiplexer(value: multiplexer))
        self.destination = destination
        let (connectStream, connectSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.connectSignal = connectSignal
        self.connectTask = Task { for try await _ in connectStream {} }
    }

    private func nextInboxChunk() async throws -> Data? {
        try await inbox.next()
    }

    // MARK: - HTTPTunnel

    // The multiplexer pushes frames from its read loop and resolves the parked continuations /
    // yields to the inbox; the async surface awaits them there, preserving the state machine.

    func openTunnel() async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else { throw NaiveHTTP2Error.notReady }
        try await multiplexer.ensureReady()

        // The peer's INITIAL_WINDOW_SIZE is known once SETTINGS is exchanged (ensureReady done);
        // reseed the multiplexer-held send window and mark the stream, then fire CONNECT HEADERS.
        // `connectSignal` resolves later in `handleHeaders` (200) or `handleStreamError` (failure).
        multiplexer.reseedStreamSendWindow(streamID)
        lock.withLock { $0.phase = .connectSent }

        Task { [weak self] in
            guard let self, let multiplexer = self.multiplexerBox.withLock({ $0.value }) else { return }
            do {
                try await multiplexer.sendConnect(stream: self)
            } catch {
                self.handleStreamError(error)
            }
        }
        try await connectTask.value
    }

    func sendData(_ data: Data) async throws {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else { throw NaiveHTTP2Error.notReady }
        let open = lock.withLock { $0.phase == .open }
        guard open else { throw NaiveHTTP2Error.notReady }
        try await multiplexer.sendData(data, on: self)
    }

    func receiveData() async throws -> Data? {
        let data = try await nextInboxChunk()
        if let data, !data.isEmpty {
            // Return flow-control credit only now the app has taken the bytes (preserves backpressure).
            acknowledgeConsumedData(count: data.count)
        }
        return data
    }

    func close() {
        guard let multiplexer = multiplexerBox.withLock({ $0.value }) else { return }
        enum Action { case none; case teardown(needsRst: Bool) }
        let action: Action = lock.withLock { state in
            guard state.phase != .closed else { return .none }
            let needsRst = (state.phase == .open || state.phase == .connectSent)
            state.phase = .closed
            return .teardown(needsRst: needsRst)
        }
        guard case .teardown(let needsRst) = action else { return }

        multiplexer.removeStream(self)
        // Inform the peer so it can reclaim its stream slot.
        if needsRst {
            multiplexer.sendControlFrame(
                NaiveHTTP2Framer.rstStreamFrame(streamID: streamID, errorCode: 0x8 /* CANCEL */)
            )
        }
        connectSignal.finish(throwing: NaiveHTTP2Error.connectionFailed("Stream closed"))
        inbox.finish()
    }

    // MARK: - Session Callbacks (called by the multiplexer with no multiplexer lock held)

    func handleHeaders(fields: [(name: String, value: String)]) {
        enum Outcome { case ignore; case success; case authRequired; case tunnelFailed(String); case missingStatus }
        let outcome: Outcome = lock.withLock { state in
            guard let statusHeader = fields.first(where: { $0.name == ":status" }) else { return .missingStatus }
            let status = statusHeader.value
            guard state.phase == .connectSent else { return .ignore }
            if status == "200" {
                state.responseHeaders = fields
                state.phase = .open
                return .success
            } else if status == "407" {
                return .authRequired
            } else {
                return .tunnelFailed(status)
            }
        }
        switch outcome {
        case .ignore:
            break
        case .success:
            connectSignal.finish()
        case .authRequired:
            handleStreamError(NaiveHTTP2Error.authenticationRequired)
        case .tunnelFailed(let status):
            handleStreamError(NaiveHTTP2Error.tunnelFailed(statusCode: status))
        case .missingStatus:
            handleStreamError(NaiveHTTP2Error.protocolError("Missing :status on stream \(streamID)"))
        }
    }

    func handleData(_ payload: Data, endStream: Bool) {
        // Yield payload to the inbox; the reader credits flow control as it drains (backpressure).
        if !payload.isEmpty {
            inbox.yield(Data(payload))
        }

        if endStream {
            // END_STREAM: free the multiplexer slot now even if buffered data remains unread.
            // The inbox still delivers every queued chunk before its EOF, so ordering is preserved.
            let removed: Bool = lock.withLock { state in
                guard state.phase != .closed else { return false }
                state.phase = .closed
                return true
            }
            if removed { multiplexerBox.withLock { $0.value }?.removeStream(self) }
            inbox.finish()
        }
    }

    func handleReset(errorCode: UInt32) {
        if errorCode == 0x0 /* NO_ERROR */ || errorCode == 0x8 /* CANCEL */ {
            handleData(Data(), endStream: true)
            return
        }
        handleStreamError(NaiveHTTP2Error.streamReset(streamID))
    }

    func handleSessionError(_ error: Error) {
        handleStreamError(error)
    }

    func handleStreamError(_ error: Error) {
        let proceed: Bool = lock.withLock { state in
            guard state.phase != .closed else { return false }
            state.phase = .closed
            return true
        }
        guard proceed else { return }

        multiplexerBox.withLock { $0.value }?.removeStream(self)
        connectSignal.finish(throwing: error)
        inbox.finish(throwing: error)
    }

    // MARK: - Flow Control

    private func acknowledgeConsumedData(count: Int) {
        let update: NaiveHTTP2Frame? = lock.withLock { state in
            state.recvConsumed += count
            guard state.recvConsumed >= recvWindowSize / 2 else { return nil }
            let increment = UInt32(state.recvConsumed)
            state.recvConsumed = 0
            return NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment)
        }
        let multiplexer = multiplexerBox.withLock { $0.value }
        if let update { multiplexer?.sendControlFrame(update) }
        multiplexer?.acknowledgeReceivedData(count: count)
    }
}
