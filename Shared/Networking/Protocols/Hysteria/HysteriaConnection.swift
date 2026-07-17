//
//  HysteriaConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaConnection")

nonisolated final class HysteriaConnection: ProxyConnection {

    enum State { case idle, openingStream, handshaking, ready, closed }

    private let session: HysteriaSession
    private let destination: String

    /// Confined to `session.queue`. The setter mirrors readiness into the
    /// atomic `_isReady` so `isConnected` can be read from any queue
    /// without a sync hop onto `session.queue`.
    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            _isReady.store(newValue == .ready, ordering: .relaxed)
        }
    }
    private let _isReady = Atomic<Bool>(false)

    /// Stored atomically: set once on `session.queue` during open, then read from the
    /// async send/receive paths off-queue.
    private let _streamID = Atomic<Int64>(-1)
    private var streamID: Int64 {
        get { _streamID.load(ordering: .relaxed) }
        set { _streamID.store(newValue, ordering: .relaxed) }
    }

    /// Post-response stream bytes / EOF / error from the session's demux loop. The async
    /// replacement for the parked `pendingReceive` completion; QUIC stream credit is
    /// returned in ``receiveRaw()`` only once ``AsyncByteChannel/next()`` hands bytes over,
    /// so the buffered queue stays bounded by the stream window (backpressure preserved).
    private let inbox = AsyncByteChannel()

    /// Accumulates incoming bytes until the response header is parsed. Confined to `session.queue`.
    private var receiveBuffer = Data()
    private var responseParsed = false

    /// One-shot open signal: finished when the Hysteria TCP response header is demuxed, or
    /// finished-throwing on failure. `open()` awaits `openTask.value` (broadcast-safe); the
    /// session's ngtcp2 demux loop resolves it by finishing `openSignal`.
    private let openSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let openTask: Task<Void, Error>

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        let (openStream, openSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.openSignal = openSignal
        self.openTask = Task { for try await _ in openStream {} }
    }

    var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Open (called by ProxyClient after session is ready)

    func open() async throws {
        // Claim the connection on the ngtcp2 queue; `openSignal` resolves later in
        // `tryParseResponse` (response header) or `fail` (error).
        let started: Bool = await session.run { [self] in
            guard state == .idle else { return false }
            state = .openingStream
            return true
        }
        guard started else { throw HysteriaError.notReady }

        // Reserve the stream, then send the request.
        Task { [weak self] in
            guard let self else { return }
            do {
                let streamID = try await self.session.openTCPStream(for: self)
                await self.session.run { self.streamID = streamID; self.sendTCPRequest() }
            } catch {
                await self.session.run { self.fail(error) }
            }
        }
        try await openTask.value
    }

    private func sendTCPRequest() {
        state = .handshaking
        let frame = HysteriaProtocol.encodeTCPRequest(address: destination)
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.session.writeStream(self.streamID, data: frame)
            } catch {
                self.session.queue.async { self.fail(error) }
            }
        }
    }

    // MARK: - Stream data (from HysteriaSession.handleStreamData)

    func handleStreamData(_ data: Data, fin: Bool) {
        // On session.queue, synchronously inside ngtcp2's read_pkt. `data` is
        // a zero-copy view into ngtcp2's buffer — detach with Data(...) before
        // handing it to the inbox (Data.append also copies).
        guard state != .closed else { return }

        if !responseParsed {
            if !data.isEmpty {
                receiveBuffer.append(data)
            }
            tryParseResponse()
            // A failed status closes us inside tryParseResponse.
            guard state != .closed else { return }
            if !responseParsed {
                if fin {
                    fail(HysteriaError.connectionFailed("Stream closed before response"))
                }
                return
            }
            // Just became ready: flush any post-header bytes, then honour FIN.
            flushBufferToInbox()
            if fin { inbox.finish() }
            return
        }

        if !data.isEmpty {
            inbox.yield(Data(data))
        }
        if fin { inbox.finish() }
    }

    private func tryParseResponse() {
        guard let parsed = HysteriaProtocol.parseTCPResponse(from: receiveBuffer) else {
            return
        }
        responseParsed = true
        receiveBuffer.removeFirst(parsed.consumed)
        // Credit the consumed response header now (small, bounded); post-header data
        // bytes are credited lazily as the app consumes them in `receiveRaw`.
        if parsed.consumed > 0 {
            session.extendStreamOffset(streamID, count: parsed.consumed)
        }

        guard parsed.status == HysteriaProtocol.tcpResponseStatusOK else {
            fail(HysteriaError.tunnelFailed(message: parsed.message))
            return
        }

        state = .ready
        openSignal.finish()
    }

    /// Hands any buffered post-header bytes to the inbox. Runs on `session.queue`.
    private func flushBufferToInbox() {
        guard !receiveBuffer.isEmpty else { return }
        let out = receiveBuffer
        receiveBuffer = Data()
        inbox.yield(out)
    }

    func handleSessionError(_ error: Error) {
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            session.queue.async { [weak self] in self?.handleStreamTermination(error: nil) }
            return
        }
        session.queue.async { [weak self] in self?.fail(error) }
    }

    /// QUIC stream termination (RESET_STREAM or stream_close). Idempotent —
    /// both callbacks can fire for the same stream. Runs on `session.queue`.
    func handleStreamTermination(error: Error?) {
        guard state != .closed else { return }
        if let error {
            fail(error)
            return
        }
        // FIN before the Hysteria TCP response — servers reject this way;
        // fail so `openCompletion` isn't leaked forever.
        if state != .ready {
            fail(HysteriaError.connectionFailed("Stream closed before TCP response"))
            return
        }
        state = .closed
        // EOF is ordered after every byte already queued in the inbox.
        inbox.finish()
    }

    private func fail(_ error: Error) {
        guard state != .closed else { return }
        state = .closed

        openSignal.finish(throwing: error)
        inbox.fail(error)
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw HysteriaError.streamClosed
        }
        try await session.writeStream(streamID, data: data)
    }

    func receiveRaw() async throws -> Data? {
        let data = try await inbox.next()
        if let data, !data.isEmpty {
            // Return stream flow-control credit only now the app has taken the bytes.
            session.extendStreamOffset(streamID, count: data.count)
        }
        return data
    }

    func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.openSignal.finish(throwing: HysteriaError.streamClosed)
            if self.streamID >= 0 {
                self.session.shutdownStream(self.streamID)
                self.session.releaseTCPStream(self.streamID)
            }
            self.inbox.cancel()
        }
    }
}
