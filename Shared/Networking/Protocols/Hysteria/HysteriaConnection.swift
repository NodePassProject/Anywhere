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

    private var openCompletion: ((Error?) -> Void)?

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Open (called by ProxyClient after session is ready)

    func open(completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard self.state == .idle else { completion(HysteriaError.notReady); return }
            self.openCompletion = completion
            self.state = .openingStream

            self.session.openTCPStream(for: self) { [weak self] streamID, error in
                guard let self else { return }
                self.session.queue.async {
                    if let error {
                        self.fail(error)
                        return
                    }
                    guard let streamID else {
                        self.fail(HysteriaError.connectionFailed("No stream"))
                        return
                    }
                    self.streamID = streamID
                    self.sendTCPRequest()
                }
            }
        }
    }

    private func sendTCPRequest() {
        state = .handshaking
        let frame = HysteriaProtocol.encodeTCPRequest(address: destination)
        session.writeStream(streamID, data: frame) { [weak self] error in
            guard let self else { return }
            if let error {
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
        if let callback = openCompletion {
            openCompletion = nil
            callback(nil)
        }
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

        if let callback = openCompletion {
            openCompletion = nil
            callback(error)
        }
        inbox.fail(error)
    }

    // MARK: - ProxyConnection overrides

    override func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw HysteriaError.streamClosed
        }
        try await session.writeStream(streamID, data: data)
    }

    override func receiveRaw() async throws -> Data? {
        let data = try await inbox.next()
        if let data, !data.isEmpty {
            // Return stream flow-control credit only now the app has taken the bytes.
            session.extendStreamOffset(streamID, count: data.count)
        }
        return data
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            if self.streamID >= 0 {
                self.session.shutdownStream(self.streamID)
                self.session.releaseTCPStream(self.streamID)
            }
            self.inbox.cancel()
        }
    }
}
