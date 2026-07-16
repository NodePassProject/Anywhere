//
//  NaiveHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 3/18/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "NaiveHTTP2Stream")

nonisolated class NaiveHTTP2Stream: HTTPTunnel {

    // MARK: - State

    enum StreamState {
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

    private weak var multiplexer: NaiveHTTP2Multiplexer?

    private var state: StreamState = .idle

    private(set) var sendWindow: Int

    private var recvConsumed: Int = 0
    private var recvWindowSize: Int = NaiveHTTP2FlowControl.naiveInitialWindowSize

    /// Inbound DATA payloads / EOF / error from the multiplexer's read loop; the async
    /// replacement for the parked `pendingReceive` completion. QUIC-style backpressure is
    /// preserved: flow-control credit is returned in ``receiveData()`` only once
    /// ``AsyncByteChannel/next()`` hands the bytes over. H2 flow control counts DATA payload
    /// octets (RFC 7540 §6.9.1), so `data.count` is the exact amount to credit.
    private let inbox = AsyncByteChannel()

    /// Resolves when the CONNECT response (200) arrives, or the stream fails first. The waiter
    /// continuation lives in the promise (async infra), bridging the multiplexer's read loop.
    private let connectPromise = AsyncPromise<Void>()

    /// CONNECT response headers exposed for proxy-layer negotiation.
    private(set) var responseHeaders: [(name: String, value: String)] = []

    var isConnected: Bool { state == .open }

    // MARK: - Init

    init(streamID: UInt32, multiplexer: NaiveHTTP2Multiplexer, destination: String) {
        self.streamID = streamID
        self.multiplexer = multiplexer
        self.destination = destination
        self.sendWindow = NaiveHTTP2FlowControl.defaultInitialWindowSize
    }

    // MARK: - HTTPTunnel

    // The multiplexer pushes frames on its own queue and resolves the parked continuations /
    // yields to the inbox; the async surface awaits them there, preserving the state machine.

    func openTunnel() async throws {
        guard let multiplexer else { throw NaiveHTTP2Error.notReady }
        try await multiplexer.ensureReady()
        // Set up the stream and fire the CONNECT HEADERS write on the multiplexer queue;
        // `connectPromise` resolves later in `handleHeaders` (200) or `handleStreamError` (failure).
        await multiplexer.run { [self] in
            // peerInitialWindowSize is set once SETTINGS is exchanged (ensureReady done).
            self.sendWindow = multiplexer.peerInitialWindowSize
            self.state = .connectSent

            Task { [weak self] in
                guard let self, let multiplexer = self.multiplexer else { return }
                do {
                    try await multiplexer.sendConnect(stream: self)
                } catch {
                    multiplexer.queue.async { self.handleStreamError(error) }
                }
            }
        }
        try await connectPromise.value()
    }

    func sendData(_ data: Data) async throws {
        guard let multiplexer else { throw NaiveHTTP2Error.notReady }
        // Guard `state == .open` on the multiplexer queue, then delegate to the flow-controlled send.
        let open: Bool = await multiplexer.run { [self] in state == .open }
        guard open else { throw NaiveHTTP2Error.notReady }
        try await multiplexer.sendData(data, on: self)
    }

    func receiveData() async throws -> Data? {
        let data = try await inbox.next()
        if let data, !data.isEmpty, let multiplexer {
            // Return flow-control credit only now the app has taken the bytes (preserves backpressure).
            multiplexer.queue.async { [weak self] in self?.acknowledgeConsumedData(count: data.count) }
        }
        return data
    }

    func close() {
        guard let multiplexer else { return }
        multiplexer.queue.async { [self] in
            guard state != .closed else { return }
            let needsRst = (state == .open || state == .connectSent)
            state = .closed
            multiplexer.removeStream(self)

            // Inform the peer so it can reclaim its stream slot.
            if needsRst {
                multiplexer.sendControlFrame(
                    NaiveHTTP2Framer.rstStreamFrame(streamID: streamID, errorCode: 0x8 /* CANCEL */)
                )
            }

            connectPromise.resolve(.failure(NaiveHTTP2Error.connectionFailed("Stream closed")))
            inbox.cancel()
        }
    }

    // MARK: - Session Callbacks (called on multiplexer.queue)

    func handleHeaders(_ frame: NaiveHTTP2Frame) {
        guard let multiplexer, let decoded = multiplexer.hpackDecoder.decodeHeaders(from: frame.payload) else {
            handleStreamError(NaiveHTTP2Error.protocolError("Failed to decode headers on stream \(streamID)"))
            return
        }
        // No re-encode/forwarding here, so the never-indexed marker can be ignored.
        let headers = decoded.fields

        guard let statusHeader = headers.first(where: { $0.name == ":status" }) else {
            handleStreamError(NaiveHTTP2Error.protocolError("Missing :status on stream \(streamID)"))
            return
        }

        let status = statusHeader.value

        if state == .connectSent {
            if status == "200" {
                responseHeaders = headers
                state = .open
                connectPromise.resolve(.success(()))
            } else if status == "407" {
                handleStreamError(NaiveHTTP2Error.authenticationRequired)
            } else {
                handleStreamError(NaiveHTTP2Error.tunnelFailed(statusCode: status))
            }
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
            if state != .closed {
                state = .closed
                multiplexer?.removeStream(self)
            }
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

    private func handleStreamError(_ error: Error) {
        guard state != .closed else { return }
        state = .closed
        multiplexer?.removeStream(self)

        connectPromise.resolve(.failure(error))
        inbox.fail(error)
    }

    // MARK: - Flow Control (called by multiplexer on multiplexer.queue)

    private func acknowledgeConsumedData(count: Int) {
        recvConsumed += count
        if recvConsumed >= recvWindowSize / 2 {
            let increment = UInt32(recvConsumed)
            recvConsumed = 0
            multiplexer?.sendControlFrame(
                NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment)
            )
        }
        multiplexer?.acknowledgeReceivedData(count: count)
    }

    func consumeSendWindow(_ bytes: Int) {
        sendWindow -= bytes
    }

    func adjustSendWindow(delta: Int) {
        sendWindow += delta
    }
}
