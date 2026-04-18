//
//  HysteriaConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/13/26.
//

import Foundation

private let logger = AnywhereLogger(category: "Hysteria")

final class HysteriaConnection: ProxyConnection {

    enum State { case idle, openingStream, handshaking, ready, closed }

    private let session: HysteriaSession
    private let destination: String

    private var state: State = .idle
    private var streamID: Int64 = -1

    /// True once we've observed FIN on the downlink (server half-closed its
    /// write side). The uplink is independent and stays open — `state`
    /// remains `.ready` so the caller can continue to `sendRaw` until it
    /// decides to tear the stream down. Blocks further reads: new
    /// `receiveRaw` calls return `(nil, nil)` once the buffer drains.
    ///
    /// Conflating this with `state = .closed` (prior bug) broke TCP
    /// half-close — any lwIP uplink bytes still coalesced at the moment the
    /// peer FIN'd would fail with `HysteriaError.streamClosed`, which is
    /// what produced the `[TCP] Send failed: host: Hysteria stream closed`
    /// line observed on gracefully-closing HTTPS connections.
    private var readClosed = false

    /// Buffer holding raw stream bytes we haven't yet delivered to a
    /// pending `receiveRaw` call, plus the unparsed response header.
    private var receiveBuffer = Data()
    private var responseParsed = false
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var pendingQuicBytes = 0

    private var openCompletion: ((Error?) -> Void)?

    init(session: HysteriaSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        session.isOnQueue ? (state == .ready) : session.queue.sync { state == .ready }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    // MARK: - Open (called by ProxyClient after session is ready)

    func open(completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard self.state == .idle else { completion(HysteriaError.notReady); return }
            self.openCompletion = completion
            self.state = .openingStream

            self.session.openTCPStream(for: self) { [weak self] sid, error in
                guard let self else { return }
                self.session.queue.async {
                    if let error {
                        self.fail(error)
                        return
                    }
                    guard let sid else {
                        self.fail(HysteriaError.connectionFailed("No stream"))
                        return
                    }
                    self.streamID = sid
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
        // On session queue (== quic.queue), called synchronously from
        // ngtcp2's read_pkt callback. `data` is a zero-copy view into
        // ngtcp2's receive buffer — any path that escapes to another
        // queue must detach it with Data(...) first; Data.append also
        // copies into our own storage.

        // Fast path: handshake done, nothing buffered, receiver waiting.
        // Deliver inline so the flow-control credit (extendStreamOffset)
        // rides read_pkt's tail-flush instead of an extra queue hop, and
        // we skip the intermediate append/extract through receiveBuffer.
        if responseParsed, receiveBuffer.isEmpty, !data.isEmpty,
           let cb = pendingReceive {
            pendingReceive = nil
            let ackCount = pendingQuicBytes + data.count
            pendingQuicBytes = 0
            session.extendStreamOffset(streamID, count: ackCount)
            cb(Data(data), nil)
            if fin { readClosed = true }
            return
        }

        if !data.isEmpty {
            pendingQuicBytes += data.count
            receiveBuffer.append(data)
        }

        if !responseParsed {
            tryParseResponse()
            if !responseParsed {
                if fin {
                    fail(HysteriaError.connectionFailed("Stream closed before response"))
                }
                return
            }
        }

        deliverBufferedOrEOF(eof: fin)
    }

    private func tryParseResponse() {
        guard let parsed = HysteriaProtocol.parseTCPResponse(from: receiveBuffer) else {
            return // incomplete
        }
        responseParsed = true
        receiveBuffer.removeFirst(parsed.consumed)
        // Flow-control credit is returned lazily when the app calls receive.

        guard parsed.status == HysteriaProtocol.tcpResponseStatusOK else {
            fail(HysteriaError.tunnelFailed(message: parsed.message))
            return
        }

        state = .ready
        if let cb = openCompletion {
            openCompletion = nil
            cb(nil)
        }
    }

    private func deliverBufferedOrEOF(eof: Bool) {
        // Record the half-close up front so both branches below see it and
        // the next receive can surface EOF. Previously this flag was only
        // set inside the `if eof` block after the early return, which meant
        // that when buffered data AND a pending receive AND FIN all arrived
        // together the EOF signal was lost — the caller would deliver the
        // buffer and then hang forever waiting for more data that would
        // never come.
        if eof { readClosed = true }

        if let cb = pendingReceive, !receiveBuffer.isEmpty {
            pendingReceive = nil
            let out = receiveBuffer
            receiveBuffer = Data()
            ackConsumedBytes()
            cb(out, nil)
            return
        }

        if eof {
            if let cb = pendingReceive {
                pendingReceive = nil
                cb(nil, nil)
            }
        }
    }

    private func ackConsumedBytes() {
        let count = pendingQuicBytes
        guard count > 0 else { return }
        pendingQuicBytes = 0
        session.extendStreamOffset(streamID, count: count)
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in self?.fail(error) }
    }

    /// Called by ``HysteriaSession`` when the QUIC layer signals that this
    /// stream is terminated — either the peer sent RESET_STREAM or the
    /// stream's `stream_close` callback fired. `error == nil` means a fully
    /// clean close with no app error code; a non-nil error wraps the app
    /// code the peer (or the local endpoint) sent.
    ///
    /// Runs on `session.queue`. Idempotent — `stream_reset` and
    /// `stream_close` can both fire for the same stream, and local
    /// `cancel()` may have already transitioned `state` to `.closed`.
    func handleStreamTermination(error: Error?) {
        guard state != .closed else { return }
        if let error {
            fail(error)
            return
        }
        // Clean termination. Flush any pending receive with EOF rather than
        // an error — the stream ended in good order.
        readClosed = true
        state = .closed
        if let cb = pendingReceive {
            pendingReceive = nil
            cb(nil, nil)
        }
    }

    private func fail(_ error: Error) {
        guard state != .closed else { return }
        state = .closed

        if let cb = openCompletion {
            openCompletion = nil
            cb(error)
        }
        if let cb = pendingReceive {
            pendingReceive = nil
            cb(nil, error)
        }
    }

    // MARK: - ProxyConnection overrides

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(HysteriaError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? HysteriaError.streamClosed : HysteriaError.notReady)
                return
            }
            self.session.writeStream(self.streamID, data: data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { error in
            if let error {
                logger.error("[Hysteria] TCP send error: \(error.localizedDescription)")
            }
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(nil, HysteriaError.streamClosed); return }
            if !self.receiveBuffer.isEmpty && self.responseParsed {
                let out = self.receiveBuffer
                self.receiveBuffer = Data()
                self.ackConsumedBytes()
                completion(out, nil)
                return
            }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            // Downlink half-closed and nothing left buffered — report EOF so
            // the caller can shut its read side without waiting on a packet
            // that will never arrive.
            if self.readClosed {
                completion(nil, nil)
                return
            }
            self.pendingReceive = completion
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            if self.streamID >= 0 {
                self.session.shutdownStream(self.streamID)
                self.session.releaseTCPStream(self.streamID)
            }
            if let cb = self.pendingReceive {
                self.pendingReceive = nil
                cb(nil, HysteriaError.streamClosed)
            }
        }
    }
}
