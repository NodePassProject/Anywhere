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
        // On session queue.
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
        if let cb = pendingReceive, !receiveBuffer.isEmpty {
            pendingReceive = nil
            let out = receiveBuffer
            receiveBuffer = Data()
            ackConsumedBytes()
            cb(out, nil)
            return
        }

        if eof {
            state = .closed
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
