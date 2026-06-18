//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

nonisolated final class NowhereConnection: ProxyConnection {

    enum State { case idle, openingStream, handshaking, ready, closed }

    private let session: NowhereSession
    private let destination: String

    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            readyLock.withLock { _isReady = (newValue == .ready) }
        }
    }
    private let readyLock = UnfairLock()
    private var _isReady = false

    private var streamID: Int64 = -1
    private var readClosed = false
    private var receiveBuffer = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var pendingQuicBytes = 0
    private var openCompletion: ((Error?) -> Void)?

    init(session: NowhereSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        readyLock.withLock { _isReady }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    func open(completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .idle else { completion(NowhereError.notReady); return }
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
                        self.fail(NowhereError.connectionFailed("No stream"))
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
        let frame: Data
        do {
            frame = try NowhereProtocol.encodeTCPRequest(
                address: destination,
                protocolSpec: session.protocolSpec
            )
        } catch {
            fail(error)
            return
        }
        session.writeStream(streamID, data: frame) { [weak self] error in
            guard let self else { return }
            self.session.queue.async {
                if let error {
                    self.fail(error)
                    return
                }
                guard self.state == .handshaking else { return }
                self.state = .ready
                if let cb = self.openCompletion {
                    self.openCompletion = nil
                    cb(nil)
                }
                self.deliverBufferedOrEOF(eof: self.readClosed)
            }
        }
    }

    func handleStreamData(_ data: Data, fin: Bool) {
        if state == .ready, receiveBuffer.isEmpty, !data.isEmpty,
           let cb = pendingReceive {
            pendingReceive = nil
            let ackCount = pendingQuicBytes + data.count
            pendingQuicBytes = 0
            let out = Data(data)
            if fin { readClosed = true }
            session.extendStreamOffset(streamID, count: ackCount)
            cb(out, nil)
            return
        }

        if !data.isEmpty {
            pendingQuicBytes += data.count
            receiveBuffer.append(data)
        }
        if fin { readClosed = true }

        guard state == .ready else { return }
        deliverBufferedOrEOF(eof: readClosed)
    }

    private func deliverBufferedOrEOF(eof: Bool) {
        if let cb = pendingReceive, !receiveBuffer.isEmpty {
            pendingReceive = nil
            let out = receiveBuffer
            receiveBuffer = Data()
            let ackCount = takePendingQuicBytes()
            session.extendStreamOffset(streamID, count: ackCount)
            cb(out, nil)
            return
        }

        if eof, let cb = pendingReceive {
            pendingReceive = nil
            cb(nil, nil)
        }
    }

    private func takePendingQuicBytes() -> Int {
        let count = pendingQuicBytes
        pendingQuicBytes = 0
        return count
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in self?.fail(error) }
    }

    func handleStreamTermination(error: Error?) {
        guard state != .closed else { return }
        if let error {
            fail(error)
            return
        }
        if state != .ready {
            fail(NowhereError.connectionFailed("Stream closed before request completed"))
            return
        }
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

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? NowhereError.streamClosed : NowhereError.notReady)
                return
            }
            self.session.writeStream(self.streamID, data: data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else {
                completion(nil, NowhereError.streamClosed)
                return
            }
            if !self.receiveBuffer.isEmpty && self.state == .ready {
                let out = self.receiveBuffer
                self.receiveBuffer = Data()
                let ackCount = self.takePendingQuicBytes()
                self.session.extendStreamOffset(self.streamID, count: ackCount)
                completion(out, nil)
                return
            }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
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
                cb(nil, NowhereError.streamClosed)
            }
        }
    }
}
