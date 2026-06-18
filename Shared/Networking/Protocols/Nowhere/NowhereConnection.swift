//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

nonisolated final class NowhereConnection: ProxyConnection, NowhereTCPFlowSink {

    enum State { case idle, openingStream, handshaking, ready, closed }

    private let session: NowhereSession
    private let destination: String
    private let uploadLane: NowhereProtocol.LaneKind
    private let downloadLane: NowhereProtocol.LaneKind
    private weak var tcpDownlinkMux: NowhereTCPMuxClient?
    private let retainedTCPDownlinkMux: NowhereTCPMuxClient?

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
    private var flowID: UInt64 = 0
    private var readClosed = false
    private var receiveBuffer = Data()
    private var frameBuffer = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var openCompletion: ((Error?) -> Void)?

    init(
        session: NowhereSession,
        destination: String,
        uploadLane: NowhereProtocol.LaneKind = .quic,
        downloadLane: NowhereProtocol.LaneKind = .quic,
        tcpDownlinkMux: NowhereTCPMuxClient? = nil,
        retainedTCPDownlinkMux: NowhereTCPMuxClient? = nil
    ) {
        self.session = session
        self.destination = destination
        self.uploadLane = uploadLane
        self.downloadLane = downloadLane
        self.tcpDownlinkMux = tcpDownlinkMux
        self.retainedTCPDownlinkMux = retainedTCPDownlinkMux
        super.init()
    }

    var flowIdentifier: UInt64 { flowID }

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
                    self.flowID = UInt64(sid)
                    if self.downloadLane == .tcp {
                        self.tcpDownlinkMux?.registerFlowSink(self, flowID: self.flowID)
                    }
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
                flowID: flowID,
                uploadLane: uploadLane,
                downloadLane: downloadLane
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
        if !data.isEmpty {
            frameBuffer.append(data)
            session.extendStreamOffset(streamID, count: data.count)
            while let frame = NowhereProtocol.takeFrame(from: &frameBuffer) {
                guard frame.flowID == flowID else { continue }
                switch frame.type {
                case .flowData where frame.flags == NowhereProtocol.frameFlagDownload:
                    if !frame.payload.isEmpty {
                        receiveBuffer.append(frame.payload)
                    }
                case .flowClose:
                    readClosed = true
                default:
                    break
                }
            }
        }
        if fin { readClosed = true }

        guard state == .ready else { return }
        deliverBufferedOrEOF(eof: readClosed)
    }

    func handleIncomingData(_ data: Data) {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            if !data.isEmpty {
                self.receiveBuffer.append(data)
            }
            guard self.state == .ready else { return }
            self.deliverBufferedOrEOF(eof: self.readClosed)
        }
    }

    func handleRemoteClose() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.readClosed = true
            self.tcpDownlinkMux?.releaseFlowSink(self.flowID)
            guard self.state == .ready else { return }
            self.deliverBufferedOrEOF(eof: true)
        }
    }

    private func deliverBufferedOrEOF(eof: Bool) {
        if let cb = pendingReceive, !receiveBuffer.isEmpty {
            pendingReceive = nil
            let out = receiveBuffer
            receiveBuffer = Data()
            cb(out, nil)
            return
        }

        if eof, let cb = pendingReceive {
            pendingReceive = nil
            cb(nil, nil)
        }
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
        tcpDownlinkMux?.releaseFlowSink(flowID)
    }

    func handleClientError(_ error: Error) {
        handleSessionError(error)
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
        tcpDownlinkMux?.releaseFlowSink(flowID)
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? NowhereError.streamClosed : NowhereError.notReady)
                return
            }
            self.session.writeStream(
                self.streamID,
                data: NowhereProtocol.encodeTCPData(flowID: self.flowID, payload: data),
                completion: completion
            )
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
                self.session.writeStream(
                    self.streamID,
                    data: NowhereProtocol.encodeTCPClose(flowID: self.flowID)
                ) { _ in }
                self.session.shutdownStream(self.streamID)
                self.session.releaseTCPStream(self.streamID)
            }
            self.tcpDownlinkMux?.releaseFlowSink(self.flowID)
            if let cb = self.pendingReceive {
                self.pendingReceive = nil
                cb(nil, NowhereError.streamClosed)
            }
        }
    }
}
