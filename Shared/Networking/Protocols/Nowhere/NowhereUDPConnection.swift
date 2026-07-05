//
//  NowhereUDPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

nonisolated final class NowhereUDPConnection: ProxyConnection {

    enum State { case idle, ready, closed }

    private let session: NowhereSession
    private let destination: String
    private let requestedFlowID: UInt64?
    private let downlink: NowhereNetwork

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

    private var flowID: UInt64 = 0
    private var packetQueue: [Data] = []
    private static let maxQueuedPackets = 1024
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var closureError: Error?
    private var compactReady = false

    init(
        session: NowhereSession,
        destination: String,
        requestedFlowID: UInt64? = nil,
        downlink: NowhereNetwork = .udp
    ) {
        self.session = session
        self.destination = destination
        self.requestedFlowID = requestedFlowID
        self.downlink = downlink
        super.init()
    }

    override var isConnected: Bool {
        readyLock.withLock { _isReady }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }
    override var deliversDatagrams: Bool { true }

    func open(completion: @escaping (Error?) -> Void) {
        session.registerUDPSession(self, requestedFlowID: requestedFlowID) { [weak self] result in
            guard let self else {
                completion(NowhereError.streamClosed)
                return
            }
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let flowID):
                self.flowID = flowID
                self.state = .ready
                completion(nil)
            }
        }
    }

    func handleOpenAck() { compactReady = true }

    func handleIncomingDatagram(_ payload: Data) {
        guard state != .closed, !payload.isEmpty else { return }
        if let callback = pendingReceive {
            pendingReceive = nil
            callback(payload, nil)
            return
        }
        if packetQueue.count >= Self.maxQueuedPackets {
            packetQueue.removeFirst()
        }
        packetQueue.append(payload)
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        guard !data.isEmpty else {
            completion(nil)
            return
        }
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? NowhereError.streamClosed : NowhereError.notReady)
                return
            }
            self.sendDatagramPayload(data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    private func sendDatagramPayload(_ payload: Data, completion: @escaping (Error?) -> Void) {
        let maxSize = session.maxDatagramPayloadSize
        let headerSize = compactReady ? 10 : 13 + destination.utf8.count
        guard maxSize > headerSize else {
            completion(NowhereError.destinationTooLargeForDatagram(maxFrame: maxSize, headerSize: headerSize))
            return
        }
        guard payload.count <= maxSize - headerSize else {
            completion(QUICConnection.QUICError.datagramTooLarge(maxBound: maxSize - headerSize))
            return
        }

        let frame: Data
        do {
            if compactReady {
                frame = try NowhereProtocol.encodeUDPCompact(
                    type: .data,
                    flowID: flowID,
                    payload: payload
                )
            } else {
                frame = try NowhereProtocol.encodeUDPOpenData(
                    flowID: flowID,
                    downlink: downlink,
                    target: destination,
                    payload: payload
                )
            }
        } catch {
            completion(error)
            return
        }
        session.writeDatagram(frame, completion: completion)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else {
                completion(nil, NowhereError.streamClosed)
                return
            }
            if !self.packetQueue.isEmpty {
                let packet = self.packetQueue.removeFirst()
                completion(packet, nil)
                return
            }
            if let error = self.closureError {
                self.closureError = nil
                completion(nil, error)
                return
            }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            let stale = self.pendingReceive
            self.pendingReceive = completion
            stale?(nil, NowhereError.connectionFailed("overlapping receiveRaw on Nowhere UDP"))
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.sendCloseFrame()
            self.session.releaseUDPSession(self.flowID)
            let callback = self.pendingReceive
            self.pendingReceive = nil
            self.packetQueue.removeAll()
            callback?(nil, nil)
        }
    }

    private func sendCloseFrame() {
        guard flowID != 0 else { return }
        let frame = try? NowhereProtocol.encodeUDPCompact(
            type: .compactClose,
            flowID: flowID
        )
        if let frame {
            session.writeDatagram(frame) { _ in }
        }
    }

    func handleSessionError(_ error: Error) {
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            handleSessionClose()
            return
        }
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            let callback = self.pendingReceive
            self.pendingReceive = nil
            if callback == nil {
                self.closureError = error
            }
            callback?(nil, error)
        }
    }

    func handleSessionClose() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            self.session.releaseUDPSession(self.flowID)
            let callback = self.pendingReceive
            self.pendingReceive = nil
            callback?(nil, nil)
        }
    }
}
