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

    init(session: NowhereSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        readyLock.withLock { _isReady }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }
    override var deliversDatagrams: Bool { true }

    func open(completion: @escaping (Error?) -> Void) {
        session.registerUDPSession(self) { [weak self] result in
            guard let self else {
                completion(NowhereError.streamClosed)
                return
            }
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let fid):
                self.flowID = fid
                self.state = .ready
                completion(nil)
            }
        }
    }

    func handleIncomingDatagram(_ payload: Data) {
        guard state != .closed, !payload.isEmpty else { return }
        if let cb = pendingReceive {
            pendingReceive = nil
            cb(payload, nil)
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
        let headerSize = NowhereProtocol.udpHeaderSize(
            target: destination,
            protocolSpec: session.protocolSpec
        )
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
            frame = try NowhereProtocol.encodeUDPDatagram(
                type: .request,
                flowID: flowID,
                target: destination,
                payload: payload,
                protocolSpec: session.protocolSpec
            )
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
            if let err = self.closureError {
                self.closureError = nil
                completion(nil, err)
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
            let cb = self.pendingReceive
            self.pendingReceive = nil
            self.packetQueue.removeAll()
            cb?(nil, NowhereError.streamClosed)
        }
    }

    private func sendCloseFrame() {
        guard flowID != 0 else { return }
        let frame = try? NowhereProtocol.encodeUDPDatagram(
            type: .close,
            flowID: flowID,
            target: destination,
            payload: Data(),
            protocolSpec: session.protocolSpec
        )
        if let frame {
            session.writeDatagram(frame) { _ in }
        }
    }

    func handleSessionError(_ error: Error) {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            let cb = self.pendingReceive
            self.pendingReceive = nil
            if cb == nil {
                self.closureError = error
            }
            cb?(nil, error)
        }
    }
}
