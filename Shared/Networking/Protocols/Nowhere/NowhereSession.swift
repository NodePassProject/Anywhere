//
//  NowhereSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

enum NowhereError: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case authFailed(String)
    case streamClosed
    case invalidTargetLength(Int)
    case destinationTooLargeForDatagram(maxFrame: Int, headerSize: Int)

    var errorDescription: String? {
        switch self {
        case .notReady: return "Nowhere session not ready"
        case .connectionFailed(let message): return "Nowhere connection failed: \(message)"
        case .authFailed(let message): return "Nowhere auth failed: \(message)"
        case .streamClosed: return "Nowhere stream closed"
        case .invalidTargetLength(let length): return "Nowhere target length is invalid (\(length))"
        case .destinationTooLargeForDatagram(let frame, let header):
            return "Nowhere destination too large for DATAGRAM (peer max \(frame) <= header \(header))"
        }
    }
}

nonisolated final class NowhereSession {

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: NowhereConfiguration

    var queue: DispatchQueue { quic.queue }
    var isOnQueue: Bool { quic.isOnQueue }

    private var state: State = .idle
    private var closed = false

    private var authStreamID: Int64 = -1
    private var readyCallbacks: [(Error?) -> Void] = []

    var onClose: (() -> Void)?

    private var tcpStreams: [Int64: NowhereConnection] = [:]
    private var udpSessions: [UInt64: NowhereUDPConnection] = [:]
    private var nextUDPFlowID: UInt64 = 1

    private var idleCloseWorkItem: DispatchWorkItem?
    private static let idleCloseDelay: DispatchTimeInterval = .seconds(60)

    private let _poolLock = UnfairLock()
    private var _poolIsClosed = false
    private var _poolTCPCount = 0
    private var _poolUDPCount = 0

    var poolIsClosed: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolIsClosed
    }

    var hasActiveConnections: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolTCPCount > 0 || _poolUDPCount > 0
    }

    init(configuration: NowhereConfiguration, transport: QUICDatagramTransport? = nil) {
        self.configuration = configuration
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.proxyHost,
            alpn: [NowhereProtocol.alpn],
            datagramsEnabled: true,
            tuning: .nowhere,
            transport: transport
        )
    }

    func ensureReady(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            switch self.state {
            case .ready:
                completion(nil)
            case .closed:
                completion(NowhereError.streamClosed)
            case .connecting, .authenticating:
                self.readyCallbacks.append(completion)
            case .idle:
                self.state = .connecting
                self.readyCallbacks.append(completion)
                self.startConnection()
            }
        }
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.connectionClosedHandler = { [weak self] error in
            self?.failSession(error)
        }
        quic.streamDataHandler = { [weak self] sid, data, fin in
            self?.handleStreamData(sid: sid, data: data, fin: fin)
        }
        quic.streamTerminationHandler = { [weak self] sid, error in
            self?.handleStreamTermination(sid: sid, error: error)
        }
        quic.datagramHandler = { [weak self] data in
            self?.handleDatagram(data)
        }

        quic.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.failSession(error)
                    return
                }
                self.state = .authenticating
                self.sendAuthFrame()
            }
        }
    }

    private func sendAuthFrame() {
        guard let sid = quic.openBidiStream() else {
            failSession(NowhereError.connectionFailed("Failed to open auth stream"))
            return
        }
        authStreamID = sid

        let frame: Data
        do {
            frame = try NowhereProtocol.makeAuthFrame(key: configuration.key)
        } catch {
            failSession(error)
            return
        }

        quic.writeStream(sid, data: frame, fin: true) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.failSession(error)
                    return
                }
                guard self.state == .authenticating else { return }
                self.state = .ready
                let callbacks = self.readyCallbacks
                self.readyCallbacks.removeAll()
                for cb in callbacks { cb(nil) }
            }
        }
    }

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        if sid == authStreamID {
            if !data.isEmpty {
                quic.extendStreamOffset(sid, count: data.count)
            }
            if state != .ready {
                failSession(NowhereError.authFailed("Auth stream returned unexpected data"))
            }
            return
        }

        if let conn = tcpStreams[sid] {
            conn.handleStreamData(data, fin: fin)
            return
        }

        if (sid & 0x01) == 0x01, !data.isEmpty {
            quic.extendStreamOffset(sid, count: data.count)
            quic.shutdownStream(sid)
        }
    }

    private func handleStreamTermination(sid: Int64, error: Error?) {
        if sid == authStreamID {
            if state == .authenticating {
                failSession(error ?? NowhereError.authFailed("Auth stream closed before completion"))
            }
            return
        }
        guard let conn = tcpStreams.removeValue(forKey: sid) else { return }
        _poolLock.lock()
        _poolTCPCount = max(0, _poolTCPCount - 1)
        _poolLock.unlock()
        updateIdleCloseTimer()
        conn.handleStreamTermination(error: error)
    }

    private func handleDatagram(_ data: Data) {
        guard let msg = NowhereProtocol.decodeUDPDatagram(data),
              msg.type == NowhereProtocol.UDPType.response.rawValue else { return }
        udpSessions[msg.flowID]?.handleIncomingDatagram(msg.payload)
    }

    func openTCPStream(for conn: NowhereConnection, completion: @escaping (Int64?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(nil, NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(nil, NowhereError.notReady)
                return
            }
            guard let sid = self.quic.openBidiStream() else {
                completion(nil, NowhereError.connectionFailed("Failed to open TCP stream"))
                return
            }
            self.tcpStreams[sid] = conn
            self._poolLock.lock()
            self._poolTCPCount += 1
            self._poolLock.unlock()
            self.updateIdleCloseTimer()
            completion(sid, nil)
        }
    }

    func writeStream(_ sid: Int64, data: Data, completion: @escaping (Error?) -> Void) {
        quic.writeStream(sid, data: data, completion: completion)
    }

    func extendStreamOffset(_ sid: Int64, count: Int) {
        quic.extendStreamOffset(sid, count: count)
    }

    func shutdownStream(_ sid: Int64) {
        quic.shutdownStream(sid)
    }

    func releaseTCPStream(_ sid: Int64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.tcpStreams.removeValue(forKey: sid) != nil {
                self._poolLock.lock()
                self._poolTCPCount = max(0, self._poolTCPCount - 1)
                self._poolLock.unlock()
                self.updateIdleCloseTimer()
            }
        }
    }

    func registerUDPSession(_ conn: NowhereUDPConnection, completion: @escaping (Result<UInt64, Error>) -> Void) {
        let body = { [weak self] in
            guard let self else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            guard self.state == .ready else {
                completion(.failure(NowhereError.notReady))
                return
            }
            guard self.udpSessions.count < Int.max else {
                completion(.failure(NowhereError.connectionFailed("UDP flow pool exhausted")))
                return
            }
            var fid = self.nextUDPFlowID
            while fid == 0 || self.udpSessions[fid] != nil {
                fid = fid == UInt64.max ? 1 : fid + 1
            }
            self.nextUDPFlowID = fid == UInt64.max ? 1 : fid + 1
            self.udpSessions[fid] = conn
            self._poolLock.lock()
            self._poolUDPCount += 1
            self._poolLock.unlock()
            self.updateIdleCloseTimer()
            completion(.success(fid))
        }
        if isOnQueue { body() } else { queue.async(execute: body) }
    }

    func releaseUDPSession(_ flowID: UInt64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.udpSessions.removeValue(forKey: flowID) != nil {
                self._poolLock.lock()
                self._poolUDPCount = max(0, self._poolUDPCount - 1)
                self._poolLock.unlock()
                self.updateIdleCloseTimer()
            }
        }
    }

    func writeDatagram(_ datagram: Data, completion: @escaping (Error?) -> Void) {
        quic.writeDatagram(datagram, completion: completion)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    private func updateIdleCloseTimer() {
        idleCloseWorkItem?.cancel()
        idleCloseWorkItem = nil

        guard state == .ready else { return }
        _poolLock.lock()
        let total = _poolTCPCount + _poolUDPCount
        _poolLock.unlock()
        guard total == 0 else { return }

        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self._poolLock.lock()
            let liveCount = self._poolTCPCount + self._poolUDPCount
            self._poolLock.unlock()
            guard liveCount == 0, self.state == .ready else { return }
            self.close()
        }
        idleCloseWorkItem = work
        queue.asyncAfter(deadline: .now() + Self.idleCloseDelay, execute: work)
    }

    func close() {
        let work = {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed
            self.idleCloseWorkItem?.cancel()
            self.idleCloseWorkItem = nil

            self._poolLock.lock()
            self._poolIsClosed = true
            self._poolTCPCount = 0
            self._poolUDPCount = 0
            self._poolLock.unlock()

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(NowhereError.connectionFailed("Session closed")) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(NowhereError.connectionFailed("Session closed")) }

            self.quic.close()
            self.onClose?()
        }
        if isOnQueue {
            work()
        } else {
            queue.async(execute: work)
        }
    }

    private func failSession(_ error: Error) {
        queue.async {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed
            self.idleCloseWorkItem?.cancel()
            self.idleCloseWorkItem = nil

            self._poolLock.lock()
            self._poolIsClosed = true
            self._poolTCPCount = 0
            self._poolUDPCount = 0
            self._poolLock.unlock()

            let callbacks = self.readyCallbacks
            self.readyCallbacks.removeAll()
            for cb in callbacks { cb(error) }

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(error) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(error) }

            self.quic.close()
            self.onClose?()
        }
    }
}
