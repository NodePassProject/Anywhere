//
//  NowhereSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

enum NowhereError: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case authFailed(String)
    case streamClosed
    case invalidTargetLength(Int)
    case destinationTooLargeForDatagram(maxFrame: Int, headerSize: Int)
    case udpPacketTooLarge
    case flowRejected(NowhereProtocol.FlowRejectCode)
    case flowOpenTimeout

    var errorDescription: String? {
        switch self {
        case .notReady: return "Nowhere session not ready"
        case .connectionFailed(let message): return "Nowhere connection failed: \(message)"
        case .authFailed(let message): return "Nowhere auth failed: \(message)"
        case .streamClosed: return "Nowhere stream closed"
        case .invalidTargetLength(let length): return "Nowhere target length is invalid (\(length))"
        case .destinationTooLargeForDatagram(let frame, let header):
            return "Nowhere destination too large for DATAGRAM (peer max \(frame) <= header \(header))"
        case .udpPacketTooLarge: return "Nowhere UDP packet is too large"
        case .flowRejected(let code): return "Nowhere flow rejected: \(code.description)"
        case .flowOpenTimeout: return "Nowhere flow open timed out"
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
    private var authFrameWritten = false
    private var readyCallbacks: [(Error?) -> Void] = []

    var onClose: (() -> Void)?

    private var tcpStreams: [Int64: NowhereConnection] = [:]
    private var udpSessions: [UInt64: NowhereUDPConnection] = [:]
    private var udpControlStreams: [Int64: NowhereUDPConnection] = [:]

    static let maxUDPFlows = 256
    static let maxUDPReassemblySlots = 64
    static let maxUDPBufferedBytes = 4 * 1024 * 1024
    private var udpReassemblySlots = 0
    private var udpBufferedBytes = 0

    private var idleCloseWorkItem: DispatchWorkItem?
    private static let idleCloseDelay: DispatchTimeInterval = .seconds(60)

    private struct PoolState {
        var isClosed = false
        var tcpCount = 0
        var udpCount = 0
    }
    private let _poolState = Mutex(PoolState())

    var protocolSpec: NowhereProtocol.EffectiveSpec { configuration.protocolSpec }

    var isClosed: Bool {
        _poolState.withLock { $0.isClosed }
    }

    var hasActiveConnections: Bool {
        _poolState.withLock { $0.tcpCount > 0 || $0.udpCount > 0 }
    }

    init(configuration: NowhereConfiguration, transport: QUICDatagramTransport? = nil) {
        self.configuration = configuration
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.tls.serverName,
            alpn: [configuration.protocolSpec.effectiveALPN],
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
        quic.bidiCreditHandler = { [weak self] _ in
            self?.finishAuthenticationIfReady()
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
            frame = try NowhereProtocol.makeAuthFrame(
                key: configuration.key,
                protocolSpec: configuration.protocolSpec,
                sessionID: configuration.sessionID
            )
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
                self.authFrameWritten = true
                self.finishAuthenticationIfReady()
            }
        }
    }

    /// The auth write callback only means ngtcp2 accepted the frame locally.
    /// The Portal confirms successful authentication by increasing the stream
    /// limit from the single pre-auth stream; do not release callers before that
    /// MAX_STREAMS update reaches the client.
    private func finishAuthenticationIfReady() {
        guard state == .authenticating,
              authFrameWritten,
              quic.availableBidiStreams > 0 else { return }

        state = .ready
        quic.bidiCreditHandler = nil
        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for callback in callbacks { callback(nil) }
    }

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        if sid == authStreamID {
            if !data.isEmpty {
                quic.extendStreamOffset(sid, count: data.count)
                failSession(NowhereError.authFailed("Auth stream returned unexpected data"))
            }
            return
        }

        if let connection = tcpStreams[sid] {
            connection.handleStreamData(data, fin: fin)
            return
        }

        if let connection = udpControlStreams[sid] {
            connection.handleControlStreamData(data, fin: fin)
            return
        }

        if (sid & 0x01) == 0x01, !data.isEmpty {
            quic.extendStreamOffset(sid, count: data.count)
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
        }
    }

    private func handleStreamTermination(sid: Int64, error: Error?) {
        if sid == authStreamID {
            if state == .authenticating, let error {
                failSession(error)
            } else if state == .authenticating, !authFrameWritten {
                failSession(NowhereError.authFailed("Auth stream closed before completion"))
            }
            return
        }
        if let connection = tcpStreams.removeValue(forKey: sid) {
            _poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
            updateIdleCloseTimer()
            connection.handleStreamTermination(error: error)
            return
        }
        if let connection = udpControlStreams.removeValue(forKey: sid) {
            connection.handleControlStreamTermination(error: error)
        }
    }

    private func handleDatagram(_ data: Data) {
        guard let message = NowhereProtocol.decodeUDPDatagram(data),
              let connection = udpSessions[message.flowID] else { return }
        if message.type == .data {
            connection.handleIncomingDatagram(message)
        } else if message.type == .close {
            connection.handleFlowClose()
        }
    }

    func openTCPStream(for connection: NowhereConnection, completion: @escaping (Int64?, Error?) -> Void) {
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
            self.tcpStreams[sid] = connection
            self._poolState.withLock { $0.tcpCount += 1 }
            self.updateIdleCloseTimer()
            completion(sid, nil)
        }
    }

    func writeStream(
        _ sid: Int64,
        data: Data,
        fin: Bool = false,
        completion: @escaping (Error?) -> Void
    ) {
        quic.writeStream(sid, data: data, fin: fin, completion: completion)
    }

    func extendStreamOffset(_ sid: Int64, count: Int) {
        quic.extendStreamOffset(sid, count: count)
    }

    func shutdownStream(_ sid: Int64) {
        quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
    }

    func releaseTCPStream(_ sid: Int64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.tcpStreams.removeValue(forKey: sid) != nil {
                self._poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
                self.updateIdleCloseTimer()
            }
        }
    }

    func openUDPControlStream(
        for connection: NowhereUDPConnection,
        completion: @escaping (Int64?, Error?) -> Void
    ) {
        queue.async { [weak self] in
            guard let self else { completion(nil, NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(nil, NowhereError.notReady)
                return
            }
            guard let sid = self.quic.openBidiStream() else {
                completion(nil, NowhereError.connectionFailed("Failed to open UDP control stream"))
                return
            }
            self.udpControlStreams[sid] = connection
            completion(sid, nil)
        }
    }

    func releaseUDPControlStream(_ sid: Int64) {
        queue.async { [weak self] in
            self?.udpControlStreams.removeValue(forKey: sid)
        }
    }

    func finishStream(_ sid: Int64, completion: @escaping (Error?) -> Void) {
        quic.writeStream(sid, data: Data(), fin: true, completion: completion)
    }

    func registerUDPSession(
        _ connection: NowhereUDPConnection,
        requestedFlowID: UInt64? = nil,
        completion: @escaping (Result<UInt64, Error>) -> Void
    ) {
        let body = { [weak self] in
            guard let self else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            guard self.state == .ready else {
                completion(.failure(NowhereError.notReady))
                return
            }
            guard self.udpSessions.count < Self.maxUDPFlows else {
                completion(.failure(NowhereError.connectionFailed("UDP flow pool exhausted")))
                return
            }
            guard let flowID = requestedFlowID,
                  flowID != 0, self.udpSessions[flowID] == nil else {
                completion(.failure(NowhereError.connectionFailed("UDP flow ID collision")))
                return
            }
            self.udpSessions[flowID] = connection
            self._poolState.withLock { $0.udpCount += 1 }
            self.updateIdleCloseTimer()
            completion(.success(flowID))
        }
        if isOnQueue { body() } else { queue.async(execute: body) }
    }

    func reserveUDPBuffer(bytes: Int, reassemblySlot: Bool) -> Bool {
        dispatchPrecondition(condition: .onQueue(queue))
        guard bytes >= 0, bytes <= Self.maxUDPBufferedBytes,
              udpBufferedBytes <= Self.maxUDPBufferedBytes - bytes,
              !reassemblySlot || udpReassemblySlots < Self.maxUDPReassemblySlots else {
            return false
        }
        udpBufferedBytes += bytes
        if reassemblySlot { udpReassemblySlots += 1 }
        return true
    }

    func releaseUDPBuffer(bytes: Int, reassemblySlot: Bool) {
        dispatchPrecondition(condition: .onQueue(queue))
        udpBufferedBytes = max(0, udpBufferedBytes - max(0, bytes))
        if reassemblySlot { udpReassemblySlots = max(0, udpReassemblySlots - 1) }
    }

    func releaseUDPSession(_ flowID: UInt64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.udpSessions.removeValue(forKey: flowID) != nil {
                self._poolState.withLock { $0.udpCount = max(0, $0.udpCount - 1) }
                self.updateIdleCloseTimer()
            }
        }
    }

    func writeDatagram(_ datagram: Data, completion: @escaping (Error?) -> Void) {
        quic.writeDatagramsAtomically([datagram], completion: completion)
    }

    func writeDatagrams(_ datagrams: [Data], completion: @escaping (Error?) -> Void) {
        quic.writeDatagramsAtomically(datagrams, completion: completion)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    private func updateIdleCloseTimer() {
        idleCloseWorkItem?.cancel()
        idleCloseWorkItem = nil

        guard state == .ready else { return }
        let total = _poolState.withLock { $0.tcpCount + $0.udpCount }
        guard total == 0 else { return }

        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            let liveCount = self._poolState.withLock { $0.tcpCount + $0.udpCount }
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
            self.quic.bidiCreditHandler = nil

            self._poolState.withLock { state in
                state.isClosed = true
                state.tcpCount = 0
                state.udpCount = 0
            }

            let callbacks = self.readyCallbacks
            self.readyCallbacks.removeAll()
            for callback in callbacks { callback(NowhereError.streamClosed) }

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionClose() }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            self.udpControlStreams.removeAll()
            self.udpBufferedBytes = 0
            self.udpReassemblySlots = 0
            for c in udp { c.handleSessionClose() }

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
            self.quic.bidiCreditHandler = nil

            self._poolState.withLock { state in
                state.isClosed = true
                state.tcpCount = 0
                state.udpCount = 0
            }

            let callbacks = self.readyCallbacks
            self.readyCallbacks.removeAll()
            for callback in callbacks { callback(error) }

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(error) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            self.udpControlStreams.removeAll()
            self.udpBufferedBytes = 0
            self.udpReassemblySlots = 0
            for c in udp { c.handleSessionError(error) }

            self.quic.close()
            self.onClose?()
        }
    }
}
