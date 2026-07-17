//
//  NowhereSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated enum NowhereError: Error, LocalizedError {
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

nonisolated final class NowhereSession: Sendable {

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: NowhereConfiguration

    var queue: DispatchQueue { quic.queue }
    var isOnQueue: Bool { quic.isOnQueue }

    /// Runs `body` on the ngtcp2 queue and awaits its result (forwards the bridge hop), so
    /// this session's connections stay free of raw `queue.async`+continuation.
    func run<T>(_ body: @escaping () -> T) async -> T { await quic.run(body) }
    func run<T>(_ body: @escaping () -> Result<T, Error>) async throws -> T { try await quic.run(body) }

    private var state: State = .idle
    private var closed = false

    private var authStreamID: Int64 = -1
    private var authFrameWritten = false
    /// Readiness latch: the ready/teardown path finishes `readySignal` (throwing on failure);
    /// every awaiter gets that one outcome via `readyTask.value` (broadcast, cached once resolved).
    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    var onClose: (() -> Void)?

    private var tcpStreams: [Int64: NowhereConnection] = [:]
    private var udpSessions: [UInt64: NowhereUDPConnection] = [:]
    private var udpControlStreams: [Int64: NowhereUDPConnection] = [:]

    static let maxUDPFlows = 256

    /// Pending idle close, accessed only on `queue`. Without it the QUIC
    /// connection stays resident forever after the last consumer goes away.
    private var idleCloseTask: Task<Void, Never>?
    private static let idleCloseDelay: TimeInterval = 60

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
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
    }

    func ensureReady() async throws {
        // Kick off connect+auth exactly once, on the ngtcp2 queue; the gate resolves it.
        await quic.run { [self] in
            guard state == .idle else { return }
            state = .connecting
            startConnection()
        }
        // Resolves on `.ready` (success) or teardown (`.streamClosed` retryable / real error).
        try await readyTask.value
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
        
        Task { [weak self] in
            guard let self else { return }
            do {
                try await quic.connect()
            } catch {
                await quic.run { self.failSession(error) }
                return
            }
            await quic.run { [self] in
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

        Task { [weak self] in
            guard let self else { return }
            do {
                try await quic.writeStream(sid, data: frame, fin: true)
            } catch {
                await quic.run { self.failSession(error) }
                return
            }
            await quic.run { [self] in
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
        readySignal.finish()
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
            connection.feedStreamData(data, fin: fin)
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

    func openTCPStream(for connection: NowhereConnection) async throws -> Int64 {
        try await quic.run { [self] () -> Result<Int64, Error> in
            guard state == .ready else { return .failure(NowhereError.notReady) }
            guard let sid = quic.openBidiStream() else {
                return .failure(NowhereError.connectionFailed("Failed to open TCP stream"))
            }
            tcpStreams[sid] = connection
            _poolState.withLock { $0.tcpCount += 1 }
            updateIdleCloseTimer()
            return .success(sid)
        }
    }

    /// Async stream write, over the QUIC ngtcp2-boundary continuation.
    func writeStream(_ sid: Int64, data: Data, fin: Bool = false) async throws {
        try await quic.writeStream(sid, data: data, fin: fin)
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

    func openUDPControlStream(for connection: NowhereUDPConnection) async throws -> Int64 {
        try await quic.run { [self] () -> Result<Int64, Error> in
            guard state == .ready else { return .failure(NowhereError.notReady) }
            guard let sid = quic.openBidiStream() else {
                return .failure(NowhereError.connectionFailed("Failed to open UDP control stream"))
            }
            udpControlStreams[sid] = connection
            return .success(sid)
        }
    }

    func releaseUDPControlStream(_ sid: Int64) {
        queue.async { [weak self] in
            self?.udpControlStreams.removeValue(forKey: sid)
        }
    }

    /// Async half-close of a stream, over the QUIC ngtcp2-boundary continuation.
    func finishStream(_ sid: Int64) async throws {
        try await quic.writeStream(sid, data: Data(), fin: true)
    }

    func registerUDPSession(
        _ connection: NowhereUDPConnection,
        requestedFlowID: UInt64? = nil
    ) async throws -> UInt64 {
        try await quic.run { [self] () -> Result<UInt64, Error> in
            guard state == .ready else { return .failure(NowhereError.notReady) }
            guard udpSessions.count < Self.maxUDPFlows else {
                return .failure(NowhereError.connectionFailed("UDP flow pool exhausted"))
            }
            guard let flowID = requestedFlowID,
                  flowID != 0, udpSessions[flowID] == nil else {
                return .failure(NowhereError.connectionFailed("UDP flow ID collision"))
            }
            udpSessions[flowID] = connection
            _poolState.withLock { $0.udpCount += 1 }
            updateIdleCloseTimer()
            return .success(flowID)
        }
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

    /// Async atomic DATAGRAM batch write, over the QUIC ngtcp2-boundary continuation.
    func writeDatagrams(_ datagrams: [Data]) async throws {
        try await quic.writeDatagramsAtomically(datagrams)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    /// Async reader for the path-MTU-bounded datagram payload size (hops onto `queue`).
    func currentMaxDatagramPayloadSize() async -> Int {
        await quic.currentMaxDatagramPayloadSize()
    }

    /// Called on `queue`. Re-checks counts at fire time so a rapid
    /// release-then-open cycle doesn't tear the connection down.
    private func updateIdleCloseTimer() {
        idleCloseTask?.cancel()
        idleCloseTask = nil

        guard state == .ready else { return }
        let total = _poolState.withLock { $0.tcpCount + $0.udpCount }
        guard total == 0 else { return }

        // Fires on `queue` (hopped back on) so the re-check and close stay serialized with session state.
        idleCloseTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.idleCloseDelay))
            guard !Task.isCancelled, let self else { return }
            self.queue.async {
                let liveCount = self._poolState.withLock { $0.tcpCount + $0.udpCount }
                guard liveCount == 0, self.state == .ready else { return }
                self.close()
            }
        }
    }

    func close() {
        let work = {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed
            self.idleCloseTask?.cancel()
            self.idleCloseTask = nil
            self.quic.bidiCreditHandler = nil

            self._poolState.withLock { state in
                state.isClosed = true
                state.tcpCount = 0
                state.udpCount = 0
            }

            // `streamClosed` (not a connect failure) so a racing acquire retries on a fresh session.
            self.readySignal.finish(throwing: NowhereError.streamClosed)

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionClose() }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            self.udpControlStreams.removeAll()
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
            self.idleCloseTask?.cancel()
            self.idleCloseTask = nil
            self.quic.bidiCreditHandler = nil

            self._poolState.withLock { state in
                state.isClosed = true
                state.tcpCount = 0
                state.udpCount = 0
            }

            self.readySignal.finish(throwing: error)

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(error) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            self.udpControlStreams.removeAll()
            for c in udp { c.handleSessionError(error) }

            self.quic.close()
            self.onClose?()
        }
    }
}
