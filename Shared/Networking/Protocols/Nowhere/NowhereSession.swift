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

/// One authenticated Nowhere session over a `QUICConnection`. An actor on the QUIC
/// connection's serial executor, so the demux path, the auth state machine, and ngtcp2
/// share a single isolation domain with no cross-queue dispatch.
actor NowhereSession {

    nonisolated var unownedExecutor: UnownedSerialExecutor { quic.unownedExecutor }

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: NowhereConfiguration

    private var state: State = .idle
    private var closed = false

    private var authStreamID: Int64 = -1
    private var authFrameWritten = false
    /// Readiness latch: the ready/teardown path finishes `readySignal` (throwing on failure);
    /// every awaiter gets that one outcome via `readyTask.value` (broadcast, cached once resolved).
    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    private var tcpStreams: [Int64: NowhereConnection] = [:]
    private var udpSessions: [UInt64: NowhereUDPConnection] = [:]
    private var udpControlStreams: [Int64: NowhereUDPConnection] = [:]

    static let maxUDPFlows = 256

    /// Pending idle close. Without it the QUIC connection stays resident forever
    /// after the last consumer goes away.
    private var idleCloseTask: Task<Void, Never>?
    private static let idleCloseDelay: TimeInterval = 60

    // MARK: Pool-visible state (read without entering the actor)

    private struct PoolState {
        var isClosed = false
        var tcpCount = 0
        var udpCount = 0
        /// Registry eviction hook, fired exactly once on close.
        var onClose: (@Sendable () -> Void)?
    }
    private let _poolState = Mutex(PoolState())

    nonisolated var protocolSpec: NowhereProtocol.EffectiveSpec { configuration.protocolSpec }

    nonisolated var isClosed: Bool {
        _poolState.withLock { $0.isClosed }
    }

    nonisolated var hasActiveConnections: Bool {
        _poolState.withLock { $0.tcpCount > 0 || $0.udpCount > 0 }
    }

    /// Installs the registry's eviction hook; fired exactly once when the session closes.
    nonisolated func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        _poolState.withLock { $0.onClose = hook }
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
        // Kick off connect+auth exactly once; the gate resolves it.
        if state == .idle {
            state = .connecting
            startConnection()
        }
        // Resolves on `.ready` (success) or teardown (`.streamClosed` retryable / real error).
        try await readyTask.value
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.handlers.withLock { handlers in
            handlers.connectionClosed = { [weak self] error in
                self?.assumeIsolated { $0.failSession(error) }
            }
            handlers.streamData = { [weak self] sid, data, fin in
                self?.assumeIsolated { $0.handleStreamData(sid: sid, data: data, fin: fin) }
            }
            handlers.streamTermination = { [weak self] sid, error in
                self?.assumeIsolated { $0.handleStreamTermination(sid: sid, error: error) }
            }
            handlers.bidiCredit = { [weak self] _ in
                self?.assumeIsolated { $0.finishAuthenticationIfReady() }
            }
            handlers.datagram = { [weak self] data in
                self?.assumeIsolated { $0.handleDatagram(data) }
            }
        }

        // Strong `self`: the connect task owns the session until auth kicks off, so it
        // can't deallocate mid-handshake and leak the ngtcp2 state.
        Task {
            do {
                try await quic.connect()
            } catch {
                failSession(error)
                return
            }
            state = .authenticating
            sendAuthFrame()
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

        // Strong `self`: the auth write task owns the session until the frame lands.
        Task {
            do {
                try await quic.writeStream(sid, data: frame, fin: true)
            } catch {
                failSession(error)
                return
            }
            guard state == .authenticating else { return }
            authFrameWritten = true
            finishAuthenticationIfReady()
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
        quic.handlers.withLock { $0.bidiCredit = nil }
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

    func openTCPStream(for connection: NowhereConnection) throws -> Int64 {
        guard state == .ready else { throw NowhereError.notReady }
        guard let sid = quic.openBidiStream() else {
            throw NowhereError.connectionFailed("Failed to open TCP stream")
        }
        tcpStreams[sid] = connection
        _poolState.withLock { $0.tcpCount += 1 }
        updateIdleCloseTimer()
        return sid
    }

    /// Async stream write, over the QUIC ngtcp2-boundary continuation.
    nonisolated func writeStream(_ sid: Int64, data: Data, fin: Bool = false) async throws {
        try await quic.writeStream(sid, data: data, fin: fin)
    }

    nonisolated func extendStreamOffset(_ sid: Int64, count: Int) {
        quic.extendStreamOffset(sid, count: count)
    }

    nonisolated func shutdownStream(_ sid: Int64) {
        quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
    }

    nonisolated func releaseTCPStream(_ sid: Int64) {
        Task { await self.performReleaseTCPStream(sid) }
    }

    private func performReleaseTCPStream(_ sid: Int64) {
        if tcpStreams.removeValue(forKey: sid) != nil {
            _poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
            updateIdleCloseTimer()
        }
    }

    func openUDPControlStream(for connection: NowhereUDPConnection) throws -> Int64 {
        guard state == .ready else { throw NowhereError.notReady }
        guard let sid = quic.openBidiStream() else {
            throw NowhereError.connectionFailed("Failed to open UDP control stream")
        }
        udpControlStreams[sid] = connection
        return sid
    }

    nonisolated func releaseUDPControlStream(_ sid: Int64) {
        Task { await self.performReleaseUDPControlStream(sid) }
    }

    private func performReleaseUDPControlStream(_ sid: Int64) {
        udpControlStreams.removeValue(forKey: sid)
    }

    /// Async half-close of a stream, over the QUIC ngtcp2-boundary continuation.
    nonisolated func finishStream(_ sid: Int64) async throws {
        try await quic.writeStream(sid, data: Data(), fin: true)
    }

    func registerUDPSession(
        _ connection: NowhereUDPConnection,
        requestedFlowID: UInt64? = nil
    ) throws -> UInt64 {
        guard state == .ready else { throw NowhereError.notReady }
        guard udpSessions.count < Self.maxUDPFlows else {
            throw NowhereError.connectionFailed("UDP flow pool exhausted")
        }
        guard let flowID = requestedFlowID,
              flowID != 0, udpSessions[flowID] == nil else {
            throw NowhereError.connectionFailed("UDP flow ID collision")
        }
        udpSessions[flowID] = connection
        _poolState.withLock { $0.udpCount += 1 }
        updateIdleCloseTimer()
        return flowID
    }

    nonisolated func releaseUDPSession(_ flowID: UInt64) {
        Task { await self.performReleaseUDPSession(flowID) }
    }

    private func performReleaseUDPSession(_ flowID: UInt64) {
        if udpSessions.removeValue(forKey: flowID) != nil {
            _poolState.withLock { $0.udpCount = max(0, $0.udpCount - 1) }
            updateIdleCloseTimer()
        }
    }

    /// Async atomic DATAGRAM batch write, over the QUIC ngtcp2-boundary continuation.
    nonisolated func writeDatagrams(_ datagrams: [Data]) async throws {
        try await quic.writeDatagramsAtomically(datagrams)
    }

    /// Async reader for the path-MTU-bounded datagram payload size.
    nonisolated func currentMaxDatagramPayloadSize() async -> Int {
        await quic.currentMaxDatagramPayloadSize()
    }

    /// Re-checks counts at fire time so a rapid release-then-open cycle doesn't
    /// tear the connection down.
    private func updateIdleCloseTimer() {
        idleCloseTask?.cancel()
        idleCloseTask = nil

        guard state == .ready else { return }
        let total = _poolState.withLock { $0.tcpCount + $0.udpCount }
        guard total == 0 else { return }

        // Weak: the idle timer observes its owner; it must not keep an otherwise
        // dropped session alive for the whole idle window.
        idleCloseTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.idleCloseDelay))
            guard !Task.isCancelled, let self else { return }
            await self.closeIfStillIdle()
        }
    }

    private func closeIfStillIdle() {
        let liveCount = _poolState.withLock { $0.tcpCount + $0.udpCount }
        guard liveCount == 0, state == .ready else { return }
        performTeardown(readyError: NowhereError.streamClosed, handleClean: true)
    }

    nonisolated func close() {
        // Strong `self`: an off-actor caller may hold the last reference; the enqueued
        // teardown must still run so the socket and ngtcp2 state are released.
        quic.enqueue {
            self.assumeIsolated {
                // `streamClosed` (not a connect failure) so a racing acquire retries on a fresh session.
                $0.performTeardown(readyError: NowhereError.streamClosed, handleClean: true)
            }
        }
    }

    private func failSession(_ error: Error) {
        performTeardown(readyError: error, handleClean: false, error: error)
    }

    /// Terminal teardown; the `closed` gate makes it run exactly once. `handleClean`
    /// selects the consumers' notification: `handleSessionClose()` for a deliberate
    /// close, `handleSessionError(_:)` with `error` for a failure.
    private func performTeardown(readyError: Error, handleClean: Bool, error: Error? = nil) {
        guard !closed else { return }
        closed = true
        state = .closed
        idleCloseTask?.cancel()
        idleCloseTask = nil
        quic.handlers.withLock { $0.bidiCredit = nil }

        let onClose = _poolState.withLock { state in
            state.isClosed = true
            state.tcpCount = 0
            state.udpCount = 0
            let hook = state.onClose
            state.onClose = nil
            return hook
        }

        readySignal.finish(throwing: readyError)

        let tcp = Array(tcpStreams.values)
        tcpStreams.removeAll()
        let udp = Array(udpSessions.values)
        udpSessions.removeAll()
        udpControlStreams.removeAll()

        if handleClean {
            for c in tcp { c.handleSessionClose() }
            for c in udp { c.handleSessionClose() }
        } else {
            let error = error ?? NowhereError.streamClosed
            for c in tcp { c.handleSessionError(error) }
            for c in udp { c.handleSessionError(error) }
        }

        quic.close()
        onClose?()
    }
}
