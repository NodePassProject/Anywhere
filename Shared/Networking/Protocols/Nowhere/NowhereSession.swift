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

nonisolated final class NowhereQueuedDatagram: @unchecked Sendable {
    let payload: Data
    private let reservation: NowhereUDPBudgetReservation

    init(payload: Data, reservation: NowhereUDPBudgetReservation) {
        self.payload = payload
        self.reservation = reservation
    }
}

nonisolated final class NowhereUDPBudgetReservation: @unchecked Sendable {
    let units: Int
    private let release: @Sendable (Int) -> Void

    init(units: Int, release: @escaping @Sendable (Int) -> Void) {
        self.units = units
        self.release = release
    }

    deinit { release(units) }
}

/// Shared QUIC carrier. The first business stream carries AUTH followed immediately by
/// its FLOW request; later streams wait for the Portal's post-auth stream credit.
actor NowhereSession {
    nonisolated var unownedExecutor: UnownedSerialExecutor { quic.unownedExecutor }

    private enum State { case idle, connecting, transportReady, authenticating, ready, closed }

    private struct UDPRoute {
        let connection: NowhereUDPConnection
        var ready: Bool
    }

    private struct ReassemblyKey: Hashable {
        let flowID: UInt32
        let packetID: UInt32
    }

    private struct ReassemblySlot {
        let createdAt: ContinuousClock.Instant
        let fragmentCount: UInt8
        let totalLength: UInt16
        var fragments: [Data?]
        var received = 0
        var receivedBytes = 0
        let reservation: NowhereUDPBudgetReservation
    }

    private let quic: QUICConnection
    private let configuration: NowhereConfiguration
    private var state: State = .idle
    private var closed = false
    private var authFrame: Data?
    private var firstStreamID: Int64?
    private var bootstrapSubmitted = false
    private var postAuthCreditObserved = false

    private let transportSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let transportTask: Task<Void, Error>
    private let authSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let authTask: Task<Void, Error>

    private var tcpStreams: [Int64: NowhereConnection] = [:]
    private var udpRoutes: [UInt32: UDPRoute] = [:]
    private var udpControlStreams: [Int64: NowhereUDPConnection] = [:]
    private var reassembly: [ReassemblyKey: ReassemblySlot] = [:]
    private var reassemblyExpiryTask: Task<Void, Never>?
    private var udpBudgetUsed = 0
    static let maxUDPFlows = 256
    private static let maxReassemblySlots = 64
    private static let udpBudgetLimit = 4 * 1024 * 1024
    private static let reassemblyTTL: Duration = .seconds(10)

    private var idleCloseTask: Task<Void, Never>?
    private static let idleCloseDelay: TimeInterval = 60

    private struct PoolState {
        var isClosed = false
        var tcpCount = 0
        var udpCount = 0
        var onClose: (@Sendable () -> Void)?
    }
    private let poolState = Mutex(PoolState())

    nonisolated var isClosed: Bool { poolState.withLock { $0.isClosed } }
    nonisolated var hasActiveConnections: Bool {
        poolState.withLock { $0.tcpCount > 0 || $0.udpCount > 0 }
    }

    nonisolated func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        poolState.withLock { $0.onClose = hook }
    }

    init(configuration: NowhereConfiguration, transport: QUICDatagramTransport? = nil) {
        self.configuration = configuration
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.tls.serverName,
            alpn: [configuration.alpn],
            datagramsEnabled: true,
            tuning: .nowhere,
            transport: transport
        )
        let (transportStream, transportSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.transportSignal = transportSignal
        self.transportTask = Task { for try await _ in transportStream {} }
        let (authStream, authSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.authSignal = authSignal
        self.authTask = Task { for try await _ in authStream {} }
    }

    /// Establishes QUIC/TLS and the exporter. Authentication is deliberately deferred until
    /// the first business flow supplies bytes for the pre-auth stream.
    func ensureReady() async throws {
        if state == .idle {
            state = .connecting
            startConnection()
        }
        try await transportTask.value
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
                self?.assumeIsolated {
                    $0.postAuthCreditObserved = true
                    $0.finishAuthenticationIfReady()
                }
            }
            handlers.datagram = { [weak self] data in
                self?.assumeIsolated { $0.handleDatagram(data) }
            }
        }

        Task {
            do {
                try await quic.connect()
                let exporter = try await quic.exportKeyingMaterial(
                    label: "EXPORTER-Nowhere-Auth",
                    context: Data(),
                    length: 32
                )
                authFrame = try NowhereProtocol.makeAuthFrame(
                    authKey: configuration.authKey,
                    transport: .quic,
                    exporter: exporter,
                    sessionID: configuration.sessionID
                )
                guard state == .connecting else { return }
                state = .transportReady
                transportSignal.finish()
            } catch {
                failSession(error)
            }
        }
    }

    private func finishAuthenticationIfReady() {
        guard state == .authenticating, bootstrapSubmitted, postAuthCreditObserved else { return }
        state = .ready
        quic.handlers.withLock { $0.bidiCredit = nil }
        authSignal.finish()
        updateIdleCloseTimer()
    }

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
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
        if firstStreamID == sid, state == .authenticating {
            failSession(error ?? NowhereError.authFailed("Bootstrap stream closed before authentication"))
            return
        }
        if let connection = tcpStreams.removeValue(forKey: sid) {
            poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
            updateIdleCloseTimer()
            connection.handleStreamTermination(error: error)
            return
        }
        if let connection = udpControlStreams.removeValue(forKey: sid) {
            connection.handleControlStreamTermination(error: error)
        }
    }

    private func handleDatagram(_ data: Data) {
        guard let envelope = NowhereProtocol.decodeUDPEnvelope(data),
              let route = udpRoutes[envelope.flowID], route.ready,
              let message = NowhereProtocol.decodeUDPDatagram(data) else { return }
        switch message.type {
        case .data:
            guard let reservation = reserveUDPBudget(message.payload.count) else { return }
            route.connection.handleIncomingDatagram(
                NowhereQueuedDatagram(payload: message.payload, reservation: reservation)
            )
        case .fragment:
            if let queued = acceptFragment(message) {
                route.connection.handleIncomingDatagram(queued)
            }
        case .close:
            removeReassembly(flowID: message.flowID)
            route.connection.handleFlowClose()
        }
    }

    private func reserveUDPBudget(_ payloadLength: Int) -> NowhereUDPBudgetReservation? {
        let units = max(payloadLength, 1)
        guard units <= Self.udpBudgetLimit - udpBudgetUsed else { return nil }
        udpBudgetUsed += units
        return NowhereUDPBudgetReservation(units: units) { [weak self] released in
            self?.releaseUDPBudget(released)
        }
    }

    private nonisolated func releaseUDPBudget(_ units: Int) {
        Task { await self.performReleaseUDPBudget(units) }
    }

    private func performReleaseUDPBudget(_ units: Int) {
        udpBudgetUsed = max(0, udpBudgetUsed - units)
    }

    private func acceptFragment(_ message: NowhereProtocol.UDPMessage) -> NowhereQueuedDatagram? {
        expireReassembly(now: .now)
        let key = ReassemblyKey(flowID: message.flowID, packetID: message.packetID)
        var slot: ReassemblySlot
        if let existing = reassembly[key] {
            guard existing.fragmentCount == message.fragmentCount,
                  existing.totalLength == message.totalLength else {
                reassembly.removeValue(forKey: key)
                scheduleReassemblyExpiry()
                return nil
            }
            slot = existing
        } else {
            guard reassembly.count < Self.maxReassemblySlots,
                  let reservation = reserveUDPBudget(Int(message.totalLength)) else { return nil }
            slot = ReassemblySlot(
                createdAt: .now,
                fragmentCount: message.fragmentCount,
                totalLength: message.totalLength,
                fragments: Array(repeating: nil, count: Int(message.fragmentCount)),
                reservation: reservation
            )
        }

        let index = Int(message.fragmentID)
        if let duplicate = slot.fragments[index] {
            if duplicate != message.payload { reassembly.removeValue(forKey: key) }
            scheduleReassemblyExpiry()
            return nil
        }
        guard slot.receivedBytes + message.payload.count <= Int(slot.totalLength) else {
            reassembly.removeValue(forKey: key)
            scheduleReassemblyExpiry()
            return nil
        }
        slot.fragments[index] = message.payload
        slot.received += 1
        slot.receivedBytes += message.payload.count
        guard slot.received == Int(slot.fragmentCount) else {
            reassembly[key] = slot
            scheduleReassemblyExpiry()
            return nil
        }

        reassembly.removeValue(forKey: key)
        guard slot.receivedBytes == Int(slot.totalLength) else {
            scheduleReassemblyExpiry()
            return nil
        }
        var payload = Data(capacity: Int(slot.totalLength))
        for fragment in slot.fragments {
            guard let fragment else { return nil }
            payload.append(fragment)
        }
        scheduleReassemblyExpiry()
        return NowhereQueuedDatagram(payload: payload, reservation: slot.reservation)
    }

    private func removeReassembly(flowID: UInt32) {
        reassembly = reassembly.filter { $0.key.flowID != flowID }
        scheduleReassemblyExpiry()
    }

    private func expireReassembly(now: ContinuousClock.Instant) {
        reassembly = reassembly.filter {
            $0.value.createdAt.duration(to: now) <= Self.reassemblyTTL
        }
    }

    private func scheduleReassemblyExpiry() {
        reassemblyExpiryTask?.cancel()
        reassemblyExpiryTask = nil
        guard let earliest = reassembly.values.map(\.createdAt).min() else { return }
        let deadline = earliest.advanced(by: Self.reassemblyTTL)
        reassemblyExpiryTask = Task { [weak self] in
            try? await Task.sleep(until: deadline, clock: .continuous)
            guard !Task.isCancelled, let self else { return }
            await self.expireAndRescheduleReassembly()
        }
    }

    private func expireAndRescheduleReassembly() {
        expireReassembly(now: .now)
        scheduleReassemblyExpiry()
    }

    private func openStream(
        request: Data,
        fin: Bool,
        earlyDataAttempt: NowhereFlowOpenAttempt? = nil,
        register: (Int64) -> Void
    ) async throws -> Int64 {
        try await ensureReady()
        if state == .transportReady {
            guard let authFrame, let sid = quic.openBidiStream() else {
                throw NowhereError.connectionFailed("Failed to open bootstrap stream")
            }
            state = .authenticating
            firstStreamID = sid
            register(sid)
            var bootstrap = Data(capacity: authFrame.count + request.count)
            bootstrap.append(authFrame)
            bootstrap.append(request)
            do {
                earlyDataAttempt?.markEarlyDataWriteStarted()
                try await quic.writeStream(sid, data: bootstrap, fin: fin)
                bootstrapSubmitted = true
                finishAuthenticationIfReady()
                return sid
            } catch {
                failSession(error)
                throw error
            }
        }

        try await authTask.value
        guard state == .ready else { throw NowhereError.streamClosed }
        let sid = try await quic.awaitBidiStream()
        do {
            try Task.checkCancellation()
        } catch {
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
            throw error
        }
        register(sid)
        do {
            earlyDataAttempt?.markEarlyDataWriteStarted()
            try await quic.writeStream(sid, data: request, fin: fin)
            return sid
        } catch {
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
            throw error
        }
    }

    func openTCPStream(
        for connection: NowhereConnection,
        request: Data,
        earlyDataAttempt: NowhereFlowOpenAttempt?
    ) async throws -> Int64 {
        let sid = try await openStream(
            request: request,
            fin: false,
            earlyDataAttempt: earlyDataAttempt
        ) { sid in
            tcpStreams[sid] = connection
            poolState.withLock { $0.tcpCount += 1 }
            updateIdleCloseTimer()
        }
        return sid
    }

    func openUDPControlStream(for connection: NowhereUDPConnection, request: Data) async throws -> Int64 {
        try await openStream(request: request, fin: true) { sid in
            udpControlStreams[sid] = connection
        }
    }

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
            poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
            updateIdleCloseTimer()
        }
    }

    nonisolated func releaseUDPControlStream(_ sid: Int64) {
        Task { await self.performReleaseUDPControlStream(sid) }
    }

    private func performReleaseUDPControlStream(_ sid: Int64) {
        udpControlStreams.removeValue(forKey: sid)
    }

    func registerUDPSession(
        _ connection: NowhereUDPConnection,
        requestedFlowID: UInt32? = nil
    ) throws -> UInt32 {
        guard state != .closed, state != .idle else { throw NowhereError.notReady }
        guard udpRoutes.count < Self.maxUDPFlows else {
            throw NowhereError.connectionFailed("UDP flow pool exhausted")
        }
        guard let flowID = requestedFlowID, flowID != 0, udpRoutes[flowID] == nil else {
            throw NowhereError.connectionFailed("UDP flow ID collision")
        }
        udpRoutes[flowID] = UDPRoute(connection: connection, ready: false)
        poolState.withLock { $0.udpCount += 1 }
        updateIdleCloseTimer()
        return flowID
    }

    func activateUDPSession(_ flowID: UInt32) {
        guard var route = udpRoutes[flowID] else { return }
        route.ready = true
        udpRoutes[flowID] = route
    }

    nonisolated func releaseUDPSession(_ flowID: UInt32) {
        Task { await self.performReleaseUDPSession(flowID) }
    }

    private func performReleaseUDPSession(_ flowID: UInt32) {
        if udpRoutes.removeValue(forKey: flowID) != nil {
            removeReassembly(flowID: flowID)
            poolState.withLock { $0.udpCount = max(0, $0.udpCount - 1) }
            updateIdleCloseTimer()
        }
    }

    nonisolated func writeDatagrams(_ datagrams: [Data]) async throws {
        try await quic.writeDatagramsAtomically(datagrams)
    }

    nonisolated func currentMaxDatagramPayloadSize() async -> Int {
        await quic.currentMaxDatagramPayloadSize()
    }

    private func updateIdleCloseTimer() {
        idleCloseTask?.cancel()
        idleCloseTask = nil
        guard state == .ready else { return }
        let total = poolState.withLock { $0.tcpCount + $0.udpCount }
        guard total == 0 else { return }
        idleCloseTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.idleCloseDelay))
            guard !Task.isCancelled, let self else { return }
            await self.closeIfStillIdle()
        }
    }

    private func closeIfStillIdle() {
        let liveCount = poolState.withLock { $0.tcpCount + $0.udpCount }
        guard liveCount == 0, state == .ready else { return }
        performTeardown(readyError: NowhereError.streamClosed, handleClean: true)
    }

    nonisolated func close() {
        quic.enqueue {
            self.assumeIsolated {
                $0.performTeardown(readyError: NowhereError.streamClosed, handleClean: true)
            }
        }
    }

    private func failSession(_ error: Error) {
        performTeardown(readyError: error, handleClean: false, error: error)
    }

    private func performTeardown(readyError: Error, handleClean: Bool, error: Error? = nil) {
        guard !closed else { return }
        closed = true
        state = .closed
        idleCloseTask?.cancel()
        idleCloseTask = nil
        reassemblyExpiryTask?.cancel()
        reassemblyExpiryTask = nil
        quic.handlers.withLock { $0.bidiCredit = nil }

        let onClose = poolState.withLock { state in
            state.isClosed = true
            state.tcpCount = 0
            state.udpCount = 0
            let hook = state.onClose
            state.onClose = nil
            return hook
        }
        transportSignal.finish(throwing: readyError)
        authSignal.finish(throwing: readyError)

        let tcp = Array(tcpStreams.values)
        let udp = udpRoutes.values.map(\.connection)
        tcpStreams.removeAll()
        udpRoutes.removeAll()
        reassembly.removeAll()
        udpControlStreams.removeAll()
        if handleClean {
            for connection in tcp { connection.handleSessionClose() }
            for connection in udp { connection.handleSessionClose() }
        } else {
            let failure = error ?? NowhereError.streamClosed
            for connection in tcp { connection.handleSessionError(failure) }
            for connection in udp { connection.handleSessionError(failure) }
        }
        quic.close()
        onClose?()
    }
}
