//
//  NowhereSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated final class NowhereQueuedDatagram: Sendable {
    let payload: Data
    private let reservation: NowhereUDPBudgetReservation

    init(payload: Data, reservation: NowhereUDPBudgetReservation) {
        self.payload = payload
        self.reservation = reservation
    }
}

nonisolated final class NowhereUDPBudgetReservation: Sendable {
    let units: Int
    private let release: @Sendable (Int) -> Void

    init(units: Int, release: @escaping @Sendable (Int) -> Void) {
        self.units = units
        self.release = release
    }

    deinit { release(units) }
}

nonisolated final class NowhereSession: Sendable {

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

    /// Session + demux state, guarded by `lock`. Never held across a call into a consumer
    /// connection, a QUIC write, or a continuation resume; effects are computed under the
    /// lock and performed after it is released.
    private struct Session {
        var state: State = .idle
        var closed = false
        var authFrame: Data?
        var firstStreamID: Int64?
        var bootstrapSubmitted = false
        var postAuthCreditObserved = false

        var tcpStreams: [Int64: NowhereConnection] = [:]
        var udpRoutes: [UInt32: UDPRoute] = [:]
        var udpControlStreams: [Int64: NowhereUDPConnection] = [:]
        var reassembly: [ReassemblyKey: ReassemblySlot] = [:]
        var reassemblyExpiryTask: Task<Void, Never>?
        var udpBudgetUsed = 0

        var idleCloseTask: Task<Void, Never>?
    }
    private let lock = Mutex(Session())

    static let maxUDPFlows = 256
    private static let maxReassemblySlots = 64
    private static let udpBudgetLimit = 4 * 1024 * 1024
    private static let reassemblyTTL: Duration = .seconds(10)
    private static let idleCloseDelay: TimeInterval = 60

    private let transportSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let transportTask: Task<Void, Error>
    private let authSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let authTask: Task<Void, Error>

    private struct PoolState {
        var isClosed = false
        var tcpCount = 0
        var udpCount = 0
        var onClose: (@Sendable () -> Void)?
    }
    private let poolState = Mutex(PoolState())

    var isClosed: Bool { poolState.withLock { $0.isClosed } }
    var hasActiveConnections: Bool {
        poolState.withLock { $0.tcpCount > 0 || $0.udpCount > 0 }
    }

    func setOnClose(_ hook: @escaping @Sendable () -> Void) {
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
        let begin: Bool = lock.withLock { session in
            guard session.state == .idle else { return false }
            session.state = .connecting
            return true
        }
        if begin { startConnection() }
        try await transportTask.value
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()
        quic.handlers.withLock { handlers in
            handlers.connectionClosed = { [weak self] error in
                self?.failSession(error)
            }
            handlers.streamData = { [weak self] sid, data, fin in
                self?.handleStreamData(sid: sid, data: data, fin: fin)
            }
            handlers.streamTermination = { [weak self] sid, error in
                self?.handleStreamTermination(sid: sid, error: error)
            }
            handlers.bidiCredit = { [weak self] _ in
                guard let self else { return }
                self.lock.withLock { $0.postAuthCreditObserved = true }
                self.finishAuthenticationIfReady()
            }
            handlers.datagram = { [weak self] data in
                self?.handleDatagram(data)
            }
        }

        // Strong `self`: the connect task owns the session until the transport settles, so it
        // can't deallocate mid-handshake and leak the ngtcp2 state.
        Task { [self] in
            do {
                try await quic.connect()
                let exporter = try await quic.exportKeyingMaterial(
                    label: "EXPORTER-Nowhere-Auth",
                    context: Data(),
                    length: 32
                )
                let authFrame = try NowhereProtocol.makeAuthFrame(
                    authKey: configuration.authKey,
                    transport: .quic,
                    exporter: exporter,
                    sessionID: configuration.sessionID
                )
                let proceed: Bool = lock.withLock { session in
                    guard session.state == .connecting else { return false }
                    session.authFrame = authFrame
                    session.state = .transportReady
                    return true
                }
                if proceed { transportSignal.finish() }
            } catch {
                failSession(error)
            }
        }
    }

    private func finishAuthenticationIfReady() {
        let proceed: Bool = lock.withLock { session in
            guard session.state == .authenticating,
                  session.bootstrapSubmitted,
                  session.postAuthCreditObserved else { return false }
            session.state = .ready
            return true
        }
        guard proceed else { return }
        quic.handlers.withLock { $0.bidiCredit = nil }
        authSignal.finish()
        updateIdleCloseTimer()
    }

    // MARK: - Stream dispatch (delivered synchronously on the ngtcp2 queue)

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        enum Route { case tcp(NowhereConnection); case udpControl(NowhereUDPConnection); case serverReject; case ignore }
        let route: Route = lock.withLock { session in
            if let connection = session.tcpStreams[sid] { return .tcp(connection) }
            if let connection = session.udpControlStreams[sid] { return .udpControl(connection) }
            if (sid & 0x01) == 0x01, !data.isEmpty { return .serverReject }
            return .ignore
        }
        switch route {
        case .tcp(let connection):
            connection.feedStreamData(data, fin: fin)
        case .udpControl(let connection):
            connection.handleControlStreamData(data, fin: fin)
        case .serverReject:
            quic.extendStreamOffset(sid, count: data.count)
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
        case .ignore:
            break
        }
    }

    private func handleStreamTermination(sid: Int64, error: Error?) {
        enum Effect { case none; case failAuth(Error); case tcp(NowhereConnection); case udpControl(NowhereUDPConnection) }
        let effect: Effect = lock.withLock { session in
            if session.firstStreamID == sid, session.state == .authenticating {
                return .failAuth(error ?? AnywhereError.proxy(.nowhere, .authenticationRejected(status: nil, detail: "Bootstrap stream closed before authentication")))
            }
            if let connection = session.tcpStreams.removeValue(forKey: sid) { return .tcp(connection) }
            if let connection = session.udpControlStreams.removeValue(forKey: sid) { return .udpControl(connection) }
            return .none
        }
        switch effect {
        case .none:
            break
        case .failAuth(let error):
            failSession(error)
        case .tcp(let connection):
            poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
            updateIdleCloseTimer()
            connection.handleStreamTermination(error: error)
        case .udpControl(let connection):
            connection.handleControlStreamTermination(error: error)
        }
    }

    // MARK: - Datagram dispatch (UDP)

    private func handleDatagram(_ data: Data) {
        guard let envelope = NowhereProtocol.decodeUDPEnvelope(data),
              let message = NowhereProtocol.decodeUDPDatagram(data) else { return }

        enum Deliver { case datagram(NowhereQueuedDatagram); case flowClose; case none }
        let (connection, deliver): (NowhereUDPConnection?, Deliver) = lock.withLock { session in
            guard let route = session.udpRoutes[envelope.flowID], route.ready else { return (nil, .none) }
            switch message.type {
            case .data:
                guard let reservation = reserveUDPBudget(message.payload.count, &session) else { return (nil, .none) }
                return (route.connection, .datagram(
                    NowhereQueuedDatagram(payload: message.payload, reservation: reservation)
                ))
            case .fragment:
                if let queued = acceptFragment(message, &session) {
                    return (route.connection, .datagram(queued))
                }
                return (nil, .none)
            case .close:
                removeReassembly(flowID: message.flowID, &session)
                return (route.connection, .flowClose)
            }
        }

        switch deliver {
        case .datagram(let queued):
            connection?.handleIncomingDatagram(queued)
        case .flowClose:
            connection?.handleFlowClose()
        case .none:
            break
        }
    }

    /// Reserves `payloadLength` UDP-budget units (min 1), returning a reservation whose deinit
    /// releases them. Must be called with `lock` held.
    private func reserveUDPBudget(_ payloadLength: Int, _ session: inout Session) -> NowhereUDPBudgetReservation? {
        let units = max(payloadLength, 1)
        guard units <= Self.udpBudgetLimit - session.udpBudgetUsed else { return nil }
        session.udpBudgetUsed += units
        return NowhereUDPBudgetReservation(units: units) { [weak self] released in
            self?.releaseUDPBudget(released)
        }
    }

    /// Fired from a reservation's deinit — possibly while a lock-holder is dropping the slot that
    /// owns it — so it defers the mutation onto a fresh task to avoid re-entering `lock`.
    private func releaseUDPBudget(_ units: Int) {
        Task { [weak self] in
            self?.lock.withLock { $0.udpBudgetUsed = max(0, $0.udpBudgetUsed - units) }
        }
    }

    /// Must be called with `lock` held.
    private func acceptFragment(_ message: NowhereProtocol.UDPMessage, _ session: inout Session) -> NowhereQueuedDatagram? {
        expireReassembly(now: .now, &session)
        let key = ReassemblyKey(flowID: message.flowID, packetID: message.packetID)
        var slot: ReassemblySlot
        if let existing = session.reassembly[key] {
            guard existing.fragmentCount == message.fragmentCount,
                  existing.totalLength == message.totalLength else {
                session.reassembly.removeValue(forKey: key)
                scheduleReassemblyExpiry(&session)
                return nil
            }
            slot = existing
        } else {
            guard session.reassembly.count < Self.maxReassemblySlots,
                  let reservation = reserveUDPBudget(Int(message.totalLength), &session) else { return nil }
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
            if duplicate != message.payload { session.reassembly.removeValue(forKey: key) }
            scheduleReassemblyExpiry(&session)
            return nil
        }
        guard slot.receivedBytes + message.payload.count <= Int(slot.totalLength) else {
            session.reassembly.removeValue(forKey: key)
            scheduleReassemblyExpiry(&session)
            return nil
        }
        slot.fragments[index] = message.payload
        slot.received += 1
        slot.receivedBytes += message.payload.count
        guard slot.received == Int(slot.fragmentCount) else {
            session.reassembly[key] = slot
            scheduleReassemblyExpiry(&session)
            return nil
        }

        session.reassembly.removeValue(forKey: key)
        guard slot.receivedBytes == Int(slot.totalLength) else {
            scheduleReassemblyExpiry(&session)
            return nil
        }
        var payload = Data(capacity: Int(slot.totalLength))
        for fragment in slot.fragments {
            guard let fragment else { return nil }
            payload.append(fragment)
        }
        scheduleReassemblyExpiry(&session)
        return NowhereQueuedDatagram(payload: payload, reservation: slot.reservation)
    }

    /// Must be called with `lock` held.
    private func removeReassembly(flowID: UInt32, _ session: inout Session) {
        session.reassembly = session.reassembly.filter { $0.key.flowID != flowID }
        scheduleReassemblyExpiry(&session)
    }

    /// Must be called with `lock` held.
    private func expireReassembly(now: ContinuousClock.Instant, _ session: inout Session) {
        session.reassembly = session.reassembly.filter {
            $0.value.createdAt.duration(to: now) <= Self.reassemblyTTL
        }
    }

    /// Must be called with `lock` held.
    private func scheduleReassemblyExpiry(_ session: inout Session) {
        session.reassemblyExpiryTask?.cancel()
        session.reassemblyExpiryTask = nil
        guard let earliest = session.reassembly.values.map(\.createdAt).min() else { return }
        let deadline = earliest.advanced(by: Self.reassemblyTTL)
        session.reassemblyExpiryTask = Task { [weak self] in
            try? await Task.sleep(until: deadline, clock: .continuous)
            guard !Task.isCancelled, let self else { return }
            self.expireAndRescheduleReassembly()
        }
    }

    private func expireAndRescheduleReassembly() {
        lock.withLock { session in
            expireReassembly(now: .now, &session)
            scheduleReassemblyExpiry(&session)
        }
    }

    // MARK: - Stream open

    /// Opens a business stream, running AUTH bootstrap on the first flow. `registerUnderLock`
    /// records the stream in the session state (run in the same ngtcp2-queue turn as the open,
    /// so no demuxed byte can beat the registration); `afterRegister` runs the off-lock
    /// bookkeeping (pool counters, idle timer) before the request write.
    private func openStream(
        request: Data,
        fin: Bool,
        earlyDataAttempt: NowhereFlowOpenAttempt? = nil,
        registerUnderLock: @escaping @Sendable (inout Session, Int64) -> Void,
        afterRegister: @escaping @Sendable (Int64) -> Void = { _ in }
    ) async throws -> Int64 {
        try await ensureReady()

        // Bootstrap branch: the first business stream carries AUTH + this FLOW request.
        enum Bootstrap { case notBootstrap; case failed; case ok(sid: Int64, authFrame: Data) }
        let bootstrap: Bootstrap = await quic.run { () -> Bootstrap in
            guard self.lock.withLock({ $0.state == .transportReady }) else { return .notBootstrap }
            let authFrame = self.lock.withLock { $0.authFrame }
            guard let authFrame, let sid = self.quic.openBidiStream() else { return .failed }
            self.lock.withLock { session in
                session.state = .authenticating
                session.firstStreamID = sid
                registerUnderLock(&session, sid)
            }
            return .ok(sid: sid, authFrame: authFrame)
        }

        switch bootstrap {
        case .failed:
            throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Failed to open bootstrap stream"))
        case .ok(let sid, let authFrame):
            afterRegister(sid)
            var payload = Data(capacity: authFrame.count + request.count)
            payload.append(authFrame)
            payload.append(request)
            do {
                earlyDataAttempt?.markEarlyDataWriteStarted()
                try await quic.writeStream(sid, data: payload, fin: fin)
                lock.withLock { $0.bootstrapSubmitted = true }
                finishAuthenticationIfReady()
                return sid
            } catch {
                failSession(error)
                throw error
            }
        case .notBootstrap:
            break
        }

        // Steady state: wait for auth to finish, then open a normal stream.
        try await authTask.value
        guard lock.withLock({ $0.state == .ready }) else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        // Honor cancellation before spending a stream ID (the write below also surfaces it).
        try Task.checkCancellation()

        enum Opened { case failed; case ok(Int64) }
        let opened: Opened = await quic.run { () -> Opened in
            guard let sid = self.quic.openBidiStream() else { return .failed }
            self.lock.withLock { session in registerUnderLock(&session, sid) }
            return .ok(sid)
        }
        switch opened {
        case .failed:
            let error = AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Failed to open QUIC stream"))
            failSession(error)
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        case .ok(let sid):
            afterRegister(sid)
            do {
                earlyDataAttempt?.markEarlyDataWriteStarted()
                try await quic.writeStream(sid, data: request, fin: fin)
                return sid
            } catch {
                quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
                throw error
            }
        }
    }

    func openTCPStream(
        for connection: NowhereConnection,
        request: Data,
        earlyDataAttempt: NowhereFlowOpenAttempt?
    ) async throws -> Int64 {
        try await openStream(
            request: request,
            fin: false,
            earlyDataAttempt: earlyDataAttempt,
            registerUnderLock: { session, sid in session.tcpStreams[sid] = connection },
            afterRegister: { [weak self] _ in
                guard let self else { return }
                self.poolState.withLock { $0.tcpCount += 1 }
                self.updateIdleCloseTimer()
            }
        )
    }

    func openUDPControlStream(for connection: NowhereUDPConnection, request: Data) async throws -> Int64 {
        try await openStream(request: request, fin: true) { session, sid in
            session.udpControlStreams[sid] = connection
        }
    }

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
        let removed = lock.withLock { $0.tcpStreams.removeValue(forKey: sid) != nil }
        if removed {
            poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
            updateIdleCloseTimer()
        }
    }

    func releaseUDPControlStream(_ sid: Int64) {
        lock.withLock { _ = $0.udpControlStreams.removeValue(forKey: sid) }
    }

    // MARK: - UDP session API

    func registerUDPSession(
        _ connection: NowhereUDPConnection,
        requestedFlowID: UInt32? = nil
    ) async throws -> UInt32 {
        let flowID: UInt32 = try lock.withLock { session in
            guard session.state != .closed, session.state != .idle else { throw AnywhereError.proxy(.nowhere, .notReady) }
            guard session.udpRoutes.count < Self.maxUDPFlows else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "UDP flow pool exhausted"))
            }
            guard let flowID = requestedFlowID, flowID != 0, session.udpRoutes[flowID] == nil else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "UDP flow ID collision"))
            }
            session.udpRoutes[flowID] = UDPRoute(connection: connection, ready: false)
            return flowID
        }
        poolState.withLock { $0.udpCount += 1 }
        updateIdleCloseTimer()
        return flowID
    }

    func activateUDPSession(_ flowID: UInt32) async {
        lock.withLock { session in
            guard var route = session.udpRoutes[flowID] else { return }
            route.ready = true
            session.udpRoutes[flowID] = route
        }
    }

    func releaseUDPSession(_ flowID: UInt32) {
        let removed = lock.withLock { session -> Bool in
            guard session.udpRoutes.removeValue(forKey: flowID) != nil else { return false }
            removeReassembly(flowID: flowID, &session)
            return true
        }
        if removed {
            poolState.withLock { $0.udpCount = max(0, $0.udpCount - 1) }
            updateIdleCloseTimer()
        }
    }

    func writeDatagrams(_ datagrams: [Data]) async throws {
        try await quic.writeDatagramsAtomically(datagrams)
    }

    func currentMaxDatagramPayloadSize() async -> Int {
        await quic.currentMaxDatagramPayloadSize()
    }

    // MARK: - Idle close

    /// Re-checks counts at fire time so a rapid release-then-open cycle doesn't tear the
    /// connection down. `poolState` is read off `lock` (never nested).
    private func updateIdleCloseTimer() {
        lock.withLock { session in
            session.idleCloseTask?.cancel()
            session.idleCloseTask = nil
        }
        guard lock.withLock({ $0.state == .ready }) else { return }
        let total = poolState.withLock { $0.tcpCount + $0.udpCount }
        guard total == 0 else { return }

        let task = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.idleCloseDelay))
            guard !Task.isCancelled, let self else { return }
            self.closeIfStillIdle()
        }
        let armed = lock.withLock { session -> Bool in
            guard session.state == .ready else { return false }
            session.idleCloseTask?.cancel()   // cancel any timer raced in between the checks
            session.idleCloseTask = task
            return true
        }
        if !armed { task.cancel() }
    }

    private func closeIfStillIdle() {
        guard lock.withLock({ $0.state == .ready }) else { return }
        let liveCount = poolState.withLock { $0.tcpCount + $0.udpCount }
        guard liveCount == 0 else { return }
        performTeardown(readyError: AnywhereError.proxy(.nowhere, .streamClosed), handleClean: true)
    }

    // MARK: - Close

    func close() {
        performTeardown(readyError: AnywhereError.proxy(.nowhere, .streamClosed), handleClean: true)
    }

    private func failSession(_ error: Error) {
        performTeardown(readyError: error, handleClean: false, error: error)
    }

    private func performTeardown(readyError: Error, handleClean: Bool, error: Error? = nil) {
        struct Teardown {
            var tcp: [NowhereConnection]
            var udp: [NowhereUDPConnection]
            var idleCloseTask: Task<Void, Never>?
            var reassemblyExpiryTask: Task<Void, Never>?
        }
        let teardown: Teardown? = lock.withLock { session in
            guard !session.closed else { return nil }
            session.closed = true
            session.state = .closed
            let snapshot = Teardown(
                tcp: Array(session.tcpStreams.values),
                udp: session.udpRoutes.values.map(\.connection),
                idleCloseTask: session.idleCloseTask,
                reassemblyExpiryTask: session.reassemblyExpiryTask
            )
            session.idleCloseTask = nil
            session.reassemblyExpiryTask = nil
            session.tcpStreams.removeAll()
            session.udpRoutes.removeAll()
            session.reassembly.removeAll()
            session.udpControlStreams.removeAll()
            return snapshot
        }
        guard let teardown else { return }

        teardown.idleCloseTask?.cancel()
        teardown.reassemblyExpiryTask?.cancel()
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

        if handleClean {
            for connection in teardown.tcp { connection.handleSessionClose() }
            for connection in teardown.udp { connection.handleSessionClose() }
        } else {
            let failure = error ?? AnywhereError.proxy(.nowhere, .streamClosed)
            for connection in teardown.tcp { connection.handleSessionError(failure) }
            for connection in teardown.udp { connection.handleSessionError(failure) }
        }
        quic.close()
        onClose?()
    }
}
