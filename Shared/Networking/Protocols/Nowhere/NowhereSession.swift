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

    private enum Phase: PhaseTransitionable {
        case idle, connecting, transportReady, authenticating, ready, closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .transportReady),
                 (.transportReady, .authenticating),
                 (.authenticating, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private enum UDPRoutePhase: PhaseTransitionable {
        case registering, active

        static func canTransition(from old: UDPRoutePhase, to new: UDPRoutePhase) -> Bool {
            switch (old, new) {
            case (.registering, .active):
                return true
            default:
                return false
            }
        }
    }

    private struct UDPRoute: PhaseHolding {
        let connection: NowhereUDPConnection
        var phase: UDPRoutePhase = .registering
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

    private struct StreamOpenWaiter {
        let id: UInt64
        let registerUnderLock: @Sendable (inout State, Int64) -> Void
        let continuation: CheckedContinuation<Int64, Error>
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var authFrame: Data?
        var firstStreamID: Int64?
        var bootstrapSubmitted = false

        var streamOpenWaiters: [StreamOpenWaiter] = []
        var streamOpenWaiterSeq: UInt64 = 0

        var cancelledStreamOpenWaiters: Set<UInt64> = []

        var tcpStreams: [Int64: NowhereConnection] = [:]
        var tcpDeliveredBytes: [Int64: Int] = [:]
        var udpRoutes: [UInt32: UDPRoute] = [:]
        var udpControlStreams: [Int64: NowhereUDPConnection] = [:]
        var reassembly: [ReassemblyKey: ReassemblySlot] = [:]
        var reassemblyExpiryTask: Task<Void, Never>?
        var udpBudgetUsed = 0

        var idleSince: ContinuousClock.Instant?
        var idleSweepTask: Task<Void, Never>?

        var onClose: (@Sendable () -> Void)?
    }
    private let state = Mutex(State())

    static let maxUDPFlows = 256
    private static let maxReassemblySlots = 64
    private static let udpBudgetLimit = 4 * 1024 * 1024
    private static let reassemblyTTL: Duration = .seconds(10)
    private static let idleCloseDelay: TimeInterval = 60

    private let transportSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let transportTask: Task<Void, Error>
    private let authSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let authTask: Task<Void, Error>

    var isClosed: Bool { state.withLock { $0.phase == .closed } }
    var hasActiveConnections: Bool {
        state.withLock { !$0.tcpStreams.isEmpty || !$0.udpRoutes.isEmpty }
    }

    func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        let fireNow: Bool = state.withLock { session in
            guard session.phase != .closed else { return true }
            session.onClose = hook
            return false
        }
        if fireNow { hook() }
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
        let begin: Bool = state.withLock { $0.transition(to: .connecting) }
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
            handlers.streamTermination = { [weak self] sid, error, cause in
                self?.handleStreamTermination(sid: sid, error: error, cause: cause)
            }
            handlers.bidiCredit = { [weak self] _ in
                guard let self else { return }
                self.finishAuthenticationIfReady()
                self.drainStreamOpenWaiters()
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
                let proceed: Bool = state.withLock { session in
                    guard session.transition(to: .transportReady) else { return false }
                    session.authFrame = authFrame
                    return true
                }
                if proceed { transportSignal.finish() }
            } catch {
                failSession(error)
            }
        }
    }

    private func finishAuthenticationIfReady() {
        let proceed: Bool = state.withLock { session in
            guard session.phase == .authenticating,
                  session.bootstrapSubmitted,
                  quic.availableBidiStreams > 0 else { return false }
            return session.transition(to: .ready)
        }
        guard proceed else { return }
        authSignal.finish()
        updateIdleCloseTimer()
    }

    // MARK: - Stream dispatch (delivered synchronously on the ngtcp2 queue)

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        enum Route { case tcp(NowhereConnection); case udpControl(NowhereUDPConnection); case serverReject; case orphanData; case ignore }
        let route: Route = state.withLock { session in
            if let connection = session.tcpStreams[sid] {
                if !data.isEmpty { session.tcpDeliveredBytes[sid, default: 0] += data.count }
                return .tcp(connection)
            }
            if let connection = session.udpControlStreams[sid] { return .udpControl(connection) }
            if data.isEmpty { return .ignore }
            if (sid & 0x01) == 0x01 { return .serverReject }
            return .orphanData
        }
        switch route {
        case .tcp(let connection):
            connection.feedStreamData(data, fin: fin)
        case .udpControl(let connection):
            connection.handleControlStreamData(data, fin: fin)
        case .serverReject:
            quic.extendStreamOffset(sid, count: data.count)
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
        case .orphanData:
            quic.extendStreamOffset(sid, count: data.count)
        case .ignore:
            break
        }
    }

    private func handleStreamTermination(
        sid: Int64,
        error: Error?,
        cause: QUICConnection.StreamTerminationCause
    ) {
        enum Effect { case none; case failAuth(Error); case tcp(NowhereConnection); case udpControl(NowhereUDPConnection) }
        let effect: Effect = state.withLock { session in
            if session.firstStreamID == sid, session.phase == .authenticating {
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
            updateIdleCloseTimer()
            connection.handleStreamTermination(error: error, cause: cause)
        case .udpControl(let connection):
            connection.handleControlStreamTermination(error: error)
        }
    }

    // MARK: - Datagram dispatch (UDP)

    private func handleDatagram(_ data: Data) {
        guard let envelope = NowhereProtocol.decodeUDPEnvelope(data),
              let message = NowhereProtocol.decodeUDPDatagram(data) else { return }

        enum Deliver { case datagram(NowhereQueuedDatagram); case flowClose; case none }
        let (connection, deliver): (NowhereUDPConnection?, Deliver) = state.withLock { session in
            guard let route = session.udpRoutes[envelope.flowID], route.phase == .active else { return (nil, .none) }
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
    /// releases them. Must be called with `state` held.
    private func reserveUDPBudget(_ payloadLength: Int, _ session: inout State) -> NowhereUDPBudgetReservation? {
        let units = max(payloadLength, 1)
        guard units <= Self.udpBudgetLimit - session.udpBudgetUsed else { return nil }
        session.udpBudgetUsed += units
        return NowhereUDPBudgetReservation(units: units) { [weak self] released in
            self?.releaseUDPBudget(released)
        }
    }

    /// Fired from a reservation's deinit — possibly while a holder of `state` is dropping the slot
    /// that owns it — so it defers the mutation onto a fresh task to avoid re-entering `state`.
    private func releaseUDPBudget(_ units: Int) {
        Task { [weak self] in
            self?.state.withLock { $0.udpBudgetUsed = max(0, $0.udpBudgetUsed - units) }
        }
    }

    /// Must be called with `state` held.
    private func acceptFragment(_ message: NowhereProtocol.UDPMessage, _ session: inout State) -> NowhereQueuedDatagram? {
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

    /// Must be called with `state` held.
    private func removeReassembly(flowID: UInt32, _ session: inout State) {
        session.reassembly = session.reassembly.filter { $0.key.flowID != flowID }
        scheduleReassemblyExpiry(&session)
    }

    /// Must be called with `state` held.
    private func expireReassembly(now: ContinuousClock.Instant, _ session: inout State) {
        session.reassembly = session.reassembly.filter {
            $0.value.createdAt.duration(to: now) <= Self.reassemblyTTL
        }
    }

    /// Must be called with `state` held.
    private func scheduleReassemblyExpiry(_ session: inout State) {
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
        state.withLock { session in
            expireReassembly(now: .now, &session)
            scheduleReassemblyExpiry(&session)
        }
    }

    // MARK: - Stream open

    private func openStream(
        request: Data,
        fin: Bool,
        earlyDataAttempt: NowhereFlowOpenAttempt? = nil,
        registerUnderLock: @escaping @Sendable (inout State, Int64) -> Void,
        afterRegister: @escaping @Sendable (Int64) -> Void = { _ in }
    ) async throws -> Int64 {
        try await ensureReady()

        // Bootstrap branch: the first business stream carries AUTH + this FLOW request.
        enum Bootstrap { case notBootstrap; case failed; case ok(sid: Int64, authFrame: Data) }
        let bootstrap: Bootstrap = await quic.run { () -> Bootstrap in
            guard self.state.withLock({ $0.phase == .transportReady }) else { return .notBootstrap }
            guard let sid = self.quic.openBidiStream() else { return .failed }
            let authFrame: Data? = self.state.withLock { session in
                guard session.phase == .transportReady,
                      let frame = session.authFrame,
                      session.transition(to: .authenticating) else { return nil }
                session.firstStreamID = sid
                registerUnderLock(&session, sid)
                return frame
            }
            guard let authFrame else {
                self.quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
                return .notBootstrap
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
                state.withLock { $0.bootstrapSubmitted = true }
                await quic.run { self.finishAuthenticationIfReady() }
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
        guard state.withLock({ $0.phase == .ready }) else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        // Honor cancellation before spending a stream ID (the write below also surfaces it).
        try Task.checkCancellation()

        let sid = try await openBidiStreamWhenCreditAvailable(registerUnderLock: registerUnderLock)
        afterRegister(sid)
        do {
            earlyDataAttempt?.markEarlyDataWriteStarted()
            try await quic.writeStream(sid, data: request, fin: fin)
            return sid
        } catch {
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
            releaseTCPStream(sid, credited: 0)
            throw error
        }
    }

    private func openBidiStreamWhenCreditAvailable(
        registerUnderLock: @escaping @Sendable (inout State, Int64) -> Void
    ) async throws -> Int64 {
        let waiterID: UInt64 = state.withLock { session in
            defer { session.streamOpenWaiterSeq &+= 1 }
            return session.streamOpenWaiterSeq
        }
        defer { state.withLock { _ = $0.cancelledStreamOpenWaiters.remove(waiterID) } }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                quic.enqueue {
                    self.openOrParkOnQueue(
                        waiterID: waiterID,
                        registerUnderLock: registerUnderLock,
                        continuation: continuation
                    )
                }
            }
        } onCancel: {
            self.cancelStreamOpenWaiter(waiterID)
        }
    }

    private func openOrParkOnQueue(
        waiterID: UInt64,
        registerUnderLock: @escaping @Sendable (inout State, Int64) -> Void,
        continuation: CheckedContinuation<Int64, Error>
    ) {
        enum Outcome { case opened(Int64); case failed(Error); case parked }
        let outcome: Outcome = state.withLock { session in
            if session.cancelledStreamOpenWaiters.remove(waiterID) != nil {
                return .failed(CancellationError())
            }
            guard session.phase == .ready else {
                return .failed(AnywhereError.proxy(.nowhere, .streamClosed))
            }
            if session.streamOpenWaiters.isEmpty, let sid = quic.openBidiStream() {
                registerUnderLock(&session, sid)
                return .opened(sid)
            }
            session.streamOpenWaiters.append(StreamOpenWaiter(
                id: waiterID,
                registerUnderLock: registerUnderLock,
                continuation: continuation
            ))
            return .parked
        }
        switch outcome {
        case .opened(let sid): continuation.resume(returning: sid)
        case .failed(let error): continuation.resume(throwing: error)
        case .parked: break
        }
    }

    private func drainStreamOpenWaiters() {
        let drained: [(CheckedContinuation<Int64, Error>, Int64)] = state.withLock { session in
            guard session.phase == .ready else { return [] }
            var resumed: [(CheckedContinuation<Int64, Error>, Int64)] = []
            while !session.streamOpenWaiters.isEmpty {
                guard let sid = quic.openBidiStream() else { break }
                let waiter = session.streamOpenWaiters.removeFirst()
                waiter.registerUnderLock(&session, sid)
                resumed.append((waiter.continuation, sid))
            }
            return resumed
        }
        for (continuation, sid) in drained { continuation.resume(returning: sid) }
    }

    private func cancelStreamOpenWaiter(_ waiterID: UInt64) {
        let continuation: CheckedContinuation<Int64, Error>? = state.withLock { session in
            if let index = session.streamOpenWaiters.firstIndex(where: { $0.id == waiterID }) {
                return session.streamOpenWaiters.remove(at: index).continuation
            }
            session.cancelledStreamOpenWaiters.insert(waiterID)
            return nil
        }
        continuation?.resume(throwing: CancellationError())
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
                self?.updateIdleCloseTimer()
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

    func releaseTCPStream(_ sid: Int64, credited: Int) {
        let (routeRemoved, delivered): (Bool, Int) = state.withLock { session in
            (session.tcpStreams.removeValue(forKey: sid) != nil,
             session.tcpDeliveredBytes.removeValue(forKey: sid) ?? 0)
        }
        let residual = delivered - credited
        if residual > 0 {
            quic.extendStreamOffset(sid, count: residual)
        }
        guard routeRemoved else { return }
        updateIdleCloseTimer()
    }

    func releaseUDPControlStream(_ sid: Int64) {
        state.withLock { _ = $0.udpControlStreams.removeValue(forKey: sid) }
    }

    // MARK: - UDP session API

    func registerUDPSession(
        _ connection: NowhereUDPConnection,
        requestedFlowID: UInt32? = nil
    ) async throws -> UInt32 {
        let flowID: UInt32 = try state.withLock { session in
            guard session.phase != .closed, session.phase != .idle else { throw AnywhereError.proxy(.nowhere, .notReady) }
            guard session.udpRoutes.count < Self.maxUDPFlows else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "UDP flow pool exhausted"))
            }
            guard let flowID = requestedFlowID, flowID != 0, session.udpRoutes[flowID] == nil else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "UDP flow ID collision"))
            }
            session.udpRoutes[flowID] = UDPRoute(connection: connection)
            return flowID
        }
        updateIdleCloseTimer()
        return flowID
    }

    func activateUDPSession(_ flowID: UInt32) {
        state.withLock { session in
            _ = session.udpRoutes[flowID]?.transition(to: .active)
        }
    }

    func releaseUDPSession(_ flowID: UInt32) {
        let removed = state.withLock { session -> Bool in
            guard session.udpRoutes.removeValue(forKey: flowID) != nil else { return false }
            removeReassembly(flowID: flowID, &session)
            return true
        }
        if removed {
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

    private func updateIdleCloseTimer() {
        state.withLock { session in
            guard session.phase == .ready else {
                session.idleSince = nil
                return
            }
            let idle = session.tcpStreams.isEmpty && session.udpRoutes.isEmpty
            session.idleSince = idle ? ContinuousClock.now : nil
            if session.idleSweepTask == nil {
                session.idleSweepTask = Task { [weak self] in await self?.runIdleSweep() }
            }
        }
    }

    private func runIdleSweep() async {
        enum Step { case closeNow; case sleep(Duration); case stop }
        while !Task.isCancelled {
            let step: Step = state.withLock { session in
                guard session.phase == .ready else { return .stop }
                guard let since = session.idleSince else { return .sleep(.seconds(Self.idleCloseDelay)) }
                let elapsed = since.duration(to: ContinuousClock.now)
                if elapsed >= .seconds(Self.idleCloseDelay) { return .closeNow }
                return .sleep(.seconds(Self.idleCloseDelay) - elapsed)
            }
            switch step {
            case .stop:
                return
            case .sleep(let duration):
                try? await Task.sleep(for: duration)
            case .closeNow:
                closeIfStillIdle()
                let done = state.withLock { session -> Bool in
                    if session.phase == .closed { return true }
                    session.idleSince = nil
                    return false
                }
                if done { return }
            }
        }
    }

    private func closeIfStillIdle() {
        performTeardown(
            readyError: AnywhereError.proxy(.nowhere, .streamClosed),
            handleClean: true,
            onlyIfIdle: true
        )
    }

    // MARK: - Close

    func close() {
        performTeardown(readyError: AnywhereError.proxy(.nowhere, .streamClosed), handleClean: true)
    }

    private func failSession(_ error: Error) {
        performTeardown(readyError: error, handleClean: false, error: error)
    }

    private func performTeardown(readyError: Error, handleClean: Bool, error: Error? = nil, onlyIfIdle: Bool = false) {
        struct Teardown {
            var tcp: [NowhereConnection]
            var udp: [NowhereUDPConnection]
            var openWaiters: [StreamOpenWaiter]
            var idleSweepTask: Task<Void, Never>?
            var reassemblyExpiryTask: Task<Void, Never>?
            var onClose: (@Sendable () -> Void)?
        }
        let teardown: Teardown? = state.withLock { session in
            if onlyIfIdle {
                guard session.phase == .ready, session.tcpStreams.isEmpty, session.udpRoutes.isEmpty else {
                    return nil
                }
            }
            guard session.transition(to: .closed) else { return nil }
            let snapshot = Teardown(
                tcp: Array(session.tcpStreams.values),
                udp: session.udpRoutes.values.map(\.connection),
                openWaiters: session.streamOpenWaiters,
                idleSweepTask: session.idleSweepTask,
                reassemblyExpiryTask: session.reassemblyExpiryTask,
                onClose: session.onClose
            )
            session.idleSweepTask = nil
            session.idleSince = nil
            session.reassemblyExpiryTask = nil
            session.tcpStreams.removeAll()
            session.tcpDeliveredBytes.removeAll()
            session.udpRoutes.removeAll()
            session.reassembly.removeAll()
            session.udpControlStreams.removeAll()
            session.streamOpenWaiters.removeAll()
            session.onClose = nil
            return snapshot
        }
        guard let teardown else { return }

        teardown.idleSweepTask?.cancel()
        teardown.reassemblyExpiryTask?.cancel()
        quic.handlers.withLock { $0.bidiCredit = nil }

        transportSignal.finish(throwing: readyError)
        authSignal.finish(throwing: readyError)
        for waiter in teardown.openWaiters {
            waiter.continuation.resume(throwing: readyError)
        }

        if handleClean {
            for connection in teardown.tcp { connection.handleSessionClose() }
            for connection in teardown.udp { connection.handleSessionClose() }
        } else {
            let failure = error ?? AnywhereError.proxy(.nowhere, .streamClosed)
            for connection in teardown.tcp { connection.handleSessionError(failure) }
            for connection in teardown.udp { connection.handleSessionError(failure) }
        }
        quic.close()
        teardown.onClose?()
    }
}
