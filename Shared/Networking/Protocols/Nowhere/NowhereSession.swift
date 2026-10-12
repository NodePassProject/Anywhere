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
        case idle, connecting, authenticating, ready, closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .authenticating),
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
    private let configuration: NowhereRuntimeConfiguration

    private struct StreamOpenWaiter {
        let id: UInt64
        let registerUnderLock: @Sendable (inout State, Int64) throws -> Void
        let continuation: CheckedContinuation<Int64, Error>
    }

    private struct State: PhaseHolding {
        var phase: Phase = .idle
        var draining = false
        var drainDeadline: DeadlineToken?
        var authenticationDeadline: DeadlineToken?

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
        var reassemblyExpiry: DeadlineToken?
        var reassemblyExpiryAt: ContinuousClock.Instant?

        var idleClose: DeadlineToken?
        var idleGeneration: UInt64 = 0

        var onClose: (@Sendable () -> Void)?
    }
    private let state = Mutex(State())
    private let udpBudgetUsed = Atomic<Int>(0)

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
    var isDraining: Bool { state.withLock { $0.draining } }

    func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        let fireNow: Bool = state.withLock { session in
            guard session.phase != .closed else { return true }
            session.onClose = hook
            return false
        }
        if fireNow { hook() }
    }

    init(configuration: NowhereRuntimeConfiguration, transport: QUICDatagramTransport? = nil) throws {
        self.configuration = configuration
        let morphObfuscator: NowhereMorphPacketObfuscator?
        if configuration.morph {
            guard let keys = configuration.morphKeys else {
                throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Missing Morph keys"))
            }
            morphObfuscator = try NowhereMorphPacketObfuscator(
                sendKey: keys.udpClientToServer,
                receiveKey: keys.udpServerToClient
            )
        } else {
            morphObfuscator = nil
        }
        let quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.proxyHost,
            alpn: [NowhereProtocol.applicationProtocol],
            datagramsEnabled: true,
            tuning: .nowhere,
            obfuscator: morphObfuscator,
            directMaxUDPPayload: configuration.morph ? 1440 : QUICConnection.maxUDPPayload,
            transport: transport
        )
        self.quic = quic
        morphObfuscator?.setFailureHandler { [weak quic] error in
            quic?.close(error: error)
        }
        let (transportStream, transportSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.transportSignal = transportSignal
        self.transportTask = Task { for try await _ in transportStream {} }
        let (authStream, authSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.authSignal = authSignal
        self.authTask = Task { for try await _ in authStream {} }
    }

    func ensureReady() async throws {
        let begin: Bool = state.withLock { session in
            guard session.transition(to: .connecting) else { return false }
            session.authenticationDeadline = TickScheduler.shared.schedule(in: .seconds(30), precision: .relaxed) { [weak self] in
                self?.performTeardown(
                    readyError: AnywhereError.proxy(.nowhere, .openTimeout),
                    handleClean: false,
                    onlyWhileOpening: true
                )
            }
            return true
        }
        if begin { startConnection() }
        try await nowhereCancellableValue(of: transportTask)
    }

    private func startConnection() {
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
            handlers.streamSendingStopped = { [weak self] sid, error in
                self?.handleStreamTermination(sid: sid, error: error, cause: .reset)
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

        Task { [self] in
            do {
                try await quic.connect()
                let exporter = try await quic.exportKeyingMaterial(
                    label: NowhereProtocol.authExporterLabel,
                    context: Data(),
                    length: 32
                )
                let authFrame = try NowhereProtocol.makeAuthFrame(
                    authKey: configuration.authKey,
                    transport: .quic,
                    exporter: exporter
                )
                let sid: Int64 = try state.withLock { session in
                    guard session.transition(to: .authenticating),
                          let sid = quic.openBidiStream(), sid == 0 else {
                        throw AnywhereError.proxy(.nowhere, .streamClosed)
                    }
                    session.firstStreamID = sid
                    return sid
                }
                try await quic.writeStream(sid, data: authFrame, fin: true)
                let submitted = state.withLock { session in
                    guard session.phase == .authenticating else { return false }
                    session.bootstrapSubmitted = true
                    return true
                }
                guard submitted else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
                transportSignal.finish()
                finishAuthenticationIfReady()
            } catch {
                failSession(error)
            }
        }
    }

    private func finishAuthenticationIfReady() {
        let result: (ready: Bool, deadline: DeadlineToken?) = state.withLock { session in
            guard session.phase == .authenticating,
                  session.bootstrapSubmitted,
                  quic.availableBidiStreams > 0 else { return (false, nil) }
            guard session.transition(to: .ready) else { return (false, nil) }
            let deadline = session.authenticationDeadline
            session.authenticationDeadline = nil
            return (true, deadline)
        }
        guard result.ready else { return }
        result.deadline?.cancel()
        authSignal.finish()
        updateIdleCloseTimer()
    }

    // MARK: - Stream dispatch

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        enum Route { case tcp(NowhereConnection); case udpControl(NowhereUDPConnection); case violation; case orphanData; case ignore }
        let route: Route = state.withLock { session in
            if let connection = session.tcpStreams[sid] {
                if !data.isEmpty { session.tcpDeliveredBytes[sid, default: 0] += data.count }
                return .tcp(connection)
            }
            if let connection = session.udpControlStreams[sid] { return .udpControl(connection) }
            if sid == session.firstStreamID {
                return data.isEmpty ? .ignore : .violation
            }
            if sid & 3 != 0 { return .violation }
            if data.isEmpty { return .ignore }
            return .orphanData
        }
        switch route {
        case .tcp(let connection):
            connection.feedStreamData(data, fin: fin)
        case .udpControl(let connection):
            connection.handleControlStreamData(data, fin: fin)
        case .violation:
            failSession(AnywhereError.proxy(.nowhere, .protocolViolation(detail: "Unexpected authentication data or business stream direction")))
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
            if session.firstStreamID == sid {
                if let error { return .failAuth(error) }
                return .none
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
        let (connection, deliver): (NowhereUDPConnection?, Deliver) = state.withLock { session in
            guard let route = session.udpRoutes[envelope.flowID], route.phase == .active else { return (nil, .none) }
            switch message.type {
            case .data:
                guard let reservation = reserveUDPBudget(message.payload.count) else { return (nil, .none) }
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

    private func reserveUDPBudget(_ payloadLength: Int) -> NowhereUDPBudgetReservation? {
        let units = max(payloadLength, 1)
        var used = udpBudgetUsed.load(ordering: .relaxed)
        while units <= Self.udpBudgetLimit - used {
            let (exchanged, original) = udpBudgetUsed.compareExchange(
                expected: used,
                desired: used + units,
                ordering: .relaxed
            )
            if exchanged {
                return NowhereUDPBudgetReservation(units: units) { [weak self] released in
                    self?.udpBudgetUsed.subtract(released, ordering: .relaxed)
                }
            }
            used = original
        }
        return nil
    }

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

    private func removeReassembly(flowID: UInt32, _ session: inout State) {
        session.reassembly = session.reassembly.filter { $0.key.flowID != flowID }
        scheduleReassemblyExpiry(&session)
    }

    private func expireReassembly(now: ContinuousClock.Instant, _ session: inout State) {
        session.reassembly = session.reassembly.filter {
            $0.value.createdAt.duration(to: now) <= Self.reassemblyTTL
        }
    }

    private func scheduleReassemblyExpiry(_ session: inout State) {
        guard let earliest = session.reassembly.values.map(\.createdAt).min() else {
            session.reassemblyExpiry?.cancel()
            session.reassemblyExpiry = nil
            session.reassemblyExpiryAt = nil
            return
        }
        let deadline = earliest.advanced(by: Self.reassemblyTTL)
        if session.reassemblyExpiry != nil, session.reassemblyExpiryAt == deadline { return }
        session.reassemblyExpiry?.cancel()
        session.reassemblyExpiryAt = deadline
        session.reassemblyExpiry = TickScheduler.shared.schedule(
            in: ContinuousClock.now.duration(to: deadline),
            precision: .relaxed
        ) { [weak self] in self?.expireAndRescheduleReassembly() }
    }

    private func expireAndRescheduleReassembly() {
        state.withLock { session in
            session.reassemblyExpiry = nil
            session.reassemblyExpiryAt = nil
            expireReassembly(now: .now, &session)
            scheduleReassemblyExpiry(&session)
        }
    }

    // MARK: - Stream open

    private func openStream(
        request: Data,
        registerUnderLock: @escaping @Sendable (inout State, Int64) throws -> Void,
        afterRegister: @escaping @Sendable (Int64) -> Void = { _ in },
        releaseOnWriteFailure: @Sendable (Int64) -> Void
    ) async throws -> Int64 {
        try await ensureReady()

        try await nowhereCancellableValue(of: authTask)
        guard state.withLock({ $0.phase == .ready }) else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        try Task.checkCancellation()

        let sid = try await openBidiStreamWhenCreditAvailable(registerUnderLock: registerUnderLock)
        afterRegister(sid)
        do {
            try await quic.writeStream(sid, data: request)
            return sid
        } catch {
            quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
            releaseOnWriteFailure(sid)
            throw error
        }
    }

    private func openBidiStreamWhenCreditAvailable(
        registerUnderLock: @escaping @Sendable (inout State, Int64) throws -> Void
    ) async throws -> Int64 {
        let waiterID: UInt64 = state.withLock { session in
            defer { session.streamOpenWaiterSeq &+= 1 }
            return session.streamOpenWaiterSeq
        }
        defer { state.withLock { _ = $0.cancelledStreamOpenWaiters.remove(waiterID) } }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                self.openOrPark(
                    waiterID: waiterID,
                    registerUnderLock: registerUnderLock,
                    continuation: continuation
                )
            }
        } onCancel: {
            self.cancelStreamOpenWaiter(waiterID)
        }
    }

    private func openOrPark(
        waiterID: UInt64,
        registerUnderLock: @escaping @Sendable (inout State, Int64) throws -> Void,
        continuation: CheckedContinuation<Int64, Error>
    ) {
        enum Outcome { case opened(Int64); case failed(Error); case parked }
        let outcome: Outcome = state.withLock { session in
            if session.cancelledStreamOpenWaiters.remove(waiterID) != nil {
                return .failed(CancellationError())
            }
            guard session.phase == .ready, !session.draining else {
                return .failed(AnywhereError.proxy(.nowhere, .streamClosed))
            }
            if session.streamOpenWaiters.isEmpty, let sid = quic.openBidiStream() {
                do {
                    _ = try NowhereProtocol.udpFlowID(streamID: sid)
                    try registerUnderLock(&session, sid)
                    return .opened(sid)
                } catch {
                    quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
                    return .failed(error)
                }
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
        case .failed(let error):
            continuation.resume(throwing: error)
            if case AnywhereError.proxy(.nowhere, .streamIDsExhausted) = error { beginDraining() }
        case .parked: break
        }
    }

    private func drainStreamOpenWaiters() {
        let drained: [(CheckedContinuation<Int64, Error>, Result<Int64, Error>)] = state.withLock { session in
            guard session.phase == .ready, !session.draining else { return [] }
            var resumed: [(CheckedContinuation<Int64, Error>, Result<Int64, Error>)] = []
            while !session.streamOpenWaiters.isEmpty {
                guard let sid = quic.openBidiStream() else { break }
                let waiter = session.streamOpenWaiters.removeFirst()
                do {
                    _ = try NowhereProtocol.udpFlowID(streamID: sid)
                    try waiter.registerUnderLock(&session, sid)
                    resumed.append((waiter.continuation, .success(sid)))
                } catch {
                    quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
                    resumed.append((waiter.continuation, .failure(error)))
                }
            }
            return resumed
        }
        for (continuation, result) in drained {
            continuation.resume(with: result)
            if case .failure(AnywhereError.proxy(.nowhere, .streamIDsExhausted)) = result { beginDraining() }
        }
    }

    private func beginDraining() {
        let waiters: [StreamOpenWaiter] = state.withLock { session in
            guard session.phase == .ready, !session.draining else { return [] }
            session.draining = true
            session.drainDeadline = TickScheduler.shared.schedule(in: .seconds(30), precision: .relaxed) { [weak self] in
                self?.close()
            }
            let waiters = session.streamOpenWaiters
            session.streamOpenWaiters.removeAll()
            return waiters
        }
        for waiter in waiters {
            waiter.continuation.resume(throwing: AnywhereError.proxy(.nowhere, .streamIDsExhausted))
        }
        updateIdleCloseTimer()
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
        request: Data
    ) async throws -> Int64 {
        try await openStream(
            request: request,
            registerUnderLock: { session, sid in session.tcpStreams[sid] = connection },
            afterRegister: { [weak self] _ in
                self?.updateIdleCloseTimer()
            },
            releaseOnWriteFailure: { [weak self] sid in
                self?.releaseTCPStream(sid, credited: 0)
            }
        )
    }

    func openUDPControlStream(for connection: NowhereUDPConnection, request: Data) async throws -> Int64 {
        try await ensureReady()
        guard quic.maxDatagramPayloadSize >= NowhereProtocol.udpHeaderSize else {
            throw AnywhereError.proxy(.nowhere, .protocolViolation(detail: "QUIC DATAGRAM is unavailable"))
        }
        return try await openStream(
            request: request,
            registerUnderLock: { session, sid in
                guard session.udpRoutes.count < Self.maxUDPFlows else {
                    throw AnywhereError.proxy(.nowhere, .flowRejected(code: NowhereProtocol.FlowRejectCode.flowLimit.rawValue))
                }
                let flowID = try NowhereProtocol.udpFlowID(streamID: sid)
                session.udpRoutes[flowID] = UDPRoute(connection: connection)
                session.udpControlStreams[sid] = connection
            },
            afterRegister: { [weak self] _ in self?.updateIdleCloseTimer() },
            releaseOnWriteFailure: { [weak self] sid in
                self?.releaseUDPControlStream(sid)
                if let flowID = try? NowhereProtocol.udpFlowID(streamID: sid) {
                    self?.releaseUDPSession(flowID)
                }
            }
        )
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
        let stale: DeadlineToken? = state.withLock { session in
            guard session.phase == .ready else {
                let stale = session.idleClose
                session.idleClose = nil
                return stale
            }
            let idle = session.tcpStreams.isEmpty && session.udpRoutes.isEmpty
            if idle {
                guard session.idleClose == nil else { return nil }
                session.idleGeneration &+= 1
                let generation = session.idleGeneration
                session.idleClose = TickScheduler.shared.schedule(
                    in: .seconds(Self.idleCloseDelay),
                    precision: .relaxed
                ) { [weak self] in self?.idleCloseFired(generation: generation) }
                return nil
            }
            let stale = session.idleClose
            session.idleClose = nil
            return stale
        }
        stale?.cancel()
        if state.withLock({ $0.draining && $0.tcpStreams.isEmpty && $0.udpRoutes.isEmpty }) {
            closeIfStillIdle()
        }
    }

    private func idleCloseFired(generation: UInt64) {
        let current: Bool = state.withLock { session in
            guard session.idleGeneration == generation else { return false }
            session.idleClose = nil
            return true
        }
        guard current else { return }
        closeIfStillIdle()
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

    private func performTeardown(readyError: Error, handleClean: Bool, error: Error? = nil, onlyIfIdle: Bool = false, onlyWhileOpening: Bool = false) {
        struct Teardown {
            var tcp: [NowhereConnection]
            var udp: [NowhereUDPConnection]
            var openWaiters: [StreamOpenWaiter]
            var idleClose: DeadlineToken?
            var reassemblyExpiry: DeadlineToken?
            var drainDeadline: DeadlineToken?
            var authenticationDeadline: DeadlineToken?
            var onClose: (@Sendable () -> Void)?
        }
        let teardown: Teardown? = state.withLock { session in
            if onlyWhileOpening {
                guard session.phase == .connecting || session.phase == .authenticating else { return nil }
            }
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
                idleClose: session.idleClose,
                reassemblyExpiry: session.reassemblyExpiry,
                drainDeadline: session.drainDeadline,
                authenticationDeadline: session.authenticationDeadline,
                onClose: session.onClose
            )
            session.idleClose = nil
            session.drainDeadline = nil
            session.authenticationDeadline = nil
            session.reassemblyExpiry = nil
            session.reassemblyExpiryAt = nil
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

        teardown.idleClose?.cancel()
        teardown.reassemblyExpiry?.cancel()
        teardown.drainDeadline?.cancel()
        teardown.authenticationDeadline?.cancel()
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
