//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

// MARK: Various code quality violation issues in this file (handler patterns), consider refactor

import Foundation
import Synchronization

nonisolated enum NowhereTCPRelayMode {
    case tcp
    case udp
}

protocol NowhereTerminationObservable: AnyObject {
    nonisolated func setNowhereTerminationHandler(_ handler: (@Sendable (Error?) -> Void)?)
}

actor NowhereConnection {
    private let session: NowhereSession
    private let destination: NowhereProtocol.Target
    private let flowHeader: NowhereProtocol.FlowHeader
    private let initialData: Data?
    private weak var attempt: NowhereFlowOpenAttempt?

    private enum Phase: PhaseTransitionable {
        case idle
        case opening
        case open(sid: Int64, ready: Bool, credited: Int)
        case closed

        var isClosed: Bool {
            if case .closed = self { true } else { false }
        }

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .opening),
                 (.opening, .open):
                return true
            case (.open(_, let wasReady, _), .open(_, let isReady, _)):
                return isReady || !wasReady
            case (_, .closed):
                return !old.isClosed
            default:
                return false
            }
        }
    }
    private nonisolated let phase = Mutex<Phase>(.idle)

    private let rawInbox = AsyncInbox<Data>()
    private var pendingData = Data()

    private var uncreditedBytes = 0
    private static let creditFlushThreshold = 256 << 10

    private var backlogChunks: [Data] = []
    private static let maxChunkBytes = 512 << 10

    init(
        session: NowhereSession,
        destination: NowhereProtocol.Target,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data?,
        attempt: NowhereFlowOpenAttempt?
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        self.initialData = initialData
        self.attempt = attempt
    }

    nonisolated var isConnected: Bool {
        phase.withLock { if case .open(_, true, _) = $0 { true } else { false } }
    }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }

    private nonisolated func closeLifecycle() -> (sid: Int64, credited: Int)? {
        phase.withLock { state in
            let released: (sid: Int64, credited: Int)?
            switch state {
            case .closed: return nil
            case .open(let sid, _, let credited): released = (sid, credited)
            case .idle, .opening: released = nil
            }
            Phase.transition(&state, to: .closed)
            return released
        }
    }

    private nonisolated func becomeReady() -> Bool {
        phase.withLock { state -> Bool in
            guard case .open(let sid, false, let credited) = state else { return false }
            return Phase.transition(&state, to: .open(sid: sid, ready: true, credited: credited))
        }
    }

    // MARK: - Open

    func open() async throws {
        let begin = phase.withLock { Phase.transition(&$0, to: .opening) }
        guard begin else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
        do {
            try await performOpen()
        } catch {
            if let released = closeLifecycle() {
                session.shutdownStream(released.sid)
                session.releaseTCPStream(released.sid, credited: released.credited)
            }
            throw error
        }
    }

    private func performOpen() async throws {
        let frame = try NowhereProtocol.encodeFlowRequest(
            header: flowHeader,
            target: flowHeader.carriesTarget ? destination : nil,
            initialData: flowHeader.role == .attach ? nil : initialData
        )
        let sid = try await session.openTCPStream(
            for: self,
            request: frame,
            earlyDataAttempt: initialData?.isEmpty == false ? attempt : nil
        )
        let adopted = phase.withLock { Phase.transition(&$0, to: .open(sid: sid, ready: false, credited: 0)) }
        guard adopted else {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid, credited: 0)
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }

        if flowHeader.role == .open {
            pendingData = Data()
            guard becomeReady() else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
            return
        }

        var buffer = Data()
        while true {
            guard let chunk = try await nextChunk() else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Stream closed before complete READY"))
            }
            buffer.append(chunk)
            guard buffer.count >= NowhereProtocol.flowResultSize else { continue }
            guard let result = NowhereProtocol.decodeFlowResult(buffer) else {
                throw AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid flow result"))
            }
            recordCredit(count: NowhereProtocol.flowResultSize)
            switch result {
            case .ready:
                pendingData = Data(buffer.dropFirst(NowhereProtocol.flowResultSize))
                guard becomeReady() else { throw AnywhereError.proxy(.nowhere, .streamClosed) }
                return
            case .reject(let code):
                throw AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
            }
        }
    }

    // MARK: - Demux feed

    nonisolated func feedStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty { rawInbox.yield(Data(data)) }
        if fin { rawInbox.finish() }
    }

    nonisolated func handleStreamTermination(error: Error?, cause: QUICConnection.StreamTerminationCause) {
        if let error { rawInbox.finish(throwing: error) } else { rawInbox.finish() }
        guard cause == .closed || error != nil else { return }
        if let released = closeLifecycle() {
            session.shutdownStream(released.sid)
            session.releaseTCPStream(released.sid, credited: released.credited)
        }
    }

    nonisolated func handleSessionClose() {
        rawInbox.finish()
        _ = closeLifecycle()
    }

    nonisolated func handleSessionError(_ error: Error) {
        if case AnywhereError.quic(.closed(graceful: true)) = error {
            rawInbox.finish()
        } else {
            rawInbox.finish(throwing: error)
        }
        _ = closeLifecycle()
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        let sid: Int64? = phase.withLock { if case .open(let s, true, _) = $0 { s } else { nil } }
        guard let sid else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        try await session.writeStream(sid, data: data)
    }

    func receiveRaw() async throws -> Data? {
        if !pendingData.isEmpty {
            let out = pendingData
            pendingData = Data()
            credit(out.count)
            return out
        }
        guard let chunk = try await nextChunk() else {
            flushCredit()
            return nil
        }
        if !chunk.isEmpty {
            credit(chunk.count)
        }
        return chunk
    }

    private func nextChunk() async throws -> Data? {
        if !backlogChunks.isEmpty { return takeBacklog() }
        guard let batch = try await rawInbox.nextBatch() else { return nil }
        if batch.count == 1 { return batch[0] }
        backlogChunks = batch
        return takeBacklog()
    }

    private func takeBacklog() -> Data {
        var joined = Data(capacity: min(backlogChunks.reduce(0) { $0 + $1.count }, Self.maxChunkBytes))
        var index = 0
        while index < backlogChunks.count, joined.count < Self.maxChunkBytes {
            joined.append(backlogChunks[index])
            index += 1
        }
        backlogChunks.removeFirst(index)
        return joined
    }

    private func credit(_ count: Int) {
        uncreditedBytes += count
        guard uncreditedBytes >= Self.creditFlushThreshold else { return }
        flushCredit()
    }

    private func flushCredit() {
        guard uncreditedBytes > 0 else { return }
        let count = uncreditedBytes
        uncreditedBytes = 0
        recordCredit(count: count)
    }

    private nonisolated func recordCredit(count: Int) {
        guard count > 0 else { return }
        let sid: Int64? = phase.withLock { state -> Int64? in
            guard case .open(let s, let ready, let credited) = state else { return nil }
            Phase.transition(&state, to: .open(sid: s, ready: ready, credited: credited + count))
            return s
        }
        guard let sid else { return }
        session.extendStreamOffset(sid, count: count)
    }

    nonisolated func cancel() {
        rawInbox.finish()
        if let released = closeLifecycle() {
            session.shutdownStream(released.sid)
            session.releaseTCPStream(released.sid, credited: released.credited)
        }
    }
}

nonisolated final class NowhereTCPUDPConnection: ProxyConnection, NowhereTerminationObservable {
    private let inner: NowhereTCPConnection
    private let udpState = Mutex(UDPFramingState())
    private let termination = TerminationLatch()

    init(inner: NowhereTCPConnection) {
        self.inner = inner
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    func setNowhereTerminationHandler(_ handler: (@Sendable (Error?) -> Void)?) {
        let live = termination.install(handler)
        if handler == nil {
            inner.setNowhereTerminationHandler(nil)
        } else if live {
            inner.setNowhereTerminationHandler { [weak self] error in
                self?.termination.fire(error)
            }
        }
    }

    func sendRaw(_ data: Data) async throws {
        let frame: Data
        do {
            frame = try NowhereProtocol.encodeUDPStreamPacket(data)
        } catch AnywhereError.proxy(.nowhere, .packetTooLarge) {
            return
        }
        try await inner.sendRaw(frame)
    }

    private enum PacketStep {
        case deliver(Data)
        case fail(Error)
        case needMore
    }

    private func nextPacketStep(_ state: inout UDPFramingState) -> PacketStep {
        let available = state.buffer.count - state.bufferOffset
        guard available >= 2 else { return .needMore }
        guard let (payload, consumed) = NowhereProtocol.decodeUDPStreamPacket(
            state.buffer,
            offset: state.bufferOffset
        ) else {
            return .needMore
        }
        state.bufferOffset += consumed
        if state.bufferOffset > 8192 {
            state.buffer.removeSubrange(0..<state.bufferOffset)
            state.bufferOffset = 0
        }
        return .deliver(payload)
    }

    func receiveRaw() async throws -> Data? {
        while true {
            let step = udpState.withLock { nextPacketStep(&$0) }
            switch step {
            case .deliver(let packet):
                return packet
            case .fail(let error):
                termination.fire(error)
                throw error
            case .needMore:
                let data: Data?
                do {
                    data = try await inner.receive()
                } catch {
                    termination.fire(error)
                    throw error
                }
                guard let data, !data.isEmpty else {
                    let truncated = udpState.withLock {
                        $0.buffer.count - $0.bufferOffset != 0
                    }
                    if truncated {
                        let error = AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Truncated UoT packet"))
                        termination.fire(error)
                        throw error
                    }
                    termination.fire(nil)
                    return nil
                }
                udpState.withLock { $0.buffer.append(data) }
            }
        }
    }

    func cancel() {
        termination.fire(AnywhereError.proxy(.nowhere, .streamClosed))
        udpState.withLock {
            $0.buffer = Data()
            $0.bufferOffset = 0
        }
        inner.cancel()
    }
}

nonisolated final class NowhereTCPConnection: ProxyConnection, NowhereTerminationObservable {

    private enum Phase: PhaseTransitionable {
        case idle, connecting, authenticating, prepared, requesting, waitingResult, ready, closed

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .connecting),
                 (.connecting, .authenticating),
                 (.authenticating, .prepared),
                 (.authenticating, .waitingResult),
                 (.authenticating, .ready),
                 (.prepared, .requesting),
                 (.requesting, .waitingResult),
                 (.requesting, .ready),
                 (.waitingResult, .ready):
                return true
            case (_, .closed):
                return old != .closed
            default:
                return false
            }
        }
    }

    private let configuration: NowhereConfiguration
    private let connectHost: String
    private let tunnel: ProxyConnection?

    private struct State {
        private(set) var phase: Phase = .idle

        private(set) var didBecomeReady = false

        @discardableResult
        mutating func transition(to new: Phase) -> Bool {
            guard Phase.transition(&phase, to: new) else { return false }
            if new == .ready { didBecomeReady = true }
            return true
        }

        var tlsClient: TLSClient?
        var inner: TLSProxyConnection?
        var openSignal: AsyncThrowingStream<Never, Error>.Continuation?
        var receiveBuffer = Data()
        var pendingReceive: AsyncThrowingStream<Data, Error>.Continuation?
        var terminalError: Error?
        var preparedCloseHandler: (@Sendable () -> Void)?
        var transportReadInFlight = false
        var transportReadTask: Task<Void, Never>?
        var transportReadClosed = false
        var flowResultKind: NowhereProtocol.FlowKind?
        var flowRole: NowhereProtocol.FlowRole?
    }
    private let state = Mutex(State())

    private let termination = TerminationLatch()

    init(
        configuration: NowhereConfiguration,
        connectHost: String,
        tunnel: ProxyConnection?
    ) {
        self.configuration = configuration
        self.connectHost = connectHost
        self.tunnel = tunnel
    }

    var isConnected: Bool {
        state.withLock { $0.phase == .ready && $0.inner?.isConnected == true }
    }

    var outerTLSVersion: TLSVersion? {
        state.withLock { $0.inner?.outerTLSVersion }
    }

    var isPrepared: Bool {
        state.withLock { $0.phase == .prepared && $0.inner?.isConnected == true }
    }

    func setNowhereTerminationHandler(_ handler: (@Sendable (Error?) -> Void)?) {
        guard termination.install(handler) else { return }
        guard handler != nil,
              let connection = state.withLock({ $0.phase == .ready ? $0.inner : nil }) else { return }
        armTransportRead(on: connection)
    }

    private var hasTerminationHandler: Bool {
        termination.hasHandler
    }

    private func shouldProbeUOTUplink(_ state: State) -> Bool {
        state.flowResultKind == .udp && state.flowRole == .open && hasTerminationHandler
    }

    func setPreparedCloseHandler(_ handler: (@Sendable () -> Void)?) {
        state.withLock { $0.preparedCloseHandler = handler }
    }

    func prepare() async throws {
        try await connectAndSend(
            payload: Data(),
            successState: .prepared,
            expectsFlowResult: false,
            flowKind: nil,
            flowRole: nil
        )
    }

    func openFresh(
        destination: NowhereProtocol.Target,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data? = nil,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws {
        let bootstrap = try requestPayload(
            destination: destination,
            flowHeader: flowHeader,
            initialData: initialData
        )

        try await connectAndSend(
            payload: bootstrap,
            successState: .ready,
            expectsFlowResult: flowHeader.role != .open,
            flowKind: flowHeader.kind,
            flowRole: flowHeader.role,
            earlyDataAttempt: initialData?.isEmpty == false ? attempt : nil
        )
    }

    func activate(
        destination: NowhereProtocol.Target,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data? = nil,
        attempt: NowhereFlowOpenAttempt? = nil
    ) async throws {
        let request = try requestPayload(
            destination: destination,
            flowHeader: flowHeader,
            initialData: initialData
        )

        let (openStream, openSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        let connection: TLSProxyConnection? = state.withLock { state in
            guard let inner = state.inner, state.transition(to: .requesting) else { return nil }
            state.preparedCloseHandler = nil
            state.openSignal = openSignal
            state.flowResultKind = flowHeader.kind
            state.flowRole = flowHeader.role
            return inner
        }
        guard let connection else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }

        let onRequestSent: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            if flowHeader.role != .open {
                let canProcess = self.state.withLock { state -> Bool in
                    guard state.phase == .requesting else { return false }
                    return state.transition(to: .waitingResult)
                }
                guard canProcess else { return }
                self.processBufferedFlowResult(on: connection, fallbackError: error)
                return
            }

            var readySignal: AsyncThrowingStream<Never, Error>.Continuation?
            var failure = error
            let wasRequesting = self.state.withLock { state -> Bool in
                guard state.phase == .requesting else { return false }
                if failure == nil, state.transportReadClosed {
                    failure = state.terminalError ?? AnywhereError.proxy(.nowhere, .connectionClosed(detail:
                        "OPEN stream closed before request completed"
                    ))
                }
                if failure == nil {
                    state.transition(to: .ready)
                    readySignal = state.openSignal
                    state.openSignal = nil
                }
                return true
            }
            guard wasRequesting else { return }
            if let failure {
                self.fail(failure)
                return
            }
            readySignal?.finish()
            self.deliverPendingReceive()
        }
        Task {
            attempt?.markEarlyDataWriteStarted()
            do { try await connection.sendRaw(request); onRequestSent(nil) }
            catch { onRequestSent(error) }
        }
        for try await _ in openStream {}
    }

    private func requestPayload(
        destination: NowhereProtocol.Target,
        flowHeader: NowhereProtocol.FlowHeader,
        initialData: Data? = nil
    ) throws -> Data {
        return try NowhereProtocol.encodeFlowRequest(
            header: flowHeader,
            target: flowHeader.carriesTarget ? destination : nil,
            initialData: flowHeader.role == .attach ? nil : initialData
        )
    }

    private func connectAndSend(
        payload: Data,
        successState: Phase,
        expectsFlowResult: Bool,
        flowKind: NowhereProtocol.FlowKind?,
        flowRole: NowhereProtocol.FlowRole?,
        earlyDataAttempt: NowhereFlowOpenAttempt? = nil
    ) async throws {
        let (openStream, openSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        let canOpen = state.withLock { state -> Bool in
            guard state.transition(to: .connecting) else { return false }
            state.openSignal = openSignal
            state.flowResultKind = flowKind
            state.flowRole = flowRole
            return true
        }
        guard canOpen else {
            throw AnywhereError.proxy(.nowhere, .notReady)
        }

        let baseTLS = configuration.tls
        let tlsConfiguration = TLSConfiguration(
            serverName: baseTLS.serverName,
            alpn: [configuration.alpn],
            minVersion: .tls13,
            maxVersion: .tls13,
            echEnabled: baseTLS.echEnabled,
            echConfig: baseTLS.echConfig,
            fingerprint: baseTLS.fingerprint
        )
        let client = TLSClient(configuration: tlsConfiguration)
        state.withLock { $0.tlsClient = client }

        let handleResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.fail(error)
            case .success(let tlsConnection):
                let bootstrap: Data
                do {
                    let exporter = try tlsConnection.exportKeyingMaterial(
                        label: "EXPORTER-Nowhere-Auth",
                        context: Data(),
                        length: 32
                    )
                    let auth = try NowhereProtocol.makeAuthFrame(
                        authKey: self.configuration.authKey,
                        transport: .tlsTCP,
                        exporter: exporter,
                        sessionID: self.configuration.sessionID
                    )
                    bootstrap = auth + payload
                } catch {
                    tlsConnection.cancel()
                    self.fail(error)
                    return
                }
                let proxy = TLSProxyConnection(tlsConnection: tlsConnection)
                let shouldSend = self.state.withLock { state -> Bool in
                    guard state.transition(to: .authenticating) else { return false }
                    state.tlsClient = nil
                    state.inner = proxy
                    return true
                }
                guard shouldSend else {
                    proxy.cancel()
                    return
                }
                let onPayloadSent: (Error?) -> Void = { [weak self] error in
                    guard let self else { return }
                    if let error {
                        self.fail(error)
                        return
                    }
                    let readySignal: AsyncThrowingStream<Never, Error>.Continuation? = self.state.withLock { state -> AsyncThrowingStream<Never, Error>.Continuation? in
                        guard state.phase == .authenticating else { return nil }
                        if expectsFlowResult {
                            state.transition(to: .waitingResult)
                            return nil
                        }
                        state.transition(to: successState)
                        let signal = state.openSignal
                        state.openSignal = nil
                        return signal
                    }
                    if !expectsFlowResult { readySignal?.finish() }
                    self.armTransportRead(on: proxy)
                }
                Task {
                    earlyDataAttempt?.markEarlyDataWriteStarted()
                    do { try await proxy.sendRaw(bootstrap); onPayloadSent(nil) }
                    catch { onPayloadSent(error) }
                }
            }
        }

        Task {
            do {
                let tlsConnection: TLSRecordConnection
                if let tunnel {
                    tlsConnection = try await client.connect(overTunnel: tunnel)
                } else {
                    tlsConnection = try await client.connect(host: connectHost, port: configuration.proxyPort)
                }
                handleResult(.success(tlsConnection))
            } catch {
                handleResult(.failure(error))
            }
        }
        for try await _ in openStream {}
    }

    private func armTransportRead(on connection: TLSProxyConnection) {
        let shouldRead: Bool = state.withLock { state in
            guard state.inner === connection, state.phase != .closed,
                  !state.transportReadClosed, !state.transportReadInFlight else {
                return false
            }
            guard state.phase == .prepared || state.phase == .requesting || state.phase == .waitingResult
                    || (state.phase == .ready && (state.pendingReceive != nil || shouldProbeUOTUplink(state))) else {
                return false
            }
            state.transportReadInFlight = true
            return true
        }
        guard shouldRead else { return }
        let task = Task {
            do {
                let data = try await connection.receiveRaw()
                handleTransportRead(connection: connection, data: data, error: nil)
            } catch {
                handleTransportRead(connection: connection, data: nil, error: error)
            }
        }
        let stored: Bool = state.withLock { state in
            guard state.phase != .closed else { return false }
            state.transportReadTask = task
            return true
        }
        if !stored { task.cancel() }
    }

    private func handleTransportRead(
        connection: TLSProxyConnection,
        data: Data?,
        error: Error?
    ) {
        var delivery: AsyncThrowingStream<Data, Error>.Continuation?
        var deliveredData: Data?
        var closeHandler: (@Sendable () -> Void)?
        var continueReading = false
        var openSignal: AsyncThrowingStream<Never, Error>.Continuation?
        var flowError: Error?
        var becameReady = false
        var shouldCancelTransport = false
        var shouldNotifyTermination = false
        var notificationError: Error?
        let terminal = error != nil || data == nil || data?.isEmpty == true

        let proceed: Bool = state.withLock { state in
            guard state.inner === connection, state.phase != .closed else {
                return false
            }
            state.transportReadInFlight = false
            state.transportReadTask = nil
            if terminal {
                shouldNotifyTermination = true
                notificationError = error
                if state.phase == .requesting {
                    state.transportReadClosed = true
                    state.terminalError = error
                } else if error == nil, state.phase == .ready {
                    state.transportReadClosed = true
                    delivery = state.pendingReceive
                    state.pendingReceive = nil
                } else {
                    let wasPrepared = state.phase == .prepared
                    state.transition(to: .closed)
                    state.terminalError = error
                    state.inner = nil
                    closeHandler = wasPrepared ? state.preparedCloseHandler : nil
                    state.preparedCloseHandler = nil
                    openSignal = state.openSignal
                    state.openSignal = nil
                    delivery = state.pendingReceive
                    state.pendingReceive = nil
                    shouldCancelTransport = true
                }
            } else if let data, !data.isEmpty {
                state.receiveBuffer.append(data)
                if state.phase == .waitingResult {
                    switch takeFlowResult(&state) {
                    case .needMore:
                        continueReading = true
                    case .ready:
                        state.transition(to: .ready)
                        openSignal = state.openSignal
                        state.openSignal = nil
                        becameReady = true
                        let terminal = bufferedUOTTermination(state)
                        shouldNotifyTermination = terminal.terminated
                        notificationError = terminal.error
                    case .reject(let code):
                        flowError = AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
                    case .invalid:
                        flowError = AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid flow result"))
                    }
                } else if state.phase == .ready, let callback = state.pendingReceive {
                    state.pendingReceive = nil
                    delivery = callback
                    deliveredData = state.receiveBuffer
                    state.receiveBuffer.removeAll(keepingCapacity: true)
                } else if state.phase == .ready, shouldProbeUOTUplink(state) {
                    let terminal = bufferedUOTTermination(state)
                    shouldNotifyTermination = terminal.terminated
                    notificationError = terminal.error
                    continueReading = !terminal.terminated
                } else {
                    continueReading = state.phase == .prepared || state.phase == .requesting
                }
            }
            return true
        }
        guard proceed else { return }

        if let flowError {
            fail(flowError)
            return
        }
        if let openSignal {
            if becameReady { openSignal.finish() }
            else { openSignal.finish(throwing: error ?? AnywhereError.proxy(.nowhere, .streamClosed)) }
        }
        Self.fulfill(delivery, data: deliveredData, error: error)
        closeHandler?()
        if shouldNotifyTermination { termination.fire(notificationError) }
        if shouldCancelTransport {
            connection.cancel()
        } else if continueReading {
            armTransportRead(on: connection)
        } else if becameReady {
            deliverPendingReceive()
        }
    }

    enum FlowResultStep: Equatable {
        case needMore
        case ready
        case reject(NowhereProtocol.FlowRejectCode)
        case invalid
    }

    private func bufferedUOTTermination(_ state: State) -> (terminated: Bool, error: Error?) {
        guard state.flowResultKind == .udp, state.flowRole == .open else { return (false, nil) }
        guard !state.receiveBuffer.isEmpty else { return (false, nil) }
        return (true, AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Unexpected reverse UoT payload")))
    }

    private func processBufferedFlowResult(
        on connection: TLSProxyConnection,
        fallbackError: Error? = nil
    ) {
        var openSignal: AsyncThrowingStream<Never, Error>.Continuation?
        var failure: Error?
        var shouldRead = false
        var becameReady = false
        var bufferedTermination = (terminated: false, error: Optional<Error>.none)

        let proceed: Bool = state.withLock { state in
            guard state.inner === connection, state.phase == .waitingResult else {
                return false
            }
            switch takeFlowResult(&state) {
            case .needMore:
                if let fallbackError {
                    failure = fallbackError
                } else if state.transportReadClosed {
                    failure = state.terminalError ?? AnywhereError.proxy(.nowhere, .streamClosed)
                } else {
                    shouldRead = true
                }
            case .ready:
                if let terminalError = state.terminalError {
                    failure = terminalError
                } else {
                    state.transition(to: .ready)
                    openSignal = state.openSignal
                    state.openSignal = nil
                    becameReady = true
                    bufferedTermination = bufferedUOTTermination(state)
                }
            case .reject(let code):
                failure = AnywhereError.proxy(.nowhere, .flowRejected(code: code.rawValue))
            case .invalid:
                failure = AnywhereError.proxy(.nowhere, .connectionClosed(detail: "Invalid flow result"))
            }
            return true
        }
        guard proceed else { return }

        if let failure {
            fail(failure)
            return
        }
        openSignal?.finish()
        if bufferedTermination.terminated {
            termination.fire(bufferedTermination.error)
        }
        if shouldRead {
            armTransportRead(on: connection)
        } else if becameReady {
            deliverPendingReceive()
        }
    }

    private func takeFlowResult(_ state: inout State) -> FlowResultStep {
        guard let flowResultKind = state.flowResultKind else { return .invalid }
        let step = Self.bufferedTLSFlowResultStep(
            kind: flowResultKind,
            buffer: state.receiveBuffer
        )
        switch step {
        case .ready, .reject:
            state.receiveBuffer.removeFirst(NowhereProtocol.flowResultSize)
        case .needMore, .invalid:
            break
        }
        return step
    }

    static func bufferedTLSFlowResultStep(
        kind: NowhereProtocol.FlowKind,
        buffer: Data
    ) -> FlowResultStep {
        _ = kind
        guard buffer.count >= NowhereProtocol.flowResultSize else { return .needMore }
        guard let result = NowhereProtocol.decodeFlowResult(buffer) else { return .invalid }
        switch result {
        case .ready: return .ready
        case .reject(let code): return .reject(code)
        }
    }

    private func deliverPendingReceive() {
        var callback: AsyncThrowingStream<Data, Error>.Continuation?
        var data: Data?
        state.withLock { state in
            if state.didBecomeReady, !state.receiveBuffer.isEmpty, let pending = state.pendingReceive {
                callback = pending
                state.pendingReceive = nil
                data = state.receiveBuffer
                state.receiveBuffer.removeAll(keepingCapacity: true)
            }
        }
        Self.fulfill(callback, data: data, error: nil)
    }

    private func fail(_ error: Error) {
        let resources: (TLSClient?, TLSProxyConnection?, AsyncThrowingStream<Never, Error>.Continuation?, AsyncThrowingStream<Data, Error>.Continuation?, (() -> Void)?) = state.withLock { state in
            let wasPrepared = state.phase == .prepared
            guard state.transition(to: .closed) else { return (nil, nil, nil, nil, nil) }
            state.terminalError = error
            let result = (state.tlsClient, state.inner, state.openSignal, state.pendingReceive, wasPrepared ? state.preparedCloseHandler : nil)
            state.tlsClient = nil
            state.inner = nil
            state.openSignal = nil
            state.pendingReceive = nil
            state.preparedCloseHandler = nil
            return result
        }
        resources.0?.cancel()
        resources.1?.cancel()
        resources.2?.finish(throwing: error)
        Self.fulfill(resources.3, data: nil, error: error)
        resources.4?()
        termination.fire(error)
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        let connection = state.withLock { state in
            state.phase == .ready ? state.inner : nil
        }
        guard let connection else {
            throw AnywhereError.proxy(.nowhere, .streamClosed)
        }
        try await connection.sendRaw(data)
    }

    private static func fulfill(
        _ continuation: AsyncThrowingStream<Data, Error>.Continuation?,
        data: Data?,
        error: Error?
    ) {
        guard let continuation else { return }
        if let error {
            continuation.finish(throwing: error)
        } else if let data {
            continuation.yield(data)
            continuation.finish()
        } else {
            continuation.finish()
        }
    }

    func receiveRaw() async throws -> Data? {
        let (inbox, continuation) = AsyncThrowingStream.makeStream(of: Data.self)
        var result: (Data?, Error?)?
        var staleReceive: AsyncThrowingStream<Data, Error>.Continuation?
        state.withLock { state in
            if state.didBecomeReady, !state.receiveBuffer.isEmpty {
                let data = state.receiveBuffer
                state.receiveBuffer.removeAll(keepingCapacity: true)
                result = (data, nil)
            } else if state.transportReadClosed {
                result = (nil, nil)
            } else if state.phase == .closed {
                result = (nil, state.terminalError)
            } else if state.phase == .ready {
                staleReceive = state.pendingReceive
                state.pendingReceive = continuation
            } else {
                result = (nil, AnywhereError.proxy(.nowhere, .notReady))
            }
        }
        Self.fulfill(staleReceive, data: nil, error: AnywhereError.proxy(.nowhere, .connectionClosed(detail:
            "overlapping receiveRaw on Nowhere TCP stream"
        )))
        if let result {
            Self.fulfill(continuation, data: result.0, error: result.1)
        } else if let connection = state.withLock({ $0.phase == .ready ? $0.inner : nil }) {
            armTransportRead(on: connection)
        }
        for try await chunk in inbox { return chunk }
        return nil
    }

    func cancel() {
        let resources: (TLSClient?, TLSProxyConnection?, AsyncThrowingStream<Never, Error>.Continuation?, AsyncThrowingStream<Data, Error>.Continuation?, (() -> Void)?) = state.withLock { state in
            let wasPrepared = state.phase == .prepared
            guard state.transition(to: .closed) else { return (nil, nil, nil, nil, nil) }
            state.terminalError = AnywhereError.proxy(.nowhere, .streamClosed)
            let result = (state.tlsClient, state.inner, state.openSignal, state.pendingReceive, wasPrepared ? state.preparedCloseHandler : nil)
            state.tlsClient = nil
            state.inner = nil
            state.openSignal = nil
            state.pendingReceive = nil
            state.preparedCloseHandler = nil
            state.transportReadTask?.cancel()
            state.transportReadTask = nil
            return result
        }
        resources.0?.cancel()
        resources.1?.cancel()
        resources.2?.finish(throwing: AnywhereError.proxy(.nowhere, .streamClosed))
        Self.fulfill(resources.3, data: nil, error: AnywhereError.proxy(.nowhere, .streamClosed))
        resources.4?()
        termination.fire(AnywhereError.proxy(.nowhere, .streamClosed))
    }
}

nonisolated final class NowhereDirectionalConnection: ProxyConnection {
    private let uplink: ProxyConnection
    private let downlink: ProxyConnection
    private let kind: NowhereProtocol.FlowKind
    private let termination = TerminationLatch()

    init(
        uplink: ProxyConnection,
        downlink: ProxyConnection,
        kind: NowhereProtocol.FlowKind
    ) {
        self.uplink = uplink
        self.downlink = downlink
        self.kind = kind
        if kind == .udp {
            (uplink as? NowhereTerminationObservable)?.setNowhereTerminationHandler {
                [weak self] _ in self?.hardFail()
            }
            if downlink !== uplink {
                (downlink as? NowhereTerminationObservable)?.setNowhereTerminationHandler {
                    [weak self] _ in self?.hardFail()
                }
            }
        }
    }

    var isConnected: Bool {
        !termination.isTerminated && uplink.isConnected && downlink.isConnected
    }
    var outerTLSVersion: TLSVersion? { uplink.outerTLSVersion ?? downlink.outerTLSVersion }
    var deliversDatagrams: Bool { uplink.deliversDatagrams || downlink.deliversDatagrams }

    // MARK: - ProxyConnection overrides

    func send(_ data: Data) async throws {
        do { try await uplink.send(data) }
        catch { hardFail(); throw error }
    }

    func sendRaw(_ data: Data) async throws {
        do { try await uplink.sendRaw(data) }
        catch { hardFail(); throw error }
    }

    func receive() async throws -> Data? {
        do {
            let data = try await downlink.receive()
            if kind == .udp, data == nil { hardFail() }
            return data
        } catch {
            hardFail()
            throw error
        }
    }

    func receiveRaw() async throws -> Data? {
        do {
            let data = try await downlink.receiveRaw()
            if kind == .udp, data == nil { hardFail() }
            return data
        } catch {
            hardFail()
            throw error
        }
    }

    func cancel() {
        guard termination.fire(nil) else { return }
        clearTerminationObservers()
        uplink.cancel()
        if uplink !== downlink { downlink.cancel() }
    }

    private func hardFail() {
        guard termination.fire(nil) else { return }
        clearTerminationObservers()
        uplink.cancel()
        if downlink !== uplink { downlink.cancel() }
    }

    private func clearTerminationObservers() {
        (uplink as? NowhereTerminationObservable)?.setNowhereTerminationHandler(nil)
        if downlink !== uplink {
            (downlink as? NowhereTerminationObservable)?.setNowhereTerminationHandler(nil)
        }
    }
}

extension NowhereConnection: ProxyConnection {}
