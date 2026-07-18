//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

nonisolated enum NowhereTCPRelayMode {
    case tcp
    case udp
}

protocol NowhereTerminationObservable: AnyObject {
    nonisolated func setNowhereTerminationHandler(_ handler: ((Error?) -> Void)?)
}

actor NowhereConnection {

    private let session: NowhereSession
    private let destination: String
    private let flowHeader: NowhereProtocol.FlowHeader

    /// Readiness mirror, so the nonisolated `isConnected`/send-guard read it without hopping.
    private nonisolated let _isReady = Atomic<Bool>(false)
    /// Assigned once in `open()`, read from the send/cancel paths.
    private nonisolated let _streamID = Atomic<Int64>(-1)

    /// Inbound stream bytes from the demux. Producer (`rawInbox`) is Sendable and driven on the
    /// ngtcp2 queue via `feedStreamData`; the single consumer pulls `rawIterator` from `open()`
    /// (flow result) then `receiveRaw()` (data), so the iterator is plain actor-isolated state.
    private nonisolated let rawInbox: AsyncThrowingStream<Data, Error>.Continuation
    private var rawIterator: AsyncThrowingStream<Data, Error>.AsyncIterator
    /// Post-result bytes left over from `open()`'s handshake, handed to the app first by `receiveRaw()`.
    private var pendingData = Data()

    /// Guards `teardown()` so the stream is shut down and released exactly once.
    private var closed = false

    init(
        session: NowhereSession,
        destination: String,
        flowHeader: NowhereProtocol.FlowHeader
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        let (stream, continuation) = AsyncThrowingStream.makeStream(of: Data.self)
        self.rawInbox = continuation
        self.rawIterator = stream.makeAsyncIterator()
    }

    nonisolated var isConnected: Bool { _isReady.load(ordering: .relaxed) }
    nonisolated var outerTLSVersion: TLSVersion? { .tls13 }

    private var streamID: Int64 {
        get { _streamID.load(ordering: .relaxed) }
        set { _streamID.store(newValue, ordering: .relaxed) }
    }

    // MARK: - Open (called by ProxyClient after the session is ready)

    func open() async throws {
        do {
            let sid = try await session.openTCPStream(for: self)
            streamID = sid
            let frame = try NowhereProtocol.encodeFlowRequest(
                header: flowHeader,
                target: destination,
                protocolSpec: session.protocolSpec
            )
            try await session.writeStream(sid, data: frame)

            if flowHeader.role == .open {
                // OPEN has no F2: ready once the request is on the wire (a write failure threw above;
                // a later reset surfaces on the first `receiveRaw`).
                pendingData = Data()
                _isReady.store(true, ordering: .relaxed)
                return
            }

            // Non-open: read inbound bytes until the flow-result (F2) frame parses.
            var buffer = Data()
            while true {
                guard let chunk = try await nextChunk() else {
                    throw NowhereError.connectionFailed("Stream closed before complete READY")
                }
                buffer.append(chunk)
                guard buffer.count >= NowhereProtocol.flowResultSize else { continue }
                let prefix = Data(buffer.prefix(NowhereProtocol.flowResultSize))
                guard let result = NowhereProtocol.decodeFlowResult(prefix) else {
                    throw NowhereError.connectionFailed("Invalid flow result")
                }
                // Credit the consumed result frame; post-result data is credited lazily in `receiveRaw`.
                session.extendStreamOffset(sid, count: NowhereProtocol.flowResultSize)
                switch result {
                case .ready:
                    buffer.removeFirst(NowhereProtocol.flowResultSize)
                    pendingData = buffer
                    _isReady.store(true, ordering: .relaxed)
                    return
                case .reject(let code):
                    throw NowhereError.flowRejected(code)
                }
            }
        } catch {
            teardown()
            throw error
        }
    }

    // MARK: - Demux feed (nonisolated; driven on the ngtcp2 queue)

    /// New inbound bytes / FIN from the session's demux loop. `data` is a zero-copy view into
    /// ngtcp2's buffer — detach with `Data(...)` before buffering it.
    nonisolated func feedStreamData(_ data: Data, fin: Bool) {
        if !data.isEmpty { rawInbox.yield(Data(data)) }
        if fin { rawInbox.finish() }
    }

    /// QUIC stream termination (RESET_STREAM or stream_close). Idempotent.
    nonisolated func handleStreamTermination(error: Error?) {
        if let error { rawInbox.finish(throwing: error) } else { rawInbox.finish() }
    }

    nonisolated func handleSessionClose() {
        rawInbox.finish()
    }

    nonisolated func handleSessionError(_ error: Error) {
        _isReady.store(false, ordering: .relaxed)
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            rawInbox.finish()
        } else {
            rawInbox.finish(throwing: error)
        }
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw NowhereError.streamClosed
        }
        try await session.writeStream(streamID, data: data)
    }

    func receiveRaw() async throws -> Data? {
        if !pendingData.isEmpty {
            let out = pendingData
            pendingData = Data()
            session.extendStreamOffset(streamID, count: out.count)
            return out
        }
        guard let chunk = try await nextChunk() else { return nil }
        if !chunk.isEmpty {
            // Return stream flow-control credit only now the app has taken the bytes.
            session.extendStreamOffset(streamID, count: chunk.count)
        }
        return chunk
    }

    /// Single-consumer pull over `rawInbox` (see `HysteriaConnection.nextChunk`).
    private func nextChunk() async throws -> Data? {
        var iterator = rawIterator
        let next = try await iterator.next()
        rawIterator = iterator
        return next
    }

    nonisolated func cancel() {
        _isReady.store(false, ordering: .relaxed)
        rawInbox.finish()
        Task { await self.teardown() }
    }

    private func teardown() {
        guard !closed else { return }
        closed = true
        let sid = _streamID.load(ordering: .relaxed)
        if sid >= 0 {
            session.shutdownStream(sid)
            session.releaseTCPStream(sid)
        }
    }
}

nonisolated final class NowhereTCPUDPConnection: ProxyConnection, NowhereTerminationObservable {

    private let inner: NowhereTCPConnection
    private let udpState = Mutex(UDPFramingState())
    private struct TerminationState {
        var handler: ((Error?) -> Void)?
        var terminated = false
        var error: Error?
    }
    private let termination = Mutex(TerminationState())
    private struct CancelState {
        var started = false
        var finished = false
    }
    private let cancelState = Mutex(CancelState())
    private static let closeFlushBound: Duration = .milliseconds(250)

    init(inner: NowhereTCPConnection) {
        self.inner = inner
    }

    var isConnected: Bool { inner.isConnected }
    var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    var deliversDatagrams: Bool { true }

    func setNowhereTerminationHandler(_ handler: ((Error?) -> Void)?) {
        let immediate: (((Error?) -> Void), Error?)? = termination.withLock { state in
            if state.terminated {
                guard let handler else { return nil }
                return (handler, state.error)
            }
            state.handler = handler
            return nil
        }
        if let immediate {
            immediate.0(immediate.1)
            return
        }
        if handler == nil {
            inner.setNowhereTerminationHandler(nil)
        } else {
            inner.setNowhereTerminationHandler { [weak self] error in
                self?.notifyTermination(error: error)
            }
        }
    }

    private func notifyTermination(error: Error?) {
        let handler: ((Error?) -> Void)? = termination.withLock { state in
            guard !state.terminated else { return nil }
            state.terminated = true
            state.error = error
            let handler = state.handler
            state.handler = nil
            return handler
        }
        handler?(error)
    }

    func sendRaw(_ data: Data) async throws {
        let frame: Data
        do {
            frame = try NowhereProtocol.encodeUDPStreamFrame(type: .data, payload: data)
        } catch NowhereError.udpPacketTooLarge {
            // UDP is lossy by contract. Drop only this packet; keep the flow alive.
            return
        }
        try await inner.sendRaw(frame)
    }

    private enum PacketStep {
        case deliver(Data)
        case close
        case fail(Error)
        case needMore
    }

    /// Pops the next typed UoT frame; call inside `udpState.withLock`.
    private func nextPacketStep(_ state: inout UDPFramingState) -> PacketStep {
        let available = state.buffer.count - state.bufferOffset
        guard available >= 3 else { return .needMore }
        let length = Int(UInt16(state.buffer[state.bufferOffset + 1]) << 8
            | UInt16(state.buffer[state.bufferOffset + 2]))
        guard available >= 3 + length else { return .needMore }
        guard let (message, consumed) = NowhereProtocol.decodeUDPStreamFrame(
            state.buffer,
            offset: state.bufferOffset
        ) else {
            return .fail(NowhereError.connectionFailed("Invalid UoT frame"))
        }
        state.bufferOffset += consumed
        if state.bufferOffset > 8192 {
            state.buffer.removeSubrange(0..<state.bufferOffset)
            state.bufferOffset = 0
        }
        switch message.type {
        case .data: return .deliver(message.payload)
        case .ready:
            return .fail(NowhereError.connectionFailed("Unexpected UoT READY frame"))
        case .close: return .close
        case .reject:
            guard let code = NowhereProtocol.FlowRejectCode(rawValue: message.payload[0]) else {
                return .fail(NowhereError.connectionFailed("Invalid UoT REJECT frame"))
            }
            return .fail(NowhereError.flowRejected(code))
        }
    }

    func receiveRaw() async throws -> Data? {
        // Pull typed UoT frames from `inner` on demand (backpressure via the app's read rate).
        while true {
            let step = udpState.withLock { nextPacketStep(&$0) }
            switch step {
            case .deliver(let packet):
                return packet
            case .close:
                notifyTermination(error: nil)
                return nil
            case .fail(let error):
                notifyTermination(error: error)
                throw error
            case .needMore:
                let data: Data?
                do {
                    data = try await inner.receive()
                } catch {
                    notifyTermination(error: error)
                    throw error
                }
                guard let data, !data.isEmpty else {
                    notifyTermination(error: nil)
                    return nil
                }
                udpState.withLock { $0.buffer.append(data) }
            }
        }
    }

    func cancel() {
        let shouldStart = cancelState.withLock { state in
            guard !state.started else { return false }
            state.started = true
            return true
        }
        guard shouldStart else { return }
        notifyTermination(error: NowhereError.streamClosed)
        udpState.withLock {
            $0.buffer = Data()
            $0.bufferOffset = 0
        }
        guard let close = try? NowhereProtocol.encodeUDPStreamFrame(type: .close) else {
            finishCancel()
            return
        }
        // Best-effort close-frame flush bounded by `closeFlushBound`; whichever of the
        // send or the deadline finishes first triggers the (idempotent) teardown.
        Task { [weak self] in
            guard let self else { return }
            _ = try? await raceDialDeadline(Self.closeFlushBound) { [weak self] in
                try await self?.inner.sendRaw(close)
            }
            self.finishCancel()
        }
    }

    private func finishCancel() {
        let shouldCancel = cancelState.withLock { state in
            guard !state.finished else { return false }
            state.finished = true
            return true
        }
        if shouldCancel { inner.cancel() }
    }
}

nonisolated final class NowhereTCPConnection: ProxyConnection, NowhereTerminationObservable {

    private enum Phase { case idle, connecting, authenticating, prepared, requesting, waitingResult, ready, closed }

    private let configuration: NowhereConfiguration
    private let connectHost: String
    private let tunnel: ProxyConnection?

    /// Guards this connection's flow-open state machine.
    private struct State {
        var phase: Phase = .idle
        var tlsClient: TLSClient?
        var inner: TLSProxyConnection?
        /// One-shot open signal: finished when the flow reaches `.prepared`/`.ready`, finished
        /// throwing on failure. The async-native bridge over the TLS-carrier setup state machine —
        /// `activate`/`connectAndSend` await it, the callback-driven resolution sites finish it.
        var openSignal: AsyncThrowingStream<Never, Error>.Continuation?
        var receiveBuffer = Data()
        /// Residual receive park (single continuation); see MIGRATION.md's residual-continuations note.
        var pendingReceive: AsyncThrowingStream<Data, Error>.Continuation?
        var terminalError: Error?
        var preparedCloseHandler: (() -> Void)?
        var transportReadInFlight = false
        var transportReadClosed = false
        var transportWriteClosed = false
        var flowResultKind: NowhereProtocol.FlowKind?
        var flowRole: NowhereProtocol.FlowRole?
        var didBecomeReady = false
    }
    private let state = Mutex(State())

    private struct TerminationState {
        var handler: ((Error?) -> Void)?
        var terminated = false
        var error: Error?
    }
    private let termination = Mutex(TerminationState())

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

    func setNowhereTerminationHandler(_ handler: ((Error?) -> Void)?) {
        let immediate: (((Error?) -> Void), Error?)? = termination.withLock { state in
            if state.terminated {
                guard let handler else { return nil }
                return (handler, state.error)
            }
            state.handler = handler
            return nil
        }
        if let immediate {
            immediate.0(immediate.1)
            return
        }
        guard handler != nil,
              let connection = state.withLock({ $0.phase == .ready ? $0.inner : nil }) else { return }
        armTransportRead(on: connection)
    }

    private var hasTerminationHandler: Bool {
        termination.withLock { !$0.terminated && $0.handler != nil }
    }

    /// Only the asymmetric UoT OPEN half has no application receive loop. Its
    /// peer must send no DATA, so one bounded frame probe can monitor liveness
    /// without prefetching valid downlink traffic into an unbounded buffer.
    private func shouldProbeUOTUplink(_ state: State) -> Bool {
        state.flowResultKind == .udp && state.flowRole == .open && hasTerminationHandler
    }

    private func notifyTermination(error: Error?) {
        let handler: ((Error?) -> Void)? = termination.withLock { state in
            guard !state.terminated else { return nil }
            state.terminated = true
            state.error = error
            let handler = state.handler
            state.handler = nil
            return handler
        }
        handler?(error)
    }

    func setPreparedCloseHandler(_ handler: (() -> Void)?) {
        state.withLock { $0.preparedCloseHandler = handler }
    }

    func prepare() async throws {
        let auth = try NowhereProtocol.makeAuthFrame(
            key: configuration.key,
            protocolSpec: configuration.protocolSpec,
            sessionID: configuration.sessionID
        )

        try await connectAndSend(
            payload: auth,
            successState: .prepared,
            expectsFlowResult: false,
            flowKind: nil,
            flowRole: nil
        )
    }

    func openFresh(
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader
    ) async throws {
        let bootstrap = try NowhereProtocol.makeAuthFrame(
            key: configuration.key,
            protocolSpec: configuration.protocolSpec,
            sessionID: configuration.sessionID
        ) + requestPayload(destination: destination, flowHeader: flowHeader)

        try await connectAndSend(
            payload: bootstrap,
            successState: .ready,
            expectsFlowResult: flowHeader.role != .open,
            flowKind: flowHeader.kind,
            flowRole: flowHeader.role
        )
    }

    func activate(
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader
    ) async throws {
        let request = try requestPayload(destination: destination, flowHeader: flowHeader)

        let (openStream, openSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        let connection: TLSProxyConnection? = state.withLock { state in
            guard state.phase == .prepared, let inner = state.inner else { return nil }
            state.phase = .requesting
            state.preparedCloseHandler = nil
            state.openSignal = openSignal
            state.flowResultKind = flowHeader.kind
            state.flowRole = flowHeader.role
            return inner
        }
        guard let connection else {
            throw NowhereError.streamClosed
        }

        let onRequestSent: (Error?) -> Void = { [weak self] error in
            guard let self else { return }
            if flowHeader.role != .open {
                let canProcess = self.state.withLock { state -> Bool in
                    guard state.phase == .requesting else { return false }
                    state.phase = .waitingResult
                    return true
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
                    failure = state.terminalError ?? NowhereError.connectionFailed(
                        "OPEN stream closed before request completed"
                    )
                }
                if failure == nil {
                    state.phase = .ready
                    state.didBecomeReady = true
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
            do { try await connection.sendRaw(request); onRequestSent(nil) }
            catch { onRequestSent(error) }
        }
        for try await _ in openStream {}
    }

    private func requestPayload(
        destination: String,
        flowHeader: NowhereProtocol.FlowHeader
    ) throws -> Data {
        return try NowhereProtocol.encodeFlowRequest(
            header: flowHeader,
            target: destination,
            protocolSpec: configuration.protocolSpec
        )
    }

    private func connectAndSend(
        payload: Data,
        successState: Phase,
        expectsFlowResult: Bool,
        flowKind: NowhereProtocol.FlowKind?,
        flowRole: NowhereProtocol.FlowRole?
    ) async throws {
        let (openStream, openSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        let canOpen = state.withLock { state -> Bool in
            guard state.phase == .idle else { return false }
            state.phase = .connecting
            state.openSignal = openSignal
            state.flowResultKind = flowKind
            state.flowRole = flowRole
            return true
        }
        guard canOpen else {
            throw NowhereError.notReady
        }

        let baseTLS = configuration.tls
        let tlsConfiguration = TLSConfiguration(
            serverName: baseTLS.serverName,
            alpn: [configuration.protocolSpec.effectiveALPN],
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
                let proxy = TLSProxyConnection(tlsConnection: tlsConnection)
                let shouldSend = self.state.withLock { state -> Bool in
                    guard state.phase == .connecting else { return false }
                    state.phase = .authenticating
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
                            state.phase = .waitingResult
                            return nil
                        }
                        state.phase = successState
                        if successState == .ready { state.didBecomeReady = true }
                        let signal = state.openSignal
                        state.openSignal = nil
                        return signal
                    }
                    if !expectsFlowResult { readySignal?.finish() }
                    self.armTransportRead(on: proxy)
                }
                Task {
                    do { try await proxy.sendRaw(payload); onPayloadSent(nil) }
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
        // Strong captures: the one-shot read task owns the connection until this single
        // `receiveRaw` settles (teardown cancels the transport, failing it); the
        // `state.inner === connection` guard in `handleTransportRead` drops stale results.
        Task {
            do {
                let data = try await connection.receiveRaw()
                handleTransportRead(connection: connection, data: data, error: nil)
            } catch {
                handleTransportRead(connection: connection, data: nil, error: error)
            }
        }
    }

    private func handleTransportRead(
        connection: TLSProxyConnection,
        data: Data?,
        error: Error?
    ) {
        var delivery: AsyncThrowingStream<Data, Error>.Continuation?
        var deliveredData: Data?
        var closeHandler: (() -> Void)?
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
            if terminal {
                shouldNotifyTermination = true
                notificationError = error
                if state.phase == .requesting {
                    // A prepared connection can receive F2+FIN before the request
                    // write callback. Preserve both the buffered result and EOF;
                    // the callback transitions to waitingResult and resolves F2.
                    state.transportReadClosed = true
                    state.terminalError = error
                } else if error == nil, state.phase == .ready {
                    state.transportReadClosed = true
                    delivery = state.pendingReceive
                    state.pendingReceive = nil
                    if state.transportWriteClosed {
                        state.phase = .closed
                        state.inner = nil
                        shouldCancelTransport = true
                    }
                } else {
                    let wasPrepared = state.phase == .prepared
                    state.phase = .closed
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
                        state.phase = .ready
                        state.didBecomeReady = true
                        openSignal = state.openSignal
                        state.openSignal = nil
                        becameReady = true
                        let terminal = bufferedUOTTermination(state)
                        shouldNotifyTermination = terminal.terminated
                        notificationError = terminal.error
                    case .reject(let code):
                        flowError = NowhereError.flowRejected(code)
                    case .invalid:
                        flowError = NowhereError.connectionFailed("Invalid flow result")
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
            else { openSignal.finish(throwing: error ?? NowhereError.streamClosed) }
        }
        Self.fulfill(delivery, data: deliveredData, error: error)
        closeHandler?()
        if shouldNotifyTermination { notifyTermination(error: notificationError) }
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

    enum BufferedUOTTerminationStep: Equatable {
        case none
        case close
        case reject(NowhereProtocol.FlowRejectCode)
        case invalidControl
    }

    /// Inspects buffered UoT frames without consuming application DATA. This is
    /// used only by the background termination probe installed for UDP flows.
    private func bufferedUOTTermination(_ state: State) -> (terminated: Bool, error: Error?) {
        guard state.flowResultKind == .udp, state.flowRole == .open else { return (false, nil) }
        switch Self.bufferedUOTTerminationStep(buffer: state.receiveBuffer) {
        case .none:
            return (false, nil)
        case .close:
            return (true, nil)
        case .reject(let code):
            return (true, NowhereError.flowRejected(code))
        case .invalidControl:
            return (true, NowhereError.connectionFailed("Invalid UoT control frame"))
        }
    }

    static func bufferedUOTTerminationStep(buffer: Data) -> BufferedUOTTerminationStep {
        // Only the first buffered frame decides the outcome — every branch is terminal.
        guard buffer.count >= 3 else { return .none }
        let length = (Int(buffer[1]) << 8) | Int(buffer[2])
        guard buffer.count >= 3 + length else { return .none }
        guard let (message, _) = NowhereProtocol.decodeUDPStreamFrame(
            buffer,
            offset: 0
        ) else { return .invalidControl }
        switch message.type {
        case .data:
            return .invalidControl
        case .close:
            return .close
        case .reject:
            guard let code = NowhereProtocol.FlowRejectCode(rawValue: message.payload[0]) else {
                return .invalidControl
            }
            return .reject(code)
        case .ready:
            return .invalidControl
        }
    }

    /// A prepared connection can already have a transport read in flight when
    /// activation writes its request. If READY wins that race, it is buffered
    /// while state is `.requesting`; consume it immediately after switching to
    /// `.waitingResult` instead of waiting for another network read.
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
                    failure = state.terminalError ?? NowhereError.streamClosed
                } else {
                    shouldRead = true
                }
            case .ready:
                if let terminalError = state.terminalError {
                    failure = terminalError
                } else {
                    state.phase = .ready
                    state.didBecomeReady = true
                    openSignal = state.openSignal
                    state.openSignal = nil
                    becameReady = true
                    bufferedTermination = bufferedUOTTermination(state)
                }
            case .reject(let code):
                failure = NowhereError.flowRejected(code)
            case .invalid:
                failure = NowhereError.connectionFailed("Invalid flow result")
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
            notifyTermination(error: bufferedTermination.error)
        }
        if shouldRead {
            armTransportRead(on: connection)
        } else if becameReady {
            deliverPendingReceive()
        }
    }

    /// Must be called while `state` is held. It consumes only the setup prefix,
    /// preserving any coalesced first payload in `receiveBuffer`.
    private func takeFlowResult(_ state: inout State) -> FlowResultStep {
        guard let flowResultKind = state.flowResultKind else { return .invalid }
        let step = Self.bufferedTLSFlowResultStep(
            kind: flowResultKind,
            buffer: state.receiveBuffer
        )
        switch step {
        case .ready, .reject:
            let consumed: Int
            switch flowResultKind {
            case .tcp:
                consumed = NowhereProtocol.flowResultSize
            case .udp:
                consumed = 3 + ((Int(state.receiveBuffer[state.receiveBuffer.startIndex + 1]) << 8)
                    | Int(state.receiveBuffer[state.receiveBuffer.startIndex + 2]))
            }
            state.receiveBuffer.removeFirst(consumed)
        case .needMore, .invalid:
            break
        }
        return step
    }

    static func bufferedTLSFlowResultStep(
        kind: NowhereProtocol.FlowKind,
        buffer: Data
    ) -> FlowResultStep {
        switch kind {
        case .tcp:
            guard buffer.count >= NowhereProtocol.flowResultSize else { return .needMore }
            let frame = Data(buffer.prefix(NowhereProtocol.flowResultSize))
            guard let result = NowhereProtocol.decodeFlowResult(frame) else { return .invalid }
            switch result {
            case .ready: return .ready
            case .reject(let code): return .reject(code)
            }
        case .udp:
            guard buffer.count >= 3 else { return .needMore }
            let length = (Int(buffer[buffer.startIndex + 1]) << 8)
                | Int(buffer[buffer.startIndex + 2])
            guard buffer.count >= 3 + length else { return .needMore }
            guard let (message, _) = NowhereProtocol.decodeUDPStreamFrame(buffer) else {
                return .invalid
            }
            switch message.type {
            case .ready:
                return .ready
            case .reject:
                guard let code = NowhereProtocol.FlowRejectCode(rawValue: message.payload[0]) else {
                    return .invalid
                }
                return .reject(code)
            case .data, .close:
                return .invalid
            }
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
            guard state.phase != .closed else { return (nil, nil, nil, nil, nil) }
            let wasPrepared = state.phase == .prepared
            state.phase = .closed
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
        notifyTermination(error: error)
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        let connection = state.withLock { state in
            state.phase == .ready && !state.transportWriteClosed ? state.inner : nil
        }
        guard let connection else {
            throw NowhereError.streamClosed
        }
        try await connection.sendRaw(data)
    }

    /// Delivers the one-shot receive outcome to a parked `receiveRaw`: a chunk (yield + finish), a
    /// clean EOF (finish → the caller's pull returns nil), or an error (finish throwing). The read
    /// stays demand-driven — `armTransportRead` only reads while a `pendingReceive` is parked — so
    /// the transport's own window is the backpressure; the setup/read machinery is unchanged.
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
        // Park a one-shot inbox in `pendingReceive`; the read machinery yields exactly one chunk (or
        // EOF/error) into it. `for try await` pulls that single value, and is cancellation-aware.
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
                result = (nil, NowhereError.notReady)
            }
        }
        Self.fulfill(staleReceive, data: nil, error: NowhereError.connectionFailed(
            "overlapping receiveRaw on Nowhere TCP stream"
        ))
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
            guard state.phase != .closed else { return (nil, nil, nil, nil, nil) }
            let wasPrepared = state.phase == .prepared
            state.phase = .closed
            state.terminalError = NowhereError.streamClosed
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
        resources.2?.finish(throwing: NowhereError.streamClosed)
        Self.fulfill(resources.3, data: nil, error: NowhereError.streamClosed)
        resources.4?()
        notifyTermination(error: NowhereError.streamClosed)
    }
}

/// Presents one logical proxy flow while retaining independent carrier halves.
nonisolated final class NowhereDirectionalConnection: ProxyConnection {
    private let uplink: ProxyConnection
    private let downlink: ProxyConnection
    private let kind: NowhereProtocol.FlowKind
    private struct LifecycleState {
        var terminated = false
    }
    private let lifecycle = Mutex(LifecycleState())

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
        !lifecycle.withLock { $0.terminated } && uplink.isConnected && downlink.isConnected
    }
    var outerTLSVersion: TLSVersion? { uplink.outerTLSVersion ?? downlink.outerTLSVersion }
    var deliversDatagrams: Bool { uplink.deliversDatagrams || downlink.deliversDatagrams }

    // MARK: - ProxyConnection overrides (directional routing; hardFail on any error)

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
        let shouldCancel = lifecycle.withLock { state in
            guard !state.terminated else { return false }
            state.terminated = true
            return true
        }
        guard shouldCancel else { return }
        clearTerminationObservers()
        uplink.cancel()
        if uplink !== downlink { downlink.cancel() }
    }

    private func hardFail() {
        let shouldCancel = lifecycle.withLock { state in
            guard !state.terminated else { return false }
            state.terminated = true
            return true
        }
        guard shouldCancel else { return }
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
