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

nonisolated protocol NowhereTerminationObservable: AnyObject {
    func setNowhereTerminationHandler(_ handler: ((Error?) -> Void)?)
}

nonisolated final class NowhereConnection: ProxyConnection {

    enum State { case idle, openingStream, handshaking, waitingResult, ready, closed }
    enum BufferedFlowResultStep: Equatable {
        case deferred
        case needMore
        case ready
        case reject(NowhereProtocol.FlowRejectCode)
        case invalid
    }

    private let session: NowhereSession
    private let destination: String
    private let flowHeader: NowhereProtocol.FlowHeader

    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            _isReady.store(newValue == .ready, ordering: .relaxed)
        }
    }
    private let _isReady = Atomic<Bool>(false)

    /// Stored atomically: set once on `session.queue` during open, then read from the
    /// async send/close paths off-queue.
    private let _streamID = Atomic<Int64>(-1)
    private var streamID: Int64 {
        get { _streamID.load(ordering: .relaxed) }
        set { _streamID.store(newValue, ordering: .relaxed) }
    }
    private var readClosed = false
    private var receiveBuffer = Data()
    /// Post-result stream bytes / EOF / error from the session demux; the async
    /// replacement for the parked `pendingReceive`. Stream credit is returned in
    /// ``receiveRaw()`` only once the app takes the bytes (backpressure preserved).
    private let inbox = AsyncByteChannel()
    /// One-shot open signal, resolved by the demux/callback path; the awaiter is `openTask.value`.
    private let openSignal: AsyncThrowingStream<Never, Error>.Continuation
    private let openTask: Task<Void, Error>
    private var setupTerminationError: Error?

    init(
        session: NowhereSession,
        destination: String,
        flowHeader: NowhereProtocol.FlowHeader
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        let (openStream, openSignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.openSignal = openSignal
        self.openTask = Task { for try await _ in openStream {} }
    }

    var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    var outerTLSVersion: TLSVersion? { .tls13 }

    func open() async throws {
        // Claim the connection on the ngtcp2 queue; `openSignal` resolves later in
        // `finishOpen`/`processFlowResultIfAvailable` (result) or `fail` (error).
        let started: Bool = await session.run { [self] in
            guard state == .idle else { return false }
            state = .openingStream
            return true
        }
        guard started else { throw NowhereError.notReady }

        // Reserve the stream, then send the request.
        Task { [weak self] in
            guard let self else { return }
            do {
                let streamID = try await self.session.openTCPStream(for: self)
                await self.session.run { self.streamID = streamID; self.sendTCPRequest() }
            } catch {
                await self.session.run { self.fail(error) }
            }
        }
        try await openTask.value
    }

    private func sendTCPRequest() {
        state = .handshaking
        let frame: Data
        do {
            frame = try NowhereProtocol.encodeFlowRequest(
                header: flowHeader,
                target: destination,
                protocolSpec: session.protocolSpec
            )
        } catch {
            fail(error)
            return
        }
        Task { [weak self] in
            guard let self else { return }
            let writeError: Error?
            do {
                try await self.session.writeStream(self.streamID, data: frame)
                writeError = nil
            } catch {
                writeError = error
            }
            self.session.queue.async {
                guard self.state == .handshaking else { return }
                if self.flowHeader.role != .open {
                    self.state = .waitingResult
                    self.processFlowResultIfAvailable()
                    guard self.state == .waitingResult else { return }
                    if let writeError {
                        self.fail(writeError)
                    } else if self.readClosed {
                        self.fail(NowhereError.connectionFailed(
                            "Stream closed before complete READY"
                        ))
                    }
                } else {
                    if let terminalError = Self.openSetupError(
                        writeError: writeError,
                        terminationError: self.setupTerminationError
                    ) {
                        self.fail(terminalError)
                        return
                    }
                    self.finishOpen()
                }
            }
        }
    }

    func handleStreamData(_ data: Data, fin: Bool) {
        // On session.queue, synchronously inside ngtcp2's read_pkt; `data` is a zero-copy
        // view that must be detached before it escapes to the inbox.
        guard state != .closed else { return }

        if state == .openingStream || state == .handshaking || state == .waitingResult {
            if !data.isEmpty {
                receiveBuffer.append(data)
            }
            if fin { readClosed = true }
            if state == .waitingResult {
                processFlowResultIfAvailable()
                if readClosed, state == .waitingResult {
                    fail(NowhereError.connectionFailed("Stream closed before complete READY"))
                }
            }
            return
        }

        guard state == .ready else { return }

        if !data.isEmpty {
            inbox.yield(Data(data))
        }
        if fin {
            readClosed = true
            inbox.finish()
        }
    }

    private func processFlowResultIfAvailable() {
        switch Self.bufferedFlowResultStep(state: state, buffer: receiveBuffer) {
        case .deferred, .needMore:
            return
        case .invalid:
            fail(NowhereError.connectionFailed("Invalid flow result"))
        case .ready:
            receiveBuffer.removeFirst(NowhereProtocol.flowResultSize)
            // Credit the consumed flow-result frame now; post-result app data is
            // credited lazily as the app consumes it in `receiveRaw`.
            session.extendStreamOffset(streamID, count: NowhereProtocol.flowResultSize)
            if let setupTerminationError {
                fail(setupTerminationError)
            } else {
                finishOpen()
            }
        case .reject(let code):
            receiveBuffer.removeFirst(NowhereProtocol.flowResultSize)
            session.extendStreamOffset(streamID, count: NowhereProtocol.flowResultSize)
            fail(NowhereError.flowRejected(code))
        }
    }

    static func bufferedFlowResultStep(
        state: State,
        buffer: Data
    ) -> BufferedFlowResultStep {
        guard state == .waitingResult else { return .deferred }
        guard buffer.count >= NowhereProtocol.flowResultSize else { return .needMore }
        let prefix = Data(buffer.prefix(NowhereProtocol.flowResultSize))
        guard let result = NowhereProtocol.decodeFlowResult(prefix) else { return .invalid }
        switch result {
        case .ready: return .ready
        case .reject(let code): return .reject(code)
        }
    }

    /// OPEN has no F2. A clean peer FIN proves the server consumed the request;
    /// only a local write failure or reset/error makes setup fail.
    static func openSetupError(
        writeError: Error?,
        terminationError: Error?
    ) -> Error? {
        writeError ?? terminationError
    }

    private func finishOpen() {
        guard state != .closed else { return }
        state = .ready
        openSignal.finish()
        // Flush any coalesced post-result app data, then honour a buffered FIN.
        flushBufferToInbox()
        if readClosed { inbox.finish() }
    }

    /// Hands buffered post-result app bytes to the inbox. Runs on `session.queue`.
    private func flushBufferToInbox() {
        guard !receiveBuffer.isEmpty else { return }
        let out = receiveBuffer
        receiveBuffer = Data()
        inbox.yield(out)
    }

    func handleSessionError(_ error: Error) {
        if let quicError = error as? QUICConnection.QUICError, case .closedOK = quicError {
            session.queue.async { [weak self] in self?.handleStreamTermination(error: nil) }
            return
        }
        session.queue.async { [weak self] in self?.fail(error) }
    }

    func handleSessionClose() {
        session.queue.async { [weak self] in self?.handleStreamTermination(error: nil) }
    }

    func handleStreamTermination(error: Error?) {
        guard state != .closed else { return }
        if state == .openingStream || state == .handshaking || state == .waitingResult {
            readClosed = true
            setupTerminationError = error
            if state == .waitingResult {
                processFlowResultIfAvailable()
                if state == .waitingResult {
                    fail(error ?? NowhereError.connectionFailed(
                        "Stream closed before complete READY"
                    ))
                }
            }
            return
        }
        if let error {
            fail(error)
            return
        }
        readClosed = true
        state = .closed
        // EOF ordered after every byte already queued in the inbox.
        inbox.finish()
    }

    private func fail(_ error: Error) {
        guard state != .closed else { return }
        state = .closed

        if streamID >= 0 {
            session.shutdownStream(streamID)
            session.releaseTCPStream(streamID)
        }

        openSignal.finish(throwing: error)
        inbox.fail(error)
    }

    // MARK: - ProxyConnection overrides

    func sendRaw(_ data: Data) async throws {
        guard _isReady.load(ordering: .relaxed) else {
            throw NowhereError.streamClosed
        }
        try await session.writeStream(streamID, data: data)
    }

    func receiveRaw() async throws -> Data? {
        let data = try await inbox.next()
        if let data, !data.isEmpty {
            // Return stream flow-control credit only now the app has taken the bytes.
            session.extendStreamOffset(streamID, count: data.count)
        }
        return data
    }

    func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            if self.streamID >= 0 {
                self.session.shutdownStream(self.streamID)
                self.session.releaseTCPStream(self.streamID)
            }
            self.inbox.cancel()
            self.openSignal.finish(throwing: NowhereError.streamClosed)
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
        /// Parked until the flow reaches `.prepared`/`.ready` or fails. The async bridge
        /// over the TLS-carrier setup state machine.
        var openContinuation: CheckedContinuation<Void, Error>?
        var receiveBuffer = Data()
        /// Residual receive park (single continuation); see MIGRATION.md's residual-continuations note.
        var pendingReceive: ((Data?, Error?) -> Void)?
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

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let connection: TLSProxyConnection? = state.withLock { state in
                guard state.phase == .prepared, let inner = state.inner else { return nil }
                state.phase = .requesting
                state.preparedCloseHandler = nil
                state.openContinuation = continuation
                state.flowResultKind = flowHeader.kind
                state.flowRole = flowHeader.role
                return inner
            }
            guard let connection else {
                continuation.resume(throwing: NowhereError.streamClosed)
                return
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

                var readyContinuation: CheckedContinuation<Void, Error>?
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
                        readyContinuation = state.openContinuation
                        state.openContinuation = nil
                    }
                    return true
                }
                guard wasRequesting else { return }
                if let failure {
                    self.fail(failure)
                    return
                }
                readyContinuation?.resume()
                self.deliverPendingReceive()
            }
            Task {
                do { try await connection.sendRaw(request); onRequestSent(nil) }
                catch { onRequestSent(error) }
            }
        }
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
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let canOpen = state.withLock { state -> Bool in
                guard state.phase == .idle else { return false }
                state.phase = .connecting
                state.openContinuation = continuation
                state.flowResultKind = flowKind
                state.flowRole = flowRole
                return true
            }
            guard canOpen else {
                continuation.resume(throwing: NowhereError.notReady)
                return
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
                        let readyContinuation: CheckedContinuation<Void, Error>? = self.state.withLock { state -> CheckedContinuation<Void, Error>? in
                            guard state.phase == .authenticating else { return nil }
                            if expectsFlowResult {
                                state.phase = .waitingResult
                                return nil
                            }
                            state.phase = successState
                            if successState == .ready { state.didBecomeReady = true }
                            let continuation = state.openContinuation
                            state.openContinuation = nil
                            return continuation
                        }
                        if !expectsFlowResult { readyContinuation?.resume() }
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
        }
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
        Task { [weak self, weak connection] in
            guard let self, let connection else { return }
            do {
                let data = try await connection.receiveRaw()
                self.handleTransportRead(connection: connection, data: data, error: nil)
            } catch {
                self.handleTransportRead(connection: connection, data: nil, error: error)
            }
        }
    }

    private func handleTransportRead(
        connection: TLSProxyConnection,
        data: Data?,
        error: Error?
    ) {
        var delivery: ((Data?, Error?) -> Void)?
        var deliveredData: Data?
        var closeHandler: (() -> Void)?
        var continueReading = false
        var openContinuation: CheckedContinuation<Void, Error>?
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
                    openContinuation = state.openContinuation
                    state.openContinuation = nil
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
                        openContinuation = state.openContinuation
                        state.openContinuation = nil
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
        if let openContinuation {
            if becameReady { openContinuation.resume() }
            else { openContinuation.resume(throwing: error ?? NowhereError.streamClosed) }
        }
        delivery?(deliveredData, error)
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
        var offset = 0
        while offset < buffer.count {
            let available = buffer.count - offset
            guard available >= 3 else { return .none }
            let length = (Int(buffer[offset + 1]) << 8) | Int(buffer[offset + 2])
            guard available >= 3 + length else { return .none }
            guard let (message, consumed) = NowhereProtocol.decodeUDPStreamFrame(
                buffer,
                offset: offset
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
        return .none
    }

    /// A prepared connection can already have a transport read in flight when
    /// activation writes its request. If READY wins that race, it is buffered
    /// while state is `.requesting`; consume it immediately after switching to
    /// `.waitingResult` instead of waiting for another network read.
    private func processBufferedFlowResult(
        on connection: TLSProxyConnection,
        fallbackError: Error? = nil
    ) {
        var continuation: CheckedContinuation<Void, Error>?
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
                    continuation = state.openContinuation
                    state.openContinuation = nil
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
        continuation?.resume()
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
        var callback: ((Data?, Error?) -> Void)?
        var data: Data?
        state.withLock { state in
            if state.didBecomeReady, !state.receiveBuffer.isEmpty, let pending = state.pendingReceive {
                callback = pending
                state.pendingReceive = nil
                data = state.receiveBuffer
                state.receiveBuffer.removeAll(keepingCapacity: true)
            }
        }
        callback?(data, nil)
    }

    private func fail(_ error: Error) {
        let resources: (TLSClient?, TLSProxyConnection?, CheckedContinuation<Void, Error>?, ((Data?, Error?) -> Void)?, (() -> Void)?) = state.withLock { state in
            guard state.phase != .closed else { return (nil, nil, nil, nil, nil) }
            let wasPrepared = state.phase == .prepared
            state.phase = .closed
            state.terminalError = error
            let result = (state.tlsClient, state.inner, state.openContinuation, state.pendingReceive, wasPrepared ? state.preparedCloseHandler : nil)
            state.tlsClient = nil
            state.inner = nil
            state.openContinuation = nil
            state.pendingReceive = nil
            state.preparedCloseHandler = nil
            return result
        }
        resources.0?.cancel()
        resources.1?.cancel()
        resources.2?.resume(throwing: error)
        resources.3?(nil, error)
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

    /// The intricate setup/read machinery (`armTransportRead`/`handleTransportRead`) still
    /// fulfils `pendingReceive`; the async surface parks the caller's continuation there, so
    /// the verified state machine is preserved verbatim (the one continuation left here is the
    /// receive park — see MIGRATION.md's residual-continuations note).
    func receiveRaw() async throws -> Data? {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            let completion: (Data?, Error?) -> Void = { data, error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume(returning: data) }
            }
            var result: (Data?, Error?)?
            var staleReceive: ((Data?, Error?) -> Void)?
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
                    state.pendingReceive = completion
                } else {
                    result = (nil, NowhereError.notReady)
                }
            }
            staleReceive?(nil, NowhereError.connectionFailed(
                "overlapping receiveRaw on Nowhere TCP stream"
            ))
            if let result { completion(result.0, result.1) }
            else if let connection = state.withLock({ $0.phase == .ready ? $0.inner : nil }) {
                armTransportRead(on: connection)
            }
        }
    }

    func cancel() {
        let resources: (TLSClient?, TLSProxyConnection?, CheckedContinuation<Void, Error>?, ((Data?, Error?) -> Void)?, (() -> Void)?) = state.withLock { state in
            guard state.phase != .closed else { return (nil, nil, nil, nil, nil) }
            let wasPrepared = state.phase == .prepared
            state.phase = .closed
            state.terminalError = NowhereError.streamClosed
            let result = (state.tlsClient, state.inner, state.openContinuation, state.pendingReceive, wasPrepared ? state.preparedCloseHandler : nil)
            state.tlsClient = nil
            state.inner = nil
            state.openContinuation = nil
            state.pendingReceive = nil
            state.preparedCloseHandler = nil
            return result
        }
        resources.0?.cancel()
        resources.1?.cancel()
        resources.2?.resume(throwing: NowhereError.streamClosed)
        resources.3?(nil, NowhereError.streamClosed)
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
