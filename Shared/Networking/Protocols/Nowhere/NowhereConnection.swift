//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation
import Synchronization

enum NowhereTCPRelayMode {
    case tcp
    case udp
}

protocol NowhereTerminationObservable: AnyObject {
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

    private var streamID: Int64 = -1
    private var readClosed = false
    private var receiveBuffer = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var pendingQuicBytes = 0
    private var openCompletion: ((Error?) -> Void)?
    private var didBecomeReady = false
    private var setupTerminationError: Error?

    init(
        session: NowhereSession,
        destination: String,
        flowHeader: NowhereProtocol.FlowHeader
    ) {
        self.session = session
        self.destination = destination
        self.flowHeader = flowHeader
        super.init()
    }

    override var isConnected: Bool {
        _isReady.load(ordering: .relaxed)
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    func open(completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .idle else { completion(NowhereError.notReady); return }
            self.openCompletion = completion
            self.state = .openingStream

            self.session.openTCPStream(for: self) { [weak self] sid, error in
                guard let self else { return }
                self.session.queue.async {
                    if let error {
                        self.fail(error)
                        return
                    }
                    guard let sid else {
                        self.fail(NowhereError.connectionFailed("No stream"))
                        return
                    }
                    self.streamID = sid
                    self.sendTCPRequest()
                }
            }
        }
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
        session.writeStream(streamID, data: frame) { [weak self] error in
            guard let self else { return }
            self.session.queue.async {
                guard self.state == .handshaking else { return }
                if self.flowHeader.role != .open {
                    self.state = .waitingResult
                    self.processFlowResultIfAvailable()
                    guard self.state == .waitingResult else { return }
                    if let error {
                        self.fail(error)
                    } else if self.readClosed {
                        self.fail(NowhereError.connectionFailed(
                            "Stream closed before complete READY"
                        ))
                    }
                } else {
                    if let terminalError = Self.openSetupError(
                        writeError: error,
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
        if state == .openingStream || state == .handshaking || state == .waitingResult {
            if !data.isEmpty {
                pendingQuicBytes += data.count
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

        if state == .ready, receiveBuffer.isEmpty, !data.isEmpty,
           let callback = pendingReceive {
            pendingReceive = nil
            let ackCount = pendingQuicBytes + data.count
            pendingQuicBytes = 0
            let out = Data(data)
            if fin { readClosed = true }
            session.extendStreamOffset(streamID, count: ackCount)
            callback(out, nil)
            return
        }

        if !data.isEmpty {
            pendingQuicBytes += data.count
            receiveBuffer.append(data)
        }
        if fin { readClosed = true }

        guard state == .ready else { return }
        deliverBufferedOrEOF(eof: readClosed)
    }

    private func processFlowResultIfAvailable() {
        switch Self.bufferedFlowResultStep(state: state, buffer: receiveBuffer) {
        case .deferred, .needMore:
            return
        case .invalid:
            fail(NowhereError.connectionFailed("Invalid flow result"))
        case .ready:
            receiveBuffer.removeFirst(NowhereProtocol.flowResultSize)
            pendingQuicBytes = max(0, pendingQuicBytes - NowhereProtocol.flowResultSize)
            session.extendStreamOffset(streamID, count: NowhereProtocol.flowResultSize)
            if let setupTerminationError {
                fail(setupTerminationError)
            } else {
                finishOpen()
            }
        case .reject(let code):
            receiveBuffer.removeFirst(NowhereProtocol.flowResultSize)
            pendingQuicBytes = max(0, pendingQuicBytes - NowhereProtocol.flowResultSize)
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
        didBecomeReady = true
        let callback = openCompletion
        openCompletion = nil
        callback?(nil)
        deliverBufferedOrEOF(eof: readClosed)
    }

    private func deliverBufferedOrEOF(eof: Bool) {
        if let callback = pendingReceive, !receiveBuffer.isEmpty {
            pendingReceive = nil
            let out = receiveBuffer
            receiveBuffer = Data()
            let ackCount = takePendingQuicBytes()
            session.extendStreamOffset(streamID, count: ackCount)
            callback(out, nil)
            return
        }

        if eof, let callback = pendingReceive {
            pendingReceive = nil
            callback(nil, nil)
        }
    }

    private func takePendingQuicBytes() -> Int {
        let count = pendingQuicBytes
        pendingQuicBytes = 0
        return count
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
        if let callback = pendingReceive {
            pendingReceive = nil
            callback(nil, nil)
        }
    }

    private func fail(_ error: Error) {
        guard state != .closed else { return }
        state = .closed

        if streamID >= 0 {
            session.shutdownStream(streamID)
            session.releaseTCPStream(streamID)
        }

        if let callback = openCompletion {
            openCompletion = nil
            callback(error)
        }
        if let callback = pendingReceive {
            pendingReceive = nil
            callback(nil, error)
        }
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(self.state == .closed ? NowhereError.streamClosed : NowhereError.notReady)
                return
            }
            self.session.writeStream(self.streamID, data: data, completion: completion)
        }
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self else {
                completion(nil, NowhereError.streamClosed)
                return
            }
            if !self.receiveBuffer.isEmpty && self.didBecomeReady {
                let out = self.receiveBuffer
                self.receiveBuffer = Data()
                let ackCount = self.takePendingQuicBytes()
                self.session.extendStreamOffset(self.streamID, count: ackCount)
                completion(out, nil)
                return
            }
            if self.state == .closed {
                completion(nil, nil)
                return
            }
            if self.readClosed {
                completion(nil, nil)
                return
            }
            let stale = self.pendingReceive
            self.pendingReceive = completion
            stale?(nil, NowhereError.connectionFailed(
                "overlapping receiveRaw on Nowhere QUIC stream"
            ))
        }
    }

    override func closeWrite(completion: @escaping (Error?) -> Void) {
        session.queue.async { [weak self] in
            guard let self, self.state == .ready else {
                completion(NowhereError.streamClosed)
                return
            }
            self.session.finishStream(self.streamID, completion: completion)
        }
    }

    override func cancel() {
        session.queue.async { [weak self] in
            guard let self, self.state != .closed else { return }
            self.state = .closed
            if self.streamID >= 0 {
                self.session.shutdownStream(self.streamID)
                self.session.releaseTCPStream(self.streamID)
            }
            if let callback = self.pendingReceive {
                self.pendingReceive = nil
                callback(nil, NowhereError.streamClosed)
            }
            if let callback = self.openCompletion {
                self.openCompletion = nil
                callback(NowhereError.streamClosed)
            }
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
    private static let closeFlushQueue = DispatchQueue(
        label: "com.argsment.Anywhere.NowhereUoTClose",
        qos: .utility
    )
    private static let closeFlushBound: DispatchTimeInterval = .milliseconds(250)

    init(inner: NowhereTCPConnection) {
        self.inner = inner
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    override var deliversDatagrams: Bool { true }

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

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        do {
            let frame = try NowhereProtocol.encodeUDPStreamFrame(type: .data, payload: data)
            inner.sendRaw(data: frame, completion: completion)
        } catch NowhereError.udpPacketTooLarge {
            // UDP is lossy by contract. Drop only this packet; keep the flow alive.
            completion(nil)
        } catch {
            completion(error)
        }
    }

    override func sendRaw(data: Data) {
        guard let frame = try? NowhereProtocol.encodeUDPStreamFrame(type: .data, payload: data) else { return }
        inner.sendRaw(data: frame)
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

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        switch udpState.withLock({ nextPacketStep(&$0) }) {
        case .deliver(let packet):
            completion(packet, nil)
        case .close:
            notifyTermination(error: nil)
            completion(nil, nil)
        case .fail(let error):
            notifyTermination(error: error)
            completion(nil, error)
        case .needMore:
            receiveMore(completion: completion)
        }
    }

    private func receiveMore(completion: @escaping (Data?, Error?) -> Void) {
        inner.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                self.notifyTermination(error: error)
                completion(nil, error)
                return
            }
            guard let data else {
                self.notifyTermination(error: nil)
                completion(nil, nil)
                return
            }
            let step = self.udpState.withLock { state -> PacketStep in
                state.buffer.append(data)
                return self.nextPacketStep(&state)
            }
            switch step {
            case .deliver(let packet):
                completion(packet, nil)
            case .close:
                self.notifyTermination(error: nil)
                completion(nil, nil)
            case .fail(let error):
                self.notifyTermination(error: error)
                completion(nil, error)
            case .needMore:
                self.receiveMore(completion: completion)
            }
        }
    }

    override func cancel() {
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
        inner.sendRaw(data: close) { [weak self] _ in self?.finishCancel() }
        Self.closeFlushQueue.asyncAfter(deadline: .now() + Self.closeFlushBound) { [self] in
            finishCancel()
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

    private enum State { case idle, connecting, authenticating, prepared, requesting, waitingResult, ready, closed }

    private let configuration: NowhereConfiguration
    private let connectHost: String
    private let tunnel: ProxyConnection?

    private var state: State = .idle
    private var tlsClient: TLSClient?
    private var inner: TLSProxyConnection?
    private var openCompletion: ((Error?) -> Void)?
    private var receiveBuffer = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var terminalError: Error?
    private var preparedCloseHandler: (() -> Void)?
    private var transportReadInFlight = false
    private var transportReadClosed = false
    private var transportWriteClosed = false
    private var flowResultKind: NowhereProtocol.FlowKind?
    private var flowRole: NowhereProtocol.FlowRole?
    private var didBecomeReady = false
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
        super.init()
    }

    override var isConnected: Bool {
        lock.withLock { state == .ready && inner?.isConnected == true }
    }

    override var outerTLSVersion: TLSVersion? {
        lock.withLock { inner?.outerTLSVersion }
    }

    var isPrepared: Bool {
        lock.withLock { state == .prepared && inner?.isConnected == true }
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
              let connection = lock.withLock({ state == .ready ? inner : nil }) else { return }
        armTransportRead(on: connection)
    }

    private var hasTerminationHandler: Bool {
        termination.withLock { !$0.terminated && $0.handler != nil }
    }

    /// Only the asymmetric UoT OPEN half has no application receive loop. Its
    /// peer must send no DATA, so one bounded frame probe can monitor liveness
    /// without prefetching valid downlink traffic into an unbounded buffer.
    private var shouldProbeUOTUplink: Bool {
        flowResultKind == .udp && flowRole == .open && hasTerminationHandler
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
        lock.withLock { preparedCloseHandler = handler }
    }

    func prepare(completion: @escaping (Error?) -> Void) {
        let auth: Data
        do {
            auth = try NowhereProtocol.makeAuthFrame(
                key: configuration.key,
                protocolSpec: configuration.protocolSpec,
                sessionID: configuration.sessionID
            )
        } catch {
            completion(error)
            return
        }

        connectAndSend(
            payload: auth,
            successState: .prepared,
            expectsFlowResult: false,
            flowKind: nil,
            flowRole: nil,
            completion: completion
        )
    }

    func openFresh(
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader,
        completion: @escaping (Error?) -> Void
    ) {
        let bootstrap: Data
        do {
            bootstrap = try NowhereProtocol.makeAuthFrame(
                key: configuration.key,
                protocolSpec: configuration.protocolSpec,
                sessionID: configuration.sessionID
            ) + requestPayload(destination: destination, flowHeader: flowHeader)
        } catch {
            completion(error)
            return
        }

        connectAndSend(
            payload: bootstrap,
            successState: .ready,
            expectsFlowResult: flowHeader.role != .open,
            flowKind: flowHeader.kind,
            flowRole: flowHeader.role,
            completion: completion
        )
    }

    func activate(
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        flowHeader: NowhereProtocol.FlowHeader,
        completion: @escaping (Error?) -> Void
    ) {
        let request: Data
        do {
            request = try requestPayload(destination: destination, flowHeader: flowHeader)
        } catch {
            completion(error)
            return
        }

        let connection: TLSProxyConnection? = lock.withLock {
            guard state == .prepared, let inner else { return nil }
            state = .requesting
            preparedCloseHandler = nil
            openCompletion = completion
            flowResultKind = flowHeader.kind
            flowRole = flowHeader.role
            return inner
        }
        guard let connection else {
            completion(NowhereError.streamClosed)
            return
        }

        connection.sendRaw(data: request) { [weak self] error in
            guard let self else { return }
            if flowHeader.role != .open {
                let canProcess = self.lock.withLock {
                    guard self.state == .requesting else { return false }
                    self.state = .waitingResult
                    return true
                }
                guard canProcess else { return }
                self.processBufferedFlowResult(on: connection, fallbackError: error)
                return
            }

            var callback: ((Error?) -> Void)?
            var failure = error
            let wasRequesting = self.lock.withLock { () -> Bool in
                guard self.state == .requesting else { return false }
                if failure == nil, self.transportReadClosed {
                    failure = self.terminalError ?? NowhereError.connectionFailed(
                        "OPEN stream closed before request completed"
                    )
                }
                if failure == nil {
                    self.state = .ready
                    self.didBecomeReady = true
                    callback = self.openCompletion
                    self.openCompletion = nil
                }
                return true
            }
            guard wasRequesting else { return }
            if let failure {
                self.fail(failure)
                return
            }
            callback?(nil)
            self.deliverPendingReceive()
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
        successState: State,
        expectsFlowResult: Bool,
        flowKind: NowhereProtocol.FlowKind?,
        flowRole: NowhereProtocol.FlowRole?,
        completion: @escaping (Error?) -> Void
    ) {
        let canOpen = lock.withLock {
            guard state == .idle else { return false }
            state = .connecting
            openCompletion = completion
            self.flowResultKind = flowKind
            self.flowRole = flowRole
            return true
        }
        guard canOpen else {
            completion(NowhereError.notReady)
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
        lock.withLock { tlsClient = client }

        let handleResult: (Result<TLSRecordConnection, Error>) -> Void = { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.fail(error)
            case .success(let tlsConnection):
                let proxy = TLSProxyConnection(tlsConnection: tlsConnection)
                let shouldSend = self.lock.withLock {
                    guard self.state == .connecting else { return false }
                    self.state = .authenticating
                    self.tlsClient = nil
                    self.inner = proxy
                    return true
                }
                guard shouldSend else {
                    proxy.cancel()
                    return
                }
                proxy.sendRaw(data: payload) { [weak self] error in
                    guard let self else { return }
                    if let error {
                        self.fail(error)
                        return
                    }
                    let callback: ((Error?) -> Void)? = self.lock.withLock {
                        guard self.state == .authenticating else { return nil }
                        if expectsFlowResult {
                            self.state = .waitingResult
                            return nil
                        }
                        self.state = successState
                        if successState == .ready { self.didBecomeReady = true }
                        let callback = self.openCompletion
                        self.openCompletion = nil
                        return callback
                    }
                    if !expectsFlowResult { callback?(nil) }
                    self.armTransportRead(on: proxy)
                }
            }
        }

        if let tunnel {
            client.connect(overTunnel: tunnel, completion: handleResult)
        } else {
            client.connect(host: connectHost, port: configuration.proxyPort, completion: handleResult)
        }
    }

    private func armTransportRead(on connection: TLSProxyConnection) {
        let shouldRead: Bool = lock.withLock {
            guard inner === connection, state != .closed,
                  !transportReadClosed, !transportReadInFlight else {
                return false
            }
            guard state == .prepared || state == .requesting || state == .waitingResult
                    || (state == .ready && (pendingReceive != nil || shouldProbeUOTUplink)) else {
                return false
            }
            transportReadInFlight = true
            return true
        }
        guard shouldRead else { return }
        connection.receiveRaw { [weak self, weak connection] data, error in
            guard let self, let connection else { return }
            self.handleTransportRead(connection: connection, data: data, error: error)
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
        var openCallback: ((Error?) -> Void)?
        var flowError: Error?
        var becameReady = false
        var shouldCancelTransport = false
        var shouldNotifyTermination = false
        var notificationError: Error?
        let terminal = error != nil || data == nil || data?.isEmpty == true

        lock.lock()
        guard inner === connection, state != .closed else {
            lock.unlock()
            return
        }
        transportReadInFlight = false
        if terminal {
            shouldNotifyTermination = true
            notificationError = error
            if state == .requesting {
                // A prepared connection can receive F2+FIN before the request
                // write callback. Preserve both the buffered result and EOF;
                // the callback transitions to waitingResult and resolves F2.
                transportReadClosed = true
                terminalError = error
            } else if error == nil, state == .ready {
                transportReadClosed = true
                delivery = pendingReceive
                pendingReceive = nil
                if transportWriteClosed {
                    state = .closed
                    inner = nil
                    shouldCancelTransport = true
                }
            } else {
                let wasPrepared = state == .prepared
                state = .closed
                terminalError = error
                inner = nil
                closeHandler = wasPrepared ? preparedCloseHandler : nil
                preparedCloseHandler = nil
                openCallback = openCompletion
                openCompletion = nil
                delivery = pendingReceive
                pendingReceive = nil
                shouldCancelTransport = true
            }
        } else if let data, !data.isEmpty {
            receiveBuffer.append(data)
            if state == .waitingResult {
                switch takeFlowResultLocked() {
                case .needMore:
                    continueReading = true
                case .ready:
                    state = .ready
                    didBecomeReady = true
                    openCallback = openCompletion
                    openCompletion = nil
                    becameReady = true
                    let terminal = bufferedUOTTerminationLocked()
                    shouldNotifyTermination = terminal.terminated
                    notificationError = terminal.error
                case .reject(let code):
                    flowError = NowhereError.flowRejected(code)
                case .invalid:
                    flowError = NowhereError.connectionFailed("Invalid flow result")
                }
            } else if state == .ready, let callback = pendingReceive {
                pendingReceive = nil
                delivery = callback
                deliveredData = receiveBuffer
                receiveBuffer.removeAll(keepingCapacity: true)
            } else if state == .ready, shouldProbeUOTUplink {
                let terminal = bufferedUOTTerminationLocked()
                shouldNotifyTermination = terminal.terminated
                notificationError = terminal.error
                continueReading = !terminal.terminated
            } else {
                continueReading = state == .prepared || state == .requesting
            }
        }
        lock.unlock()

        if let flowError {
            fail(flowError)
            return
        }
        openCallback?(becameReady ? nil : (error ?? NowhereError.streamClosed))
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
    private func bufferedUOTTerminationLocked() -> (terminated: Bool, error: Error?) {
        guard flowResultKind == .udp, flowRole == .open else { return (false, nil) }
        switch Self.bufferedUOTTerminationStep(buffer: receiveBuffer) {
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
        var callback: ((Error?) -> Void)?
        var failure: Error?
        var shouldRead = false
        var becameReady = false
        var bufferedTermination = (terminated: false, error: Optional<Error>.none)

        lock.lock()
        guard inner === connection, state == .waitingResult else {
            lock.unlock()
            return
        }
        switch takeFlowResultLocked() {
        case .needMore:
            if let fallbackError {
                failure = fallbackError
            } else if transportReadClosed {
                failure = terminalError ?? NowhereError.streamClosed
            } else {
                shouldRead = true
            }
        case .ready:
            if let terminalError {
                failure = terminalError
            } else {
                state = .ready
                didBecomeReady = true
                callback = openCompletion
                openCompletion = nil
                becameReady = true
                bufferedTermination = bufferedUOTTerminationLocked()
            }
        case .reject(let code):
            failure = NowhereError.flowRejected(code)
        case .invalid:
            failure = NowhereError.connectionFailed("Invalid flow result")
        }
        lock.unlock()

        if let failure {
            fail(failure)
            return
        }
        callback?(nil)
        if bufferedTermination.terminated {
            notifyTermination(error: bufferedTermination.error)
        }
        if shouldRead {
            armTransportRead(on: connection)
        } else if becameReady {
            deliverPendingReceive()
        }
    }

    /// Must be called while `lock` is held. It consumes only the setup prefix,
    /// preserving any coalesced first payload in `receiveBuffer`.
    private func takeFlowResultLocked() -> FlowResultStep {
        guard let flowResultKind else { return .invalid }
        let step = Self.bufferedTLSFlowResultStep(
            kind: flowResultKind,
            buffer: receiveBuffer
        )
        switch step {
        case .ready, .reject:
            let consumed: Int
            switch flowResultKind {
            case .tcp:
                consumed = NowhereProtocol.flowResultSize
            case .udp:
                consumed = 3 + ((Int(receiveBuffer[receiveBuffer.startIndex + 1]) << 8)
                    | Int(receiveBuffer[receiveBuffer.startIndex + 2]))
            }
            receiveBuffer.removeFirst(consumed)
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
        lock.lock()
        if didBecomeReady, !receiveBuffer.isEmpty, let pending = pendingReceive {
            callback = pending
            pendingReceive = nil
            data = receiveBuffer
            receiveBuffer.removeAll(keepingCapacity: true)
        }
        lock.unlock()
        callback?(data, nil)
    }

    private func fail(_ error: Error) {
        let resources: (TLSClient?, TLSProxyConnection?, ((Error?) -> Void)?, ((Data?, Error?) -> Void)?, (() -> Void)?) = lock.withLock {
            guard state != .closed else { return (nil, nil, nil, nil, nil) }
            let wasPrepared = state == .prepared
            state = .closed
            terminalError = error
            let result = (tlsClient, inner, openCompletion, pendingReceive, wasPrepared ? preparedCloseHandler : nil)
            tlsClient = nil
            inner = nil
            openCompletion = nil
            pendingReceive = nil
            preparedCloseHandler = nil
            return result
        }
        resources.0?.cancel()
        resources.1?.cancel()
        resources.2?(error)
        resources.3?(nil, error)
        resources.4?()
        notifyTermination(error: error)
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        let connection = lock.withLock {
            state == .ready && !transportWriteClosed ? inner : nil
        }
        guard let connection else {
            completion(NowhereError.streamClosed)
            return
        }
        connection.sendRaw(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        let connection = lock.withLock {
            state == .ready && !transportWriteClosed ? inner : nil
        }
        connection?.sendRaw(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        var result: (Data?, Error?)?
        var staleReceive: ((Data?, Error?) -> Void)?
        lock.lock()
        if didBecomeReady, !receiveBuffer.isEmpty {
            let data = receiveBuffer
            receiveBuffer.removeAll(keepingCapacity: true)
            result = (data, nil)
        } else if transportReadClosed {
            result = (nil, nil)
        } else if state == .closed {
            result = (nil, terminalError)
        } else if state == .ready {
            staleReceive = pendingReceive
            pendingReceive = completion
        } else {
            result = (nil, NowhereError.notReady)
        }
        lock.unlock()
        staleReceive?(nil, NowhereError.connectionFailed(
            "overlapping receiveRaw on Nowhere TCP stream"
        ))
        if let result { completion(result.0, result.1) }
        else if let connection = lock.withLock({ state == .ready ? inner : nil }) {
            armTransportRead(on: connection)
        }
    }

    override func closeWrite(completion: @escaping (Error?) -> Void) {
        let connection: TLSProxyConnection? = lock.withLock {
            guard state == .ready, !transportWriteClosed else { return nil }
            return inner
        }
        guard let connection else {
            let alreadyClosed = lock.withLock { state == .ready && transportWriteClosed }
            completion(alreadyClosed ? nil : NowhereError.streamClosed)
            return
        }
        connection.closeWrite { [weak self, weak connection] error in
            guard let self, let connection else {
                completion(error ?? NowhereError.streamClosed)
                return
            }
            var shouldCancel = false
            if error == nil {
                self.lock.withLock {
                    guard self.inner === connection, self.state == .ready else { return }
                    self.transportWriteClosed = true
                    if self.transportReadClosed {
                        self.state = .closed
                        self.inner = nil
                        shouldCancel = true
                    }
                }
            }
            if shouldCancel { connection.cancel() }
            completion(error)
        }
    }

    override func cancel() {
        let resources: (TLSClient?, TLSProxyConnection?, ((Error?) -> Void)?, ((Data?, Error?) -> Void)?, (() -> Void)?) = lock.withLock {
            guard state != .closed else { return (nil, nil, nil, nil, nil) }
            let wasPrepared = state == .prepared
            state = .closed
            terminalError = NowhereError.streamClosed
            let result = (tlsClient, inner, openCompletion, pendingReceive, wasPrepared ? preparedCloseHandler : nil)
            tlsClient = nil
            inner = nil
            openCompletion = nil
            pendingReceive = nil
            preparedCloseHandler = nil
            return result
        }
        resources.0?.cancel()
        resources.1?.cancel()
        resources.2?(NowhereError.streamClosed)
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
        super.init()
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

    override var isConnected: Bool {
        !lifecycle.withLock { $0.terminated } && uplink.isConnected && downlink.isConnected
    }
    override var outerTLSVersion: TLSVersion? { uplink.outerTLSVersion ?? downlink.outerTLSVersion }
    override var deliversDatagrams: Bool { uplink.deliversDatagrams || downlink.deliversDatagrams }

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        uplink.send(data: data) { [weak self] error in
            if let self, error != nil { self.hardFail() }
            completion(error)
        }
    }

    override func send(data: Data) { send(data: data) { _ in } }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        uplink.sendRaw(data: data) { [weak self] error in
            if let self, error != nil { self.hardFail() }
            completion(error)
        }
    }

    override func sendRaw(data: Data) { sendRaw(data: data) { _ in } }

    override func receive(completion: @escaping (Data?, Error?) -> Void) {
        downlink.receive { [weak self] data, error in
            if let self, error != nil || (self.kind == .udp && data == nil) {
                self.hardFail()
            }
            completion(data, error)
        }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        downlink.receiveRaw { [weak self] data, error in
            if let self, error != nil || (self.kind == .udp && data == nil) {
                self.hardFail()
            }
            completion(data, error)
        }
    }

    override func closeWrite(completion: @escaping (Error?) -> Void) {
        guard kind == .tcp else {
            completion(nil)
            return
        }
        uplink.closeWrite { [weak self] error in
            if let self, error != nil { self.hardFail() }
            completion(error)
        }
    }

    override func cancel() {
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
