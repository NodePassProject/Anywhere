//
//  NowhereConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

enum NowhereTCPRelayMode {
    case tcp
    case udp
}

nonisolated final class NowhereConnection: ProxyConnection {

    enum State { case idle, openingStream, handshaking, ready, closed }

    private let session: NowhereSession
    private let destination: String

    private var _state: State = .idle
    private var state: State {
        get { _state }
        set {
            _state = newValue
            readyLock.withLock { _isReady = (newValue == .ready) }
        }
    }
    private let readyLock = UnfairLock()
    private var _isReady = false

    private var streamID: Int64 = -1
    private var readClosed = false
    private var receiveBuffer = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var pendingQuicBytes = 0
    private var openCompletion: ((Error?) -> Void)?

    init(session: NowhereSession, destination: String) {
        self.session = session
        self.destination = destination
        super.init()
    }

    override var isConnected: Bool {
        readyLock.withLock { _isReady }
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
            frame = try NowhereProtocol.encodeTCPRequest(
                address: destination,
                protocolSpec: session.protocolSpec
            )
        } catch {
            fail(error)
            return
        }
        session.writeStream(streamID, data: frame) { [weak self] error in
            guard let self else { return }
            self.session.queue.async {
                if let error {
                    self.fail(error)
                    return
                }
                guard self.state == .handshaking else { return }
                self.state = .ready
                if let callback = self.openCompletion {
                    self.openCompletion = nil
                    callback(nil)
                }
                self.deliverBufferedOrEOF(eof: self.readClosed)
            }
        }
    }

    func handleStreamData(_ data: Data, fin: Bool) {
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

    func handleStreamTermination(error: Error?) {
        guard state != .closed else { return }
        if let error {
            fail(error)
            return
        }
        if state != .ready {
            fail(NowhereError.connectionFailed("Stream closed before request completed"))
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
            if !self.receiveBuffer.isEmpty && self.state == .ready {
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
            self.pendingReceive = completion
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
        }
    }
}

nonisolated final class NowhereTCPUDPConnection: ProxyConnection, UDPFramingCapable {

    private let inner: NowhereTCPConnection

    var udpBuffer = Data()
    var udpBufferOffset = 0
    let udpLock = UnfairLock()

    init(inner: NowhereTCPConnection) {
        self.inner = inner
        super.init()
    }

    override var isConnected: Bool { inner.isConnected }
    override var outerTLSVersion: TLSVersion? { inner.outerTLSVersion }
    override var deliversDatagrams: Bool { true }

    override func send(data: Data, completion: @escaping (Error?) -> Void) {
        super.send(data: frameUDPPacket(data), completion: completion)
    }

    override func send(data: Data) {
        super.send(data: frameUDPPacket(data))
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        inner.sendRaw(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        inner.sendRaw(data: data)
    }

    override func receive(completion: @escaping (Data?, Error?) -> Void) {
        udpLock.lock()
        if let packet = extractUDPPacket() {
            udpLock.unlock()
            completion(packet, nil)
            return
        }
        udpLock.unlock()
        receiveMore(completion: completion)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        inner.receiveRaw(completion: completion)
    }

    private func receiveMore(completion: @escaping (Data?, Error?) -> Void) {
        inner.receive { [weak self] data, error in
            guard let self else {
                completion(nil, ProxyError.connectionFailed("Connection deallocated"))
                return
            }
            if let error {
                completion(nil, error)
                return
            }
            guard let data else {
                completion(nil, nil)
                return
            }
            self.udpLock.lock()
            self.udpBuffer.append(data)
            if let packet = self.extractUDPPacket() {
                self.udpLock.unlock()
                completion(packet, nil)
            } else {
                self.udpLock.unlock()
                self.receiveMore(completion: completion)
            }
        }
    }

    override func cancel() {
        udpLock.lock()
        clearUDPBuffer()
        udpLock.unlock()
        inner.cancel()
    }
}

nonisolated final class NowhereTCPConnection: ProxyConnection {

    private enum State { case idle, connecting, authenticating, prepared, requesting, ready, closed }

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

    func setPreparedCloseHandler(_ handler: (() -> Void)?) {
        lock.withLock { preparedCloseHandler = handler }
    }

    func prepare(completion: @escaping (Error?) -> Void) {
        let auth: Data
        do {
            auth = try NowhereProtocol.makeAuthFrame(
                key: configuration.key,
                protocolSpec: configuration.protocolSpec
            )
        } catch {
            completion(error)
            return
        }

        connectAndSend(payload: auth, successState: .prepared, completion: completion)
    }

    func openFresh(
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        completion: @escaping (Error?) -> Void
    ) {
        let bootstrap: Data
        do {
            bootstrap = try NowhereProtocol.makeAuthFrame(
                key: configuration.key,
                protocolSpec: configuration.protocolSpec
            ) + requestPayload(destination: destination, mode: mode)
        } catch {
            completion(error)
            return
        }

        connectAndSend(payload: bootstrap, successState: .ready, completion: completion)
    }

    func activate(
        destination: String,
        mode: NowhereTCPRelayMode = .tcp,
        completion: @escaping (Error?) -> Void
    ) {
        let request: Data
        do {
            request = try requestPayload(destination: destination, mode: mode)
        } catch {
            completion(error)
            return
        }

        let connection: TLSProxyConnection? = lock.withLock {
            guard state == .prepared, let inner else { return nil }
            state = .requesting
            preparedCloseHandler = nil
            openCompletion = completion
            return inner
        }
        guard let connection else {
            completion(NowhereError.streamClosed)
            return
        }

        connection.sendRaw(data: request) { [weak self] error in
            guard let self else { return }
            if let error {
                self.fail(error)
                return
            }
            let callback: ((Error?) -> Void)? = self.lock.withLock {
                guard self.state == .requesting else { return nil }
                self.state = .ready
                let callback = self.openCompletion
                self.openCompletion = nil
                return callback
            }
            callback?(nil)
            self.deliverPendingReceive()
        }
    }

    private func requestPayload(destination: String, mode: NowhereTCPRelayMode) throws -> Data {
        switch mode {
        case .tcp:
            return try NowhereProtocol.encodeTCPRequest(
                address: destination,
                protocolSpec: configuration.protocolSpec
            )
        case .udp:
            var payload = try NowhereProtocol.encodeTCPRequest(
                address: NowhereProtocol.uotMagicTarget,
                protocolSpec: configuration.protocolSpec
            )
            payload.append(try NowhereProtocol.encodeUOTSetupTarget(destination))
            return payload
        }
    }

    private func connectAndSend(
        payload: Data,
        successState: State,
        completion: @escaping (Error?) -> Void
    ) {
        let canOpen = lock.withLock {
            guard state == .idle else { return false }
            state = .connecting
            openCompletion = completion
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
                        self.state = successState
                        let callback = self.openCompletion
                        self.openCompletion = nil
                        return callback
                    }
                    callback?(nil)
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
            guard inner === connection, state != .closed, !transportReadInFlight else {
                return false
            }
            guard state == .prepared || state == .requesting || (state == .ready && pendingReceive != nil) else {
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
        let terminal = error != nil || data == nil || data?.isEmpty == true

        lock.lock()
        guard inner === connection, state != .closed else {
            lock.unlock()
            return
        }
        transportReadInFlight = false
        if terminal {
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
        } else if let data, !data.isEmpty {
            if state == .ready, receiveBuffer.isEmpty, let callback = pendingReceive {
                pendingReceive = nil
                delivery = callback
                deliveredData = data
            } else {
                receiveBuffer.append(data)
            }
            continueReading = true
        }
        lock.unlock()

        openCallback?(error ?? NowhereError.streamClosed)
        delivery?(deliveredData, error)
        closeHandler?()
        if terminal {
            connection.cancel()
        } else if continueReading {
            armTransportRead(on: connection)
        }
    }

    private func deliverPendingReceive() {
        var callback: ((Data?, Error?) -> Void)?
        var data: Data?
        lock.lock()
        if state == .ready, !receiveBuffer.isEmpty, let pending = pendingReceive {
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
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        let connection = lock.withLock { state == .ready ? inner : nil }
        guard let connection else {
            completion(NowhereError.streamClosed)
            return
        }
        connection.sendRaw(data: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        let connection = lock.withLock { state == .ready ? inner : nil }
        connection?.sendRaw(data: data)
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        var result: (Data?, Error?)?
        lock.lock()
        if state == .ready, !receiveBuffer.isEmpty {
            let data = receiveBuffer
            receiveBuffer.removeAll(keepingCapacity: true)
            result = (data, nil)
        } else if state == .closed {
            result = (nil, terminalError)
        } else if state == .ready {
            pendingReceive = completion
        } else {
            result = (nil, NowhereError.notReady)
        }
        lock.unlock()
        if let result { completion(result.0, result.1) }
        else if let connection = lock.withLock({ state == .ready ? inner : nil }) {
            armTransportRead(on: connection)
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
    }
}
