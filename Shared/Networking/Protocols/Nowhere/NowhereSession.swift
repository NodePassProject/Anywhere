//
//  NowhereSession.swift
//  Anywhere
//
//  Created by NodePassProject on 5/30/26.
//

import Foundation

enum NowhereError: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case authFailed(String)
    case streamClosed
    case invalidTargetLength(Int)
    case destinationTooLargeForDatagram(maxFrame: Int, headerSize: Int)

    var errorDescription: String? {
        switch self {
        case .notReady: return "Nowhere session not ready"
        case .connectionFailed(let message): return "Nowhere connection failed: \(message)"
        case .authFailed(let message): return "Nowhere auth failed: \(message)"
        case .streamClosed: return "Nowhere stream closed"
        case .invalidTargetLength(let length): return "Nowhere target length is invalid (\(length))"
        case .destinationTooLargeForDatagram(let frame, let header):
            return "Nowhere destination too large for DATAGRAM (peer max \(frame) <= header \(header))"
        }
    }
}

protocol NowhereTCPFlowSink: AnyObject {
    func handleIncomingData(_ data: Data)
    func handleRemoteClose()
    func handleClientError(_ error: Error)
}

nonisolated final class NowhereTCPMuxClient {
    enum State { case idle, connecting, authenticating, ready, closed }

    private let configuration: NowhereConfiguration
    private weak var attachedSession: NowhereSession?
    private let transport: TLSStreamTransport
    private let queue = DispatchQueue(label: "\(AWCore.Identifier.quicQueue).nowhere-tcp", qos: .userInitiated)
    private let queueKey = DispatchSpecificKey<Void>()

    private var state: State = .idle
    private var closed = false
    private var closeWhenIdle = false
    private var readyCallbacks: [(Error?) -> Void] = []
    private var frameBuffer = Data()
    private var flows: [UInt64: NowhereTCPFlowSink] = [:]
    private var nextFlowID: UInt64 = 1
    var onClose: (() -> Void)?

    var isClosed: Bool {
        if isOnQueue { return closed }
        return queue.sync { closed }
    }

    private var isOnQueue: Bool {
        DispatchQueue.getSpecific(key: queueKey) != nil
    }

    init(configuration: NowhereConfiguration, session: NowhereSession? = nil, closeWhenIdle: Bool = false) {
        self.configuration = configuration
        self.attachedSession = session
        self.closeWhenIdle = closeWhenIdle
        self.transport = TLSStreamTransport(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            sni: configuration.tls.serverName,
            alpn: [configuration.protocolSpec.effectiveALPN]
        )
        self.queue.setSpecific(key: queueKey, value: ())
    }

    func isAttached(to session: NowhereSession) -> Bool {
        if isOnQueue { return attachedSession === session && !closed }
        return queue.sync { attachedSession === session && !closed }
    }

    func ensureReady(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            switch self.state {
            case .ready:
                completion(nil)
            case .closed:
                completion(NowhereError.streamClosed)
            case .connecting, .authenticating:
                self.readyCallbacks.append(completion)
            case .idle:
                self.readyCallbacks.append(completion)
                self.startConnection()
            }
        }
    }

    private func startConnection() {
        state = .connecting
        transport.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.fail(error)
                    return
                }
                self.state = .authenticating
                self.sendPreface()
            }
        }
    }

    private func sendPreface() {
        let frame: Data
        do {
            if let session = attachedSession {
                frame = try NowhereProtocol.makeLaneAttachFrame(
                    sessionID: session.negotiatedSessionID,
                    key: configuration.key,
                    protocolSpec: configuration.protocolSpec
                )
            } else {
                frame = try NowhereProtocol.makeAuthFrame(
                    key: configuration.key,
                    protocolSpec: configuration.protocolSpec
                )
            }
        } catch {
            fail(error)
            return
        }

        transport.send(data: frame) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.fail(error)
                    return
                }
                guard self.state == .authenticating else { return }
                self.readLoop()
            }
        }
    }

    private func readLoop() {
        transport.receive { [weak self] data, error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.fail(error)
                    return
                }
                guard let data, !data.isEmpty else {
                    self.fail(NowhereError.streamClosed)
                    return
                }
                self.frameBuffer.append(data)
                while let frame = NowhereProtocol.takeFrame(from: &self.frameBuffer) {
                    self.handleFrame(frame)
                }
                guard self.state == .ready || self.state == .authenticating else { return }
                self.readLoop()
            }
        }
    }

    private func handleFrame(_ frame: NowhereProtocol.Frame) {
        if state == .authenticating {
            handleHandshakeFrame(frame)
            return
        }
        guard let conn = flows[frame.flowID] else { return }
        switch frame.type {
        case .flowData where frame.flags == NowhereProtocol.frameFlagDownload:
            conn.handleIncomingData(frame.payload)
        case .flowClose:
            flows.removeValue(forKey: frame.flowID)
            conn.handleRemoteClose()
            maybeCloseIfIdle()
        default:
            break
        }
    }

    private func handleHandshakeFrame(_ frame: NowhereProtocol.Frame) {
        let expected: NowhereProtocol.FrameType = attachedSession == nil ? .settings : .laneAccept
        guard frame.type == expected,
              let sessionID = NowhereProtocol.decodeSessionIDPayload(frame.payload) else {
            fail(NowhereError.authFailed("TCP lane handshake returned unexpected frame"))
            return
        }
        if let attachedSession, sessionID != attachedSession.negotiatedSessionID {
            fail(NowhereError.authFailed("TCP lane attached to wrong session"))
            return
        }
        state = .ready
        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for cb in callbacks { cb(nil) }
    }

    func openTCP(
        destination: String,
        uploadLane: NowhereProtocol.LaneKind,
        downloadLane: NowhereProtocol.LaneKind,
        retainClient: Bool = false,
        completion: @escaping (Result<ProxyConnection, Error>) -> Void
    ) {
        ensureReady { [weak self] error in
            guard let self else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            if let error {
                completion(.failure(error))
                return
            }
            self.queue.async {
                var flowID = self.nextFlowID
                while flowID == 0 || self.flows[flowID] != nil {
                    flowID = flowID == UInt64.max ? 1 : flowID + 1
                }
                self.nextFlowID = flowID == UInt64.max ? 1 : flowID + 1
                let conn = NowhereTCPMuxConnection(
                    client: self,
                    flowID: flowID,
                    retainedClient: retainClient ? self : nil,
                    quicDownlinkSession: downloadLane == .quic ? self.attachedSession : nil
                )
                self.flows[flowID] = conn
                if downloadLane == .quic {
                    self.attachedSession?.registerTCPFlowSink(conn, flowID: flowID, counted: true)
                }
                let open: Data
                do {
                    open = try NowhereProtocol.encodeTCPRequest(
                        address: destination,
                        flowID: flowID,
                        uploadLane: uploadLane,
                        downloadLane: downloadLane
                    )
                } catch {
                    self.flows.removeValue(forKey: flowID)
                    self.attachedSession?.releaseTCPFlowSink(flowID)
                    completion(.failure(error))
                    return
                }
                self.transport.send(data: open) { [weak self, weak conn] error in
                    guard let self else { return }
                    self.queue.async {
                        if let error {
                            self.flows.removeValue(forKey: flowID)
                            self.attachedSession?.releaseTCPFlowSink(flowID)
                            completion(.failure(error))
                            return
                        }
                        guard let conn else {
                            self.flows.removeValue(forKey: flowID)
                            self.attachedSession?.releaseTCPFlowSink(flowID)
                            completion(.failure(NowhereError.streamClosed))
                            return
                        }
                        completion(.success(conn))
                    }
                }
            }
        }
    }

    func send(flowID: UInt64, payload: Data, completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self, self.state == .ready else {
                completion(NowhereError.streamClosed)
                return
            }
            self.transport.send(
                data: NowhereProtocol.encodeTCPData(flowID: flowID, payload: payload),
                completion: completion
            )
        }
    }

    func closeFlow(_ flowID: UInt64) {
        queue.async { [weak self] in
            guard let self else { return }
            self.flows.removeValue(forKey: flowID)
            self.attachedSession?.releaseTCPFlowSink(flowID)
            self.transport.send(data: NowhereProtocol.encodeTCPClose(flowID: flowID)) { _ in }
            self.maybeCloseIfIdle()
        }
    }

    func registerFlowSink(_ sink: NowhereTCPFlowSink, flowID: UInt64) {
        let work = {
            guard self.state == .ready else { return }
            self.flows[flowID] = sink
        }
        if isOnQueue {
            work()
        } else {
            queue.sync(execute: work)
        }
    }

    func releaseFlowSink(_ flowID: UInt64) {
        queue.async { [weak self] in
            guard let self else { return }
            self.flows.removeValue(forKey: flowID)
            self.maybeCloseIfIdle()
        }
    }

    func retireWhenIdle() {
        queue.async { [weak self] in
            guard let self else { return }
            self.closeWhenIdle = true
            self.maybeCloseIfIdle()
        }
    }

    func close() {
        queue.async { [weak self] in
            self?.closeLocked(error: NowhereError.streamClosed)
        }
    }

    private func fail(_ error: Error) {
        guard !closed else { return }
        closeLocked(error: error)
    }

    private func maybeCloseIfIdle() {
        guard closeWhenIdle, flows.isEmpty else { return }
        closeLocked(error: NowhereError.streamClosed)
    }

    private func closeLocked(error: Error) {
        guard !closed else { return }
        closed = true
        state = .closed
        transport.cancel()
        let callbacks = readyCallbacks
        readyCallbacks.removeAll()
        for cb in callbacks { cb(error) }
        let live = Array(flows.values)
        flows.removeAll()
        for flow in live {
            flow.handleClientError(error)
        }
        onClose?()
    }
}

nonisolated final class NowhereTCPMuxConnection: ProxyConnection, NowhereTCPFlowSink {
    private weak var client: NowhereTCPMuxClient?
    private let retainedClient: NowhereTCPMuxClient?
    private weak var quicDownlinkSession: NowhereSession?
    private let flowID: UInt64
    private var closed = false
    private var receiveBuffer = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?

    init(
        client: NowhereTCPMuxClient,
        flowID: UInt64,
        retainedClient: NowhereTCPMuxClient? = nil,
        quicDownlinkSession: NowhereSession? = nil
    ) {
        self.client = client
        self.retainedClient = retainedClient
        self.quicDownlinkSession = quicDownlinkSession
        self.flowID = flowID
        super.init()
    }

    override var isConnected: Bool {
        lock.withLock { !closed }
    }

    override var outerTLSVersion: TLSVersion? { .tls13 }

    func handleIncomingData(_ data: Data) {
        lock.lock()
        if let cb = pendingReceive, receiveBuffer.isEmpty {
            pendingReceive = nil
            lock.unlock()
            cb(data, nil)
            return
        }
        receiveBuffer.append(data)
        lock.unlock()
    }

    func handleRemoteClose() {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        let cb = pendingReceive
        pendingReceive = nil
        lock.unlock()
        quicDownlinkSession?.releaseTCPFlowSink(flowID)
        client?.releaseFlowSink(flowID)
        cb?(nil, nil)
    }

    func handleClientError(_ error: Error) {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        let cb = pendingReceive
        pendingReceive = nil
        lock.unlock()
        quicDownlinkSession?.releaseTCPFlowSink(flowID)
        client?.releaseFlowSink(flowID)
        cb?(nil, error)
    }

    override func sendRaw(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        let isClosed = closed
        lock.unlock()
        guard !isClosed, let client else {
            completion(NowhereError.streamClosed)
            return
        }
        client.send(flowID: flowID, payload: data, completion: completion)
    }

    override func sendRaw(data: Data) {
        sendRaw(data: data) { _ in }
    }

    override func receiveRaw(completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !receiveBuffer.isEmpty {
            let data = receiveBuffer
            receiveBuffer = Data()
            lock.unlock()
            completion(data, nil)
            return
        }
        if closed {
            lock.unlock()
            completion(nil, nil)
            return
        }
        pendingReceive = completion
        lock.unlock()
    }

    override func cancel() {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        let cb = pendingReceive
        pendingReceive = nil
        lock.unlock()
        client?.closeFlow(flowID)
        quicDownlinkSession?.releaseTCPFlowSink(flowID)
        cb?(nil, NowhereError.streamClosed)
    }
}

nonisolated final class NowhereSession {

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: NowhereConfiguration

    var queue: DispatchQueue { quic.queue }
    var isOnQueue: Bool { quic.isOnQueue }

    private var state: State = .idle
    private var closed = false

    private var authStreamID: Int64 = -1
    private var authFrameBuffer = Data()
    private var sessionID: UInt64 = 0
    private var readyCallbacks: [(Error?) -> Void] = []

    var onClose: (() -> Void)?

    private var tcpStreams: [Int64: NowhereConnection] = [:]
    private var tcpFlowSinks: [UInt64: NowhereTCPFlowSink] = [:]
    private var countedTCPFlowIDs: Set<UInt64> = []
    private var serverStreamBuffers: [Int64: Data] = [:]
    private var udpSessions: [UInt64: NowhereUDPConnection] = [:]
    private var nextUDPFlowID: UInt64 = 1

    private var idleCloseWorkItem: DispatchWorkItem?
    private static let idleCloseDelay: DispatchTimeInterval = .seconds(60)

    private let _poolLock = UnfairLock()
    private var _poolIsClosed = false
    private var _poolTCPCount = 0
    private var _poolUDPCount = 0

    var isClosed: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolIsClosed
    }

    var hasActiveConnections: Bool {
        _poolLock.lock()
        defer { _poolLock.unlock() }
        return _poolTCPCount > 0 || _poolUDPCount > 0
    }

    var negotiatedSessionID: UInt64 {
        if isOnQueue { return sessionID }
        return queue.sync { sessionID }
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
    }

    func ensureReady(completion: @escaping (Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(NowhereError.streamClosed); return }
            switch self.state {
            case .ready:
                completion(nil)
            case .closed:
                completion(NowhereError.streamClosed)
            case .connecting, .authenticating:
                self.readyCallbacks.append(completion)
            case .idle:
                self.state = .connecting
                self.readyCallbacks.append(completion)
                self.startConnection()
            }
        }
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.connectionClosedHandler = { [weak self] error in
            self?.failSession(error)
        }
        quic.streamDataHandler = { [weak self] sid, data, fin in
            self?.handleStreamData(sid: sid, data: data, fin: fin)
        }
        quic.streamTerminationHandler = { [weak self] sid, error in
            self?.handleStreamTermination(sid: sid, error: error)
        }
        quic.datagramHandler = { [weak self] data in
            self?.handleDatagram(data)
        }

        quic.connect { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.failSession(error)
                    return
                }
                self.state = .authenticating
                self.sendAuthFrame()
            }
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
                protocolSpec: configuration.protocolSpec
            )
        } catch {
            failSession(error)
            return
        }

        quic.writeStream(sid, data: frame, fin: true) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                if let error {
                    self.failSession(error)
                    return
                }
            }
        }
    }

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        if sid == authStreamID {
            if !data.isEmpty {
                authFrameBuffer.append(data)
                quic.extendStreamOffset(sid, count: data.count)
            }
            while let frame = NowhereProtocol.takeFrame(from: &authFrameBuffer) {
                guard frame.type == .settings,
                      let id = NowhereProtocol.decodeSessionIDPayload(frame.payload) else {
                    failSession(NowhereError.authFailed("Auth stream returned unexpected frame"))
                    return
                }
                sessionID = id
                state = .ready
                let callbacks = readyCallbacks
                readyCallbacks.removeAll()
                for cb in callbacks { cb(nil) }
            }
            if fin && state == .authenticating {
                failSession(NowhereError.authFailed("Auth stream closed before SETTINGS"))
            }
            return
        }

        if let conn = tcpStreams[sid] {
            conn.handleStreamData(data, fin: fin)
            return
        }

        if !data.isEmpty {
            var buffer = serverStreamBuffers[sid] ?? Data()
            buffer.append(data)
            quic.extendStreamOffset(sid, count: data.count)
            while let frame = NowhereProtocol.takeFrame(from: &buffer) {
                handleServerStreamFrame(frame)
            }
            if buffer.isEmpty {
                serverStreamBuffers.removeValue(forKey: sid)
            } else {
                serverStreamBuffers[sid] = buffer
            }
        }
        if fin {
            serverStreamBuffers.removeValue(forKey: sid)
        }
    }

    private func handleServerStreamFrame(_ frame: NowhereProtocol.Frame) {
        guard let sink = tcpFlowSinks[frame.flowID] else { return }
        switch frame.type {
        case .flowData where frame.flags == NowhereProtocol.frameFlagDownload:
            sink.handleIncomingData(frame.payload)
        case .flowClose:
            tcpFlowSinks.removeValue(forKey: frame.flowID)
            releaseCountedTCPFlowIfNeeded(frame.flowID)
            sink.handleRemoteClose()
            updateIdleCloseTimer()
        default:
            break
        }
    }

    private func handleStreamTermination(sid: Int64, error: Error?) {
        if sid == authStreamID {
            if state == .authenticating {
                failSession(error ?? NowhereError.authFailed("Auth stream closed before completion"))
            }
            return
        }
        guard let conn = tcpStreams.removeValue(forKey: sid) else { return }
        tcpFlowSinks.removeValue(forKey: UInt64(sid))
        _poolLock.lock()
        _poolTCPCount = max(0, _poolTCPCount - 1)
        _poolLock.unlock()
        updateIdleCloseTimer()
        conn.handleStreamTermination(error: error)
    }

    private func handleDatagram(_ data: Data) {
        guard let msg = NowhereProtocol.decodeUDPDatagram(data),
              msg.type == NowhereProtocol.UDPType.response.rawValue else { return }
        udpSessions[msg.flowID]?.handleIncomingDatagram(msg.payload)
    }

    func openTCPStream(for conn: NowhereConnection, completion: @escaping (Int64?, Error?) -> Void) {
        queue.async { [weak self] in
            guard let self else { completion(nil, NowhereError.streamClosed); return }
            guard self.state == .ready else {
                completion(nil, NowhereError.notReady)
                return
            }
            guard let sid = self.quic.openBidiStream() else {
                completion(nil, NowhereError.connectionFailed("Failed to open TCP stream"))
                return
            }
            self.tcpStreams[sid] = conn
            self.tcpFlowSinks[UInt64(sid)] = conn
            self._poolLock.lock()
            self._poolTCPCount += 1
            self._poolLock.unlock()
            self.updateIdleCloseTimer()
            completion(sid, nil)
        }
    }

    func writeStream(_ sid: Int64, data: Data, completion: @escaping (Error?) -> Void) {
        quic.writeStream(sid, data: data, completion: completion)
    }

    func extendStreamOffset(_ sid: Int64, count: Int) {
        quic.extendStreamOffset(sid, count: count)
    }

    func shutdownStream(_ sid: Int64) {
        quic.shutdownStream(sid, appErrorCode: NowhereProtocol.closeErrCodeOK)
    }

    func releaseTCPStream(_ sid: Int64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.tcpStreams.removeValue(forKey: sid) != nil {
                self.tcpFlowSinks.removeValue(forKey: UInt64(sid))
                self._poolLock.lock()
                self._poolTCPCount = max(0, self._poolTCPCount - 1)
                self._poolLock.unlock()
                self.updateIdleCloseTimer()
            }
        }
    }

    func registerTCPFlowSink(_ sink: NowhereTCPFlowSink, flowID: UInt64, counted: Bool) {
        let work = {
            guard self.state == .ready else { return }
            self.tcpFlowSinks[flowID] = sink
            if counted, self.countedTCPFlowIDs.insert(flowID).inserted {
                self._poolLock.lock()
                self._poolTCPCount += 1
                self._poolLock.unlock()
                self.updateIdleCloseTimer()
            }
        }
        if isOnQueue {
            work()
        } else {
            // Install the sink before FLOWOPEN is written so a fast downlink cannot race us.
            queue.sync(execute: work)
        }
    }

    func releaseTCPFlowSink(_ flowID: UInt64) {
        queue.async { [weak self] in
            guard let self else { return }
            self.tcpFlowSinks.removeValue(forKey: flowID)
            self.releaseCountedTCPFlowIfNeeded(flowID)
            self.updateIdleCloseTimer()
        }
    }

    private func releaseCountedTCPFlowIfNeeded(_ flowID: UInt64) {
        if countedTCPFlowIDs.remove(flowID) != nil {
            _poolLock.lock()
            _poolTCPCount = max(0, _poolTCPCount - 1)
            _poolLock.unlock()
        }
    }

    func registerUDPSession(_ conn: NowhereUDPConnection, completion: @escaping (Result<UInt64, Error>) -> Void) {
        let body = { [weak self] in
            guard let self else {
                completion(.failure(NowhereError.streamClosed))
                return
            }
            guard self.state == .ready else {
                completion(.failure(NowhereError.notReady))
                return
            }
            guard self.udpSessions.count < Int.max else {
                completion(.failure(NowhereError.connectionFailed("UDP flow pool exhausted")))
                return
            }
            var fid = self.nextUDPFlowID
            while fid == 0 || self.udpSessions[fid] != nil {
                fid = fid == UInt64.max ? 1 : fid + 1
            }
            self.nextUDPFlowID = fid == UInt64.max ? 1 : fid + 1
            self.udpSessions[fid] = conn
            self._poolLock.lock()
            self._poolUDPCount += 1
            self._poolLock.unlock()
            self.updateIdleCloseTimer()
            completion(.success(fid))
        }
        if isOnQueue { body() } else { queue.async(execute: body) }
    }

    func releaseUDPSession(_ flowID: UInt64) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.udpSessions.removeValue(forKey: flowID) != nil {
                self._poolLock.lock()
                self._poolUDPCount = max(0, self._poolUDPCount - 1)
                self._poolLock.unlock()
                self.updateIdleCloseTimer()
            }
        }
    }

    func writeDatagram(_ datagram: Data, completion: @escaping (Error?) -> Void) {
        quic.writeDatagram(datagram, completion: completion)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    private func updateIdleCloseTimer() {
        idleCloseWorkItem?.cancel()
        idleCloseWorkItem = nil

        guard state == .ready else { return }
        _poolLock.lock()
        let total = _poolTCPCount + _poolUDPCount
        _poolLock.unlock()
        guard total == 0 else { return }

        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self._poolLock.lock()
            let liveCount = self._poolTCPCount + self._poolUDPCount
            self._poolLock.unlock()
            guard liveCount == 0, self.state == .ready else { return }
            self.close()
        }
        idleCloseWorkItem = work
        queue.asyncAfter(deadline: .now() + Self.idleCloseDelay, execute: work)
    }

    func close() {
        let work = {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed
            self.idleCloseWorkItem?.cancel()
            self.idleCloseWorkItem = nil

            self._poolLock.lock()
            self._poolIsClosed = true
            self._poolTCPCount = 0
            self._poolUDPCount = 0
            self._poolLock.unlock()

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            let sinks = Array(self.tcpFlowSinks.values)
            self.tcpFlowSinks.removeAll()
            self.countedTCPFlowIDs.removeAll()
            self.serverStreamBuffers.removeAll()
            for c in tcp { c.handleSessionError(NowhereError.connectionFailed("Session closed")) }
            for sink in sinks { sink.handleClientError(NowhereError.connectionFailed("Session closed")) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(NowhereError.connectionFailed("Session closed")) }

            self.quic.close()
            self.onClose?()
        }
        if isOnQueue {
            work()
        } else {
            queue.async(execute: work)
        }
    }

    private func failSession(_ error: Error) {
        queue.async {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed
            self.idleCloseWorkItem?.cancel()
            self.idleCloseWorkItem = nil

            self._poolLock.lock()
            self._poolIsClosed = true
            self._poolTCPCount = 0
            self._poolUDPCount = 0
            self._poolLock.unlock()

            let callbacks = self.readyCallbacks
            self.readyCallbacks.removeAll()
            for cb in callbacks { cb(error) }

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            let sinks = Array(self.tcpFlowSinks.values)
            self.tcpFlowSinks.removeAll()
            self.countedTCPFlowIDs.removeAll()
            self.serverStreamBuffers.removeAll()
            for c in tcp { c.handleSessionError(error) }
            for sink in sinks { sink.handleClientError(error) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(error) }

            self.quic.close()
            self.onClose?()
        }
    }
}
