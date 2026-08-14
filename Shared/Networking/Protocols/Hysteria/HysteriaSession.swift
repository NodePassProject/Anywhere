//
//  HysteriaSession.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaSession")

nonisolated final class HysteriaSession: Sendable {

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

    private let quic: QUICConnection
    private let configuration: HysteriaConfiguration

    private struct State: PhaseHolding {
        var phase: Phase = .idle

        var authStreamID: Int64 = -1
        var authBuffer = Data()
        var authHeadersReceived = false

        var tcpStreams: [Int64: HysteriaConnection] = [:]
        var rejectedServerStreams: Set<Int64> = []

        var udpSessions: [UInt32: HysteriaUDPConnection] = [:]
        var nextUDPSessionID: UInt32 = 1

        var idleSince: ContinuousClock.Instant?
        var idleSweepTask: Task<Void, Never>?

        var udpSupported = false
        var serverRxBytesPerSec: UInt64 = 0

        var onClose: (@Sendable () -> Void)?
    }
    private let state = Mutex(State())

    private static let authBufferMaxBytes = 16 * 1024

    private static let idleCloseDelay: TimeInterval = 60

    private let readySignal: AsyncThrowingStream<Never, Error>.Continuation
    private let readyTask: Task<Void, Error>

    // MARK: Pool-visible state

    var isClosed: Bool {
        state.withLock { $0.phase == .closed }
    }

    var hasActiveConnections: Bool {
        state.withLock { !$0.tcpStreams.isEmpty || !$0.udpSessions.isEmpty }
    }

    func setOnClose(_ hook: @escaping @Sendable () -> Void) {
        let fireNow: Bool = state.withLock { session in
            guard session.phase != .closed else { return true }
            session.onClose = hook
            return false
        }
        if fireNow { hook() }
    }

    // MARK: - Init

    init(configuration: HysteriaConfiguration, transport: QUICDatagramTransport? = nil) {
        self.configuration = configuration
        let obfuscator: QUICPacketObfuscator?
        switch configuration.obfuscation {
        case .salamander(let password):
            obfuscator = SalamanderObfuscator(password: password)
        case .gecko(let password, let minPacketSize, let maxPacketSize):
            obfuscator = GeckoObfuscator(password: password, minPacketSize: minPacketSize, maxPacketSize: maxPacketSize)
        case nil:
            obfuscator = nil
        }
        self.quic = QUICConnection(
            host: configuration.proxyHost,
            port: configuration.proxyPort,
            serverName: configuration.sni,
            alpn: ["h3"],
            datagramsEnabled: true,
            tuning: .hysteria(congestionControl: configuration.congestionControl, uploadMbps: configuration.uploadMbps),
            obfuscator: obfuscator,
            transport: transport
        )
        let (readyStream, readySignal) = AsyncThrowingStream.makeStream(of: Never.self)
        self.readySignal = readySignal
        self.readyTask = Task { for try await _ in readyStream {} }
    }

    // MARK: - Lifecycle

    func ensureReady() async throws {
        let begin: Bool = state.withLock { $0.transition(to: .connecting) }
        if begin { startConnection() }
        try await readyTask.value
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.handlers.withLock { handlers in
            handlers.connectionClosed = { [weak self] error in
                self?.failSession(error)
            }
        }

        Task { [self] in
            do {
                try await quic.connect()
            } catch {
                failSession(error)
                return
            }
            quic.handlers.withLock { handlers in
                handlers.streamData = { [weak self] sid, data, fin in
                    self?.handleStreamData(sid: sid, data: data, fin: fin)
                }
                handlers.streamTermination = { [weak self] sid, error, cause in
                    self?.handleStreamTermination(sid: sid, error: error, cause: cause)
                }
                handlers.datagram = { [weak self] data in
                    self?.handleDatagram(data)
                }
            }

            let opened: Bool = await quic.run { self.openControlAndAuthOnQueue() }
            if !opened {
                failSession(AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Failed to open auth stream")))
            }
        }
    }

    private func openControlAndAuthOnQueue() -> Bool {
        if let sid = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00) // stream type = control
            payload.append(Self.clientSettingsFrame())
            quic.writeStreamOnQueue(sid, data: payload)
        }
        if let encoderStreamID = quic.openUniStream() {
            quic.writeStreamOnQueue(encoderStreamID, data: Data([0x02]))
        }
        if let decoderStreamID = quic.openUniStream() {
            quic.writeStreamOnQueue(decoderStreamID, data: Data([0x03]))
        }

        guard let sid = quic.openBidiStream() else { return false }
        state.withLock { session in
            session.authStreamID = sid
            session.transition(to: .authenticating)
        }

        let extraHeaders: [(name: String, value: String)] = [
            ("hysteria-auth", configuration.password),
            ("hysteria-cc-rx", String(configuration.clientRxBytesPerSec)),
            ("hysteria-padding", HysteriaProtocol.randomPaddingString()),
            ("content-length", "0"),
        ]
        let frame = HysteriaHTTP3Codec.encodeAuthRequestFrame(
            authority: "hysteria", path: "/auth", extraHeaders: extraHeaders
        )
        quic.writeStreamOnQueue(sid, data: frame)
        return true
    }

    private static func parseNextHTTP3Frame(_ buffer: Data) -> (type: UInt64, payload: Data, consumed: Int)? {
        guard let (frameType, typeLen) = HysteriaProtocol.decodeVarInt(from: buffer, offset: 0) else { return nil }
        guard let (payloadLen, lenBytes) = HysteriaProtocol.decodeVarInt(from: buffer, offset: typeLen) else { return nil }
        let headerLen = typeLen + lenBytes
        let total = headerLen + Int(payloadLen)
        guard buffer.count >= total else { return nil }
        let base = buffer.startIndex
        let payload = buffer[(base + headerLen)..<(base + total)]
        return (frameType, payload, total)
    }

    private static func clientSettingsFrame() -> Data {
        // id=0x01 (QPACK_MAX_TABLE_CAPACITY) val=0,
        // id=0x07 (QPACK_BLOCKED_STREAMS) val=0.
        let payload = Data([0x01, 0x00, 0x07, 0x00])
        var frame = Data()
        frame.append(0x04)                  // type = SETTINGS (1-byte varint)
        frame.append(UInt8(payload.count))  // len   (1-byte varint)
        frame.append(payload)
        return frame
    }

    // MARK: - Stream dispatch

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        enum Route { case auth; case tcp(HysteriaConnection); case serverReject(first: Bool); case ignore }
        let route: Route = state.withLock { session in
            if sid == session.authStreamID { return .auth }
            if let connection = session.tcpStreams[sid] { return .tcp(connection) }
            // Server-initiated stream (uni or bidi): reject it once so it stops streaming garbage.
            if (sid & 0x01) == 0x01, !data.isEmpty {
                return .serverReject(first: session.rejectedServerStreams.insert(sid).inserted)
            }
            return .ignore
        }

        switch route {
        case .auth:
            handleAuthStreamData(data, fin: fin)
        case .tcp(let connection):
            connection.feedStreamData(data, fin: fin)
        case .serverReject(let first):
            quic.extendStreamOffset(sid, count: data.count)
            if first {
                quic.shutdownStream(sid, appErrorCode: HysteriaProtocol.closeErrCodeProtocolError)
            }
        case .ignore:
            break
        }
    }

    private enum AuthOutcome {
        case needMore
        case fail(Error)
        case ready(brutal: BrutalAction?, authStreamID: Int64)
    }
    private enum BrutalAction { case uninstall; case setBandwidth(UInt64) }

    private func handleAuthStreamData(_ data: Data, fin: Bool) {
        var creditStreamID: Int64 = -1
        let outcome: AuthOutcome = state.withLock { session in
            creditStreamID = session.authStreamID

            guard session.phase == .authenticating else { return .needMore }
            guard !session.authHeadersReceived else { return .needMore }

            session.authBuffer.append(data)
            if session.authBuffer.count > Self.authBufferMaxBytes {
                return .fail(AnywhereError.proxy(.hysteria, .connectionClosed(detail:
                    "Auth response exceeded \(Self.authBufferMaxBytes)-byte buffer cap"
                )))
            }

            guard let (frameType, payload, consumed) = Self.parseNextHTTP3Frame(session.authBuffer) else {
                if fin {
                    return .fail(AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Auth stream ended before HEADERS frame")))
                }
                return .needMore
            }
            session.authBuffer = Data(session.authBuffer.dropFirst(consumed))

            guard frameType == 0x01 else {
                return .fail(AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Auth response wasn't HEADERS")))
            }
            guard let headers = HysteriaHTTP3Codec.decodeHeaderBlock(payload) else {
                return .fail(AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Malformed auth QPACK block")))
            }

            session.authHeadersReceived = true

            let status = headers.first(where: { $0.name == ":status" })?.value
            guard let statusStr = status, let code = Int(statusStr) else {
                return .fail(AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Missing :status on auth response")))
            }
            if code != HysteriaProtocol.authSuccessStatus {
                return .fail(AnywhereError.proxy(.hysteria, .authenticationRejected(status: code, detail: nil)))
            }

            session.udpSupported = (headers.first(where: { $0.name == "hysteria-udp" })?.value).map {
                $0.lowercased() == "true"
            } ?? false

            var brutal: BrutalAction? = nil
            if configuration.congestionControl == .brutal {
                let ccRxValue = headers.first(where: { $0.name == "hysteria-cc-rx" })?.value ?? ""
                let serverRxAuto = ccRxValue.lowercased() == "auto"
                session.serverRxBytesPerSec = serverRxAuto ? 0 : (UInt64(ccRxValue) ?? 0)

                if serverRxAuto {
                    brutal = .uninstall
                } else {
                    let clientTxBps = configuration.uploadBytesPerSec
                    let effectiveTxBps: UInt64 = session.serverRxBytesPerSec == 0
                        ? clientTxBps
                        : min(session.serverRxBytesPerSec, clientTxBps)
                    brutal = effectiveTxBps == 0 ? .uninstall : .setBandwidth(effectiveTxBps)
                }
            }

            guard session.transition(to: .ready) else { return .needMore }
            return .ready(brutal: brutal, authStreamID: session.authStreamID)
        }

        quic.extendStreamOffset(creditStreamID, count: data.count)

        switch outcome {
        case .needMore:
            break
        case .fail(let error):
            failSession(error)
        case .ready(let brutal, let authStreamID):
            switch brutal {
            case .uninstall: quic.uninstallBrutalCC()
            case .setBandwidth(let bps): quic.setBrutalBandwidth(bps)
            case nil: break
            }
            quic.shutdownStream(authStreamID, appErrorCode: HysteriaProtocol.closeErrCodeOK)
            readySignal.finish()
        }
    }

    private func handleStreamTermination(
        sid: Int64,
        error: Error?,
        cause: QUICConnection.StreamTerminationCause
    ) {
        enum Effect { case none; case failAuth(Error); case tcp(HysteriaConnection) }
        let effect: Effect = state.withLock { session in
            if sid == session.authStreamID {
                if session.phase != .ready {
                    return .failAuth(error ?? AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Auth stream closed before completion")))
                }
                return .none
            }
            if session.rejectedServerStreams.remove(sid) != nil { return .none }
            guard let connection = session.tcpStreams.removeValue(forKey: sid) else { return .none }
            return .tcp(connection)
        }

        switch effect {
        case .none:
            break
        case .failAuth(let error):
            failSession(error)
        case .tcp(let connection):
            updateIdleCloseTimer()
            connection.handleStreamTermination(error: error, cause: cause)
        }
    }

    // MARK: - Datagram dispatch

    private func handleDatagram(_ data: Data) {
        guard let message = HysteriaProtocol.decodeUDPMessage(data) else { return }
        let connection = state.withLock { $0.udpSessions[message.sessionID] }
        connection?.feedDatagram(message)
    }

    // MARK: - TCP stream API

    func openTCPStream(for connection: HysteriaConnection) async throws -> Int64 {
        enum Result { case notReady; case openFailed; case ok(Int64) }
        let result: Result = await quic.run {
            guard self.state.withLock({ $0.phase == .ready }) else { return .notReady }
            guard let sid = self.quic.openBidiStream() else { return .openFailed }
            let accepted: Bool = self.state.withLock { session in
                guard session.phase == .ready else { return false }
                session.tcpStreams[sid] = connection
                return true
            }
            guard accepted else {
                self.quic.shutdownStream(sid, appErrorCode: HysteriaProtocol.closeErrCodeOK)
                return .notReady
            }
            return .ok(sid)
        }
        switch result {
        case .notReady:
            throw AnywhereError.proxy(.hysteria, .notReady)
        case .openFailed:
            throw AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Failed to open TCP stream"))
        case .ok(let sid):
            updateIdleCloseTimer()
            return sid
        }
    }

    func writeStream(_ sid: Int64, data: Data) async throws {
        try await quic.writeStream(sid, data: data)
    }

    func extendStreamOffset(_ sid: Int64, count: Int) {
        quic.extendStreamOffset(sid, count: count)
    }

    func shutdownStream(_ sid: Int64, appErrorCode: UInt64 = HysteriaProtocol.closeErrCodeOK) {
        quic.shutdownStream(sid, appErrorCode: appErrorCode)
    }

    func releaseTCPStream(_ sid: Int64) {
        let removed = state.withLock { $0.tcpStreams.removeValue(forKey: sid) != nil }
        if removed {
            updateIdleCloseTimer()
        }
    }

    // MARK: - UDP session API

    func registerUDPSession(_ conn: HysteriaUDPConnection) async throws -> UInt32 {
        let sid: UInt32 = try state.withLock { session in
            guard session.phase == .ready else { throw AnywhereError.proxy(.hysteria, .notReady) }
            guard session.udpSupported else { throw AnywhereError.proxy(.hysteria, .unsupported(feature: "UDP")) }
            guard session.udpSessions.count < Int(UInt32.max) else {
                throw AnywhereError.proxy(.hysteria, .connectionClosed(detail: "UDP session pool exhausted"))
            }
            var sid = session.nextUDPSessionID
            while session.udpSessions[sid] != nil {
                sid = sid == UInt32.max ? 1 : sid + 1
            }
            session.nextUDPSessionID = sid == UInt32.max ? 1 : sid + 1
            session.udpSessions[sid] = conn
            return sid
        }
        updateIdleCloseTimer()
        return sid
    }

    func releaseUDPSession(_ sessionID: UInt32) {
        let removed = state.withLock { $0.udpSessions.removeValue(forKey: sessionID) != nil }
        if removed {
            updateIdleCloseTimer()
        }
    }

    private func updateIdleCloseTimer() {
        state.withLock { session in
            guard session.phase == .ready else {
                session.idleSince = nil
                return
            }
            let idle = session.tcpStreams.isEmpty && session.udpSessions.isEmpty
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
            readyError: AnywhereError.proxy(.hysteria, .streamClosed),
            connectionError: AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Session closed")),
            onlyIfIdle: true
        )
    }

    func writeDatagrams(_ datagrams: [Data]) async throws {
        try await quic.writeDatagrams(datagrams)
    }

    func currentMaxDatagramPayloadSize() async -> Int {
        await quic.currentMaxDatagramPayloadSize()
    }

    // MARK: - Close

    func close() {
        performTeardown(
            readyError: AnywhereError.proxy(.hysteria, .streamClosed),
            connectionError: AnywhereError.proxy(.hysteria, .connectionClosed(detail: "Session closed"))
        )
    }

    private func failSession(_ error: Error) {
        performTeardown(readyError: error, connectionError: error)
    }

    private func performTeardown(readyError: Error, connectionError: Error, onlyIfIdle: Bool = false) {
        struct Teardown {
            var tcp: [HysteriaConnection]
            var udp: [HysteriaUDPConnection]
            var idleSweepTask: Task<Void, Never>?
            var onClose: (@Sendable () -> Void)?
        }
        let teardown: Teardown? = state.withLock { session in
            if onlyIfIdle {
                guard session.phase == .ready, session.tcpStreams.isEmpty, session.udpSessions.isEmpty else {
                    return nil
                }
            }
            guard session.transition(to: .closed) else { return nil }
            let snapshot = Teardown(
                tcp: Array(session.tcpStreams.values),
                udp: Array(session.udpSessions.values),
                idleSweepTask: session.idleSweepTask,
                onClose: session.onClose
            )
            session.idleSweepTask = nil
            session.idleSince = nil
            session.tcpStreams.removeAll()
            session.udpSessions.removeAll()
            session.rejectedServerStreams.removeAll()
            session.onClose = nil
            return snapshot
        }
        guard let teardown else { return }

        teardown.idleSweepTask?.cancel()

        readySignal.finish(throwing: readyError)

        for connection in teardown.tcp { connection.handleSessionError(connectionError) }
        for connection in teardown.udp { connection.handleSessionError(connectionError) }

        quic.close()
        teardown.onClose?()
    }
}
