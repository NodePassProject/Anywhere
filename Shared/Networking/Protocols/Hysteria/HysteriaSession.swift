//
//  HysteriaSession.swift
//  Anywhere
//
//  Created by NodePassProject on 4/13/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "HysteriaSession")

// MARK: - Errors

nonisolated enum HysteriaError: Error, LocalizedError {
    case notReady
    case connectionFailed(String)
    case authRejected(statusCode: Int)
    case tunnelFailed(message: String)
    case streamClosed
    case udpNotSupported
    /// The Hysteria UDP header for this destination alone meets the peer's
    /// DATAGRAM ceiling. Permanent for the flow (fixed address), so callers
    /// tear it down instead of retrying.
    case destinationTooLargeForDatagram(maxFrame: Int, headerSize: Int)

    var errorDescription: String? {
        switch self {
        case .notReady: return "Hysteria session not ready"
        case .connectionFailed(let m): return "Hysteria connection failed: \(m)"
        case .authRejected(let c): return "Hysteria auth rejected (status \(c))"
        case .tunnelFailed(let m): return "Hysteria tunnel failed: \(m)"
        case .streamClosed: return "Hysteria stream closed"
        case .udpNotSupported: return "Hysteria server does not support UDP"
        case .destinationTooLargeForDatagram(let frame, let header):
            return "Hysteria destination too large for DATAGRAM (peer max \(frame) ≤ header \(header))"
        }
    }
}

// MARK: - HysteriaSession

nonisolated final class HysteriaSession {

    enum State { case idle, connecting, authenticating, ready, closed }

    private let quic: QUICConnection
    private let configuration: HysteriaConfiguration

    var queue: DispatchQueue { quic.queue }
    var isOnQueue: Bool { quic.isOnQueue }

    /// Runs `body` on the ngtcp2 queue and awaits its result (forwards the bridge hop), so
    /// this session's connections stay free of raw `queue.async`+continuation.
    func run<T>(_ body: @escaping () -> T) async -> T { await quic.run(body) }
    func run<T>(_ body: @escaping () -> Result<T, Error>) async throws -> T { try await quic.run(body) }

    private var state: State = .idle

    /// Once-only gate shared by `close()` and `failSession`; terminal teardown runs exactly once.
    private var closed = false

    /// Bidi stream used for the one-shot auth POST.
    private var authStreamID: Int64 = -1
    private var authBuffer = Data()
    private var authHeadersReceived = false
    /// Ceiling on `authBuffer` growth; ~3× the largest legitimate auth
    /// response (one HEADERS frame plus padding ≤ `maxPaddingLength`), so
    /// anything bigger is a misbehaving server — tear down rather than OOM.
    private static let authBufferMaxBytes = 16 * 1024

    /// Awaiters coalesced behind one connect+auth; resolved when the session reaches `.ready`
    /// or terminates. The waiter continuations live in the gate (async infra), not here.
    private let readyGate = AsyncReadinessGate()

    /// Fired once when the session transitions to `.closed`.
    var onClose: (() -> Void)?

    private var tcpStreams: [Int64: HysteriaConnection] = [:]

    /// Server-initiated streams already rejected via STOP_SENDING/RESET_STREAM,
    /// so chunks arriving before the peer's reset don't re-trigger `shutdownStream`.
    private var rejectedServerStreams: Set<Int64> = []

    private var udpSessions: [UInt32: HysteriaUDPConnection] = [:]
    private var nextUDPSessionID: UInt32 = 1

    /// Pending idle close; without it the QUIC connection (socket, ngtcp2
    /// state, keep-alive PING) stays resident forever after the last consumer
    /// goes away. Accessed only on `queue`.
    private var idleCloseTask: Task<Void, Never>?
    /// Idle window before self-close; 60 s frees resources promptly yet
    /// survives back-to-back UDP queries.
    private static let idleCloseDelay: TimeInterval = 60

    private(set) var udpSupported = false
    private(set) var serverRxBytesPerSec: UInt64 = 0

    // MARK: Pool-visible state (accessed without the queue)

    /// Read and written only inside `_poolState.withLock`; a lock-free read
    /// of a locked `Bool` write is a data race under Swift's memory model.
    private struct PoolState {
        var isClosed = false
        var tcpCount = 0
        var udpCount = 0
    }
    private let _poolState = Mutex(PoolState())

    var isClosed: Bool {
        _poolState.withLock { $0.isClosed }
    }

    var hasActiveConnections: Bool {
        _poolState.withLock { $0.tcpCount > 0 || $0.udpCount > 0 }
    }

    // MARK: - Init

    /// - Parameter transport: Optional UDP-relay transport for chained Hysteria; QUIC rides it instead of the direct UDP carrier.
    init(configuration: HysteriaConfiguration, transport: QUICDatagramTransport? = nil) {
        self.configuration = configuration
        // Obfuscation applies on both carriers, so build it regardless of `transport`.
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
    }

    // MARK: - Lifecycle

    func ensureReady() async throws {
        // Kick off connect+auth exactly once, on the ngtcp2 queue; the gate resolves it.
        await quic.run { [self] in
            guard state == .idle else { return }
            state = .connecting
            startConnection()
        }
        // Resolves on `.ready` (success) or teardown (`.streamClosed` retryable / real error).
        try await readyGate.wait()
    }

    private func startConnection() {
        QUICCrypto.registerCallbacks()

        quic.connectionClosedHandler = { [weak self] error in
            self?.failSession(error)
        }
        
        Task { [weak self] in
            guard let self else { return }
            do {
                try await quic.connect()
            } catch {
                await quic.run { self.failSession(error) }
                return
            }
            await quic.run { [self] in
                self.quic.streamDataHandler = { [weak self] sid, data, fin in
                    self?.handleStreamData(sid: sid, data: data, fin: fin)
                }
                self.quic.streamTerminationHandler = { [weak self] sid, error in
                    self?.handleStreamTermination(sid: sid, error: error)
                }
                self.quic.datagramHandler = { [weak self] data in
                    self?.handleDatagram(data)
                }

                self.openHTTP3Control()
                self.sendAuthRequest()
                self.state = .authenticating
            }
        }
    }

    private func openHTTP3Control() {
        // RFC 9114 §6.2: a control stream with SETTINGS is mandatory;
        // a strict HTTP/3 server would otherwise close the connection.
        if let sid = quic.openUniStream() {
            var payload = Data()
            payload.append(0x00) // stream type = control
            payload.append(Self.clientSettingsFrame())
            quic.writeStreamOnQueue(sid, data: payload)
        }
        // QPACK encoder (0x02) / decoder (0x03) uni streams; dynamic table
        // is 0, so they carry only the type byte.
        if let encoderStreamID = quic.openUniStream() {
            quic.writeStreamOnQueue(encoderStreamID, data: Data([0x02]))
        }
        if let decoderStreamID = quic.openUniStream() {
            quic.writeStreamOnQueue(decoderStreamID, data: Data([0x03]))
        }
    }

    /// Parses one HTTP/3 frame off the front of `buffer`, or nil if incomplete.
    /// The payload is a zero-copy slice of `buffer`.
    private func parseNextHTTP3Frame(_ buffer: Data) -> (type: UInt64, payload: Data, consumed: Int)? {
        guard let (frameType, typeLen) = HysteriaProtocol.decodeVarInt(from: buffer, offset: 0) else { return nil }
        guard let (payloadLen, lenBytes) = HysteriaProtocol.decodeVarInt(from: buffer, offset: typeLen) else { return nil }
        let headerLen = typeLen + lenBytes
        let total = headerLen + Int(payloadLen)
        guard buffer.count >= total else { return nil }
        let base = buffer.startIndex
        let payload = buffer[(base + headerLen)..<(base + total)]
        return (frameType, payload, total)
    }

    /// HTTP/3 SETTINGS frame with QPACK dynamic table disabled.
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

    private func sendAuthRequest() {
        guard let sid = quic.openBidiStream() else {
            failSession(HysteriaError.connectionFailed("Failed to open auth stream"))
            return
        }
        authStreamID = sid

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
    }

    // MARK: - Stream dispatch

    private func handleStreamData(sid: Int64, data: Data, fin: Bool) {
        if sid == authStreamID {
            handleAuthStreamData(data, fin: fin)
            return
        }

        if let connection = tcpStreams[sid] {
            connection.handleStreamData(data, fin: fin)
            return
        }

        // Server-initiated stream (uni or bidi). Credit flow control so a
        // misbehaving peer can't pin the connection window to zero, then
        // reject the stream once so it stops streaming garbage.
        if (sid & 0x01) == 0x01, !data.isEmpty {
            quic.extendStreamOffset(sid, count: data.count)
            if rejectedServerStreams.insert(sid).inserted {
                quic.shutdownStream(sid, appErrorCode: HysteriaProtocol.closeErrCodeProtocolError)
            }
        }
    }

    private func handleAuthStreamData(_ data: Data, fin: Bool) {
        // Credit flow control even for post-auth drain bytes.
        quic.extendStreamOffset(authStreamID, count: data.count)

        // Don't buffer post-auth bytes; they could trip the buffer cap.
        if authHeadersReceived { return }

        authBuffer.append(data)

        if authBuffer.count > Self.authBufferMaxBytes {
            failSession(HysteriaError.connectionFailed(
                "Auth response exceeded \(Self.authBufferMaxBytes)-byte buffer cap"
            ))
            return
        }

        guard let (frameType, payload, consumed) = parseNextHTTP3Frame(authBuffer) else {
            // FIN before a parseable HEADERS frame — fail fast instead of
            // waiting for the QUIC idle timeout.
            if fin {
                failSession(HysteriaError.connectionFailed(
                    "Auth stream ended before HEADERS frame"
                ))
            }
            return
        }
        authBuffer = Data(authBuffer.dropFirst(consumed))

        guard frameType == 0x01 else {
            failSession(HysteriaError.connectionFailed("Auth response wasn't HEADERS"))
            return
        }
        guard let headers = HysteriaHTTP3Codec.decodeHeaderBlock(payload) else {
            failSession(HysteriaError.connectionFailed("Malformed auth QPACK block"))
            return
        }

        authHeadersReceived = true

        let status = headers.first(where: { $0.name == ":status" })?.value
        guard let statusStr = status, let code = Int(statusStr) else {
            failSession(HysteriaError.connectionFailed("Missing :status on auth response"))
            return
        }
        if code != HysteriaProtocol.authSuccessStatus {
            failSession(HysteriaError.authRejected(statusCode: code))
            return
        }

        udpSupported = (headers.first(where: { $0.name == "hysteria-udp" })?.value).map {
            $0.lowercased() == "true"
        } ?? false
        // The server's CC-RX only caps our send rate under Brutal; BBR paces itself.
        if configuration.congestionControl == .brutal {
            let ccRxValue = headers.first(where: { $0.name == "hysteria-cc-rx" })?.value ?? ""
            // "auto" asks the client to self-pace. ngtcp2 here lacks
            // BBR-with-pacing, so uninstall Brutal and let native CUBIC drive.
            // Any other value (including unparseable/missing) means 0 = no cap.
            let serverRxAuto = ccRxValue.lowercased() == "auto"
            serverRxBytesPerSec = serverRxAuto ? 0 : (UInt64(ccRxValue) ?? 0)

            if serverRxAuto {
                quic.uninstallBrutalCC()
            } else {
                // Brutal tx = min(server_rx, client_max_tx); 0 means no cap
                // on either side (client 0 leaves CUBIC driving).
                let clientTxBps = configuration.uploadBytesPerSec
                let effectiveTxBps: UInt64 = serverRxBytesPerSec == 0
                    ? clientTxBps
                    : min(serverRxBytesPerSec, clientTxBps)
                quic.setBrutalBandwidth(effectiveTxBps)
            }
        }

        quic.shutdownStream(authStreamID, appErrorCode: HysteriaProtocol.closeErrCodeOK)

        state = .ready
        readyGate.signalSuccess()
    }

    private func handleStreamTermination(sid: Int64, error: Error?) {
        if sid == authStreamID {
            // Pre-ready: server aborted auth — fail fast. Post-ready: our
            // own STOP_SENDING reflecting back — absorb silently.
            if state != .ready {
                failSession(error ?? HysteriaError.connectionFailed(
                    "Auth stream closed before completion"
                ))
            }
            return
        }
        if rejectedServerStreams.remove(sid) != nil { return }
        guard let connection = tcpStreams.removeValue(forKey: sid) else { return }
        _poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
        updateIdleCloseTimer()
        connection.handleStreamTermination(error: error)
    }

    // MARK: - Datagram dispatch (UDP)

    private func handleDatagram(_ data: Data) {
        guard let message = HysteriaProtocol.decodeUDPMessage(data) else { return }
        if let connection = udpSessions[message.sessionID] {
            connection.handleIncomingDatagram(message)
        }
        // Unknown sessions drop silently; Hysteria has no UDP teardown handshake.
    }

    // MARK: - TCP stream API (called by HysteriaConnection)

    func openTCPStream(for connection: HysteriaConnection) async throws -> Int64 {
        try await quic.run { [self] () -> Result<Int64, Error> in
            guard state == .ready else { return .failure(HysteriaError.notReady) }
            guard let sid = quic.openBidiStream() else {
                return .failure(HysteriaError.connectionFailed("Failed to open TCP stream"))
            }
            tcpStreams[sid] = connection
            _poolState.withLock { $0.tcpCount += 1 }
            updateIdleCloseTimer()
            return .success(sid)
        }
    }

    /// Async stream write, over the QUIC ngtcp2-boundary continuation.
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
        queue.async { [weak self] in
            guard let self else { return }
            if self.tcpStreams.removeValue(forKey: sid) != nil {
                self._poolState.withLock { $0.tcpCount = max(0, $0.tcpCount - 1) }
                self.updateIdleCloseTimer()
            }
        }
    }

    // MARK: - UDP session API (called by HysteriaUDPConnection)

    func registerUDPSession(_ conn: HysteriaUDPConnection) async throws -> UInt32 {
        try await quic.run { [self] () -> Result<UInt32, Error> in
            guard state == .ready else { return .failure(HysteriaError.notReady) }
            guard udpSupported else { return .failure(HysteriaError.udpNotSupported) }
            guard udpSessions.count < Int(UInt32.max) else {
                return .failure(HysteriaError.connectionFailed("UDP session pool exhausted"))
            }
            var sid = nextUDPSessionID
            while udpSessions[sid] != nil {
                sid = sid == UInt32.max ? 1 : sid + 1
            }
            nextUDPSessionID = sid == UInt32.max ? 1 : sid + 1
            udpSessions[sid] = conn
            _poolState.withLock { $0.udpCount += 1 }
            updateIdleCloseTimer()
            return .success(sid)
        }
    }

    func releaseUDPSession(_ sessionID: UInt32) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.udpSessions.removeValue(forKey: sessionID) != nil {
                self._poolState.withLock { $0.udpCount = max(0, $0.udpCount - 1) }
                self.updateIdleCloseTimer()
            }
        }
    }

    /// Called on `queue`. Re-checks counts at fire time so a rapid
    /// release-then-open cycle doesn't tear the connection down.
    private func updateIdleCloseTimer() {
        idleCloseTask?.cancel()
        idleCloseTask = nil

        guard state == .ready else { return }
        let total = _poolState.withLock { $0.tcpCount + $0.udpCount }
        guard total == 0 else { return }

        // Fires on `queue` (hopped back on) so the re-check and close stay serialized with session state.
        idleCloseTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.idleCloseDelay))
            guard !Task.isCancelled, let self else { return }
            self.queue.async {
                let liveCount = self._poolState.withLock { $0.tcpCount + $0.udpCount }
                guard liveCount == 0, self.state == .ready else { return }
                self.close()
            }
        }
    }

    /// Async DATAGRAM batch write, over the QUIC ngtcp2-boundary continuation.
    func writeDatagrams(_ datagrams: [Data]) async throws {
        try await quic.writeDatagrams(datagrams)
    }

    var maxDatagramPayloadSize: Int {
        quic.maxDatagramPayloadSize
    }

    /// Async reader for the path-MTU-bounded datagram payload size (hops onto `queue`).
    func currentMaxDatagramPayloadSize() async -> Int {
        await quic.currentMaxDatagramPayloadSize()
    }

    // MARK: - Close

    func close() {
        // Strong `self`: an off-queue caller may hold the last reference;
        // weak could dealloc before the block runs, leaking the socket.
        let work = {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed

            self.idleCloseTask?.cancel()
            self.idleCloseTask = nil

            // Zero counters atomically with isClosed so hasActiveConnections
            // never reads true on a closed session.
            self._poolState.withLock { state in
                state.isClosed = true
                state.tcpCount = 0
                state.udpCount = 0
            }

            // `streamClosed` (not a connect failure) so a racing acquire retries on a fresh session.
            self.readyGate.signalFailure(HysteriaError.streamClosed)

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(HysteriaError.connectionFailed("Session closed")) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(HysteriaError.connectionFailed("Session closed")) }

            self.rejectedServerStreams.removeAll()

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
        // Strong `self` and shared `closed` flag as in close(); first enqueue wins.
        queue.async {
            guard !self.closed else { return }
            self.closed = true
            self.state = .closed

            self.idleCloseTask?.cancel()
            self.idleCloseTask = nil

            self._poolState.withLock { state in
                state.isClosed = true
                state.tcpCount = 0
                state.udpCount = 0
            }

            self.readyGate.signalFailure(error)

            let tcp = Array(self.tcpStreams.values)
            self.tcpStreams.removeAll()
            for c in tcp { c.handleSessionError(error) }

            let udp = Array(self.udpSessions.values)
            self.udpSessions.removeAll()
            for c in udp { c.handleSessionError(error) }

            self.rejectedServerStreams.removeAll()

            self.quic.close()
            self.onClose?()
        }
    }
}
