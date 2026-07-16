//
//  MITMScriptHTTP2Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMScriptHTTP2")

// MARK: - Errors

enum MITMScriptHTTP2Error: Error, LocalizedError {
    case notReady
    case protocolError(String)
    case connectionClosed(String)
    case goaway
    case streamReset(UInt32)
    case requestHeadersTooLarge
    /// Sentinel: the TLS ALPN came back non-`h2`; retry over HTTP/1.1.
    case needsHTTP1Fallback

    var errorDescription: String? {
        switch self {
        case .notReady: return "HTTP/2 connection not ready"
        case .protocolError(let message): return "HTTP/2 protocol error: \(message)"
        case .connectionClosed(let message): return "HTTP/2 connection closed: \(message)"
        case .goaway: return "HTTP/2 GOAWAY received"
        case .streamReset(let sid): return "HTTP/2 stream \(sid) reset"
        case .requestHeadersTooLarge: return "HTTP/2 request header block exceeds one frame"
        case .needsHTTP1Fallback: return "origin did not negotiate HTTP/2"
        }
    }
}

// MARK: - MITMScriptHTTP2Connection

nonisolated final class MITMScriptHTTP2Connection: Multiplexer {

    // MARK: Phase

    enum Phase: Equatable {
        case idle
        case connecting
        /// Client preface + SETTINGS sent, awaiting the server's SETTINGS.
        case prefaceSent
        case ready
        /// GOAWAY received — existing streams finish, no new streams.
        case goingAway
        case closed
    }

    // MARK: Flow-control / SETTINGS profile

    /// Advertised per-stream receive window; also our SETTINGS_INITIAL_WINDOW_SIZE.
    private static let streamRecvWindow = 4 * 1024 * 1024
    /// Advertised connection receive window; sized to the client's 16 MiB global in-flight budget.
    private static let connectionRecvWindow = 16 * 1024 * 1024
    private static let maxFrameSize: UInt32 = 16_384
    private static let headerTableSize: UInt32 = 65_536
    /// Bounds a single decoded header list and the accumulated CONTINUATION block.
    private static let maxHeaderListSize = 262_144
    /// Keeps in-flight bodies bounded under the NE memory budget; beyond this the pool opens another connection.
    private static let ownMaxConcurrentStreams: UInt32 = 32

    private static let httpVersionDefaultWindow = 65_535
    private static let priorityFlag: UInt8 = 0x20
    private static let connectionPreface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
    private static let maxReceiveBufferSize = 2 * 1024 * 1024

    // MARK: Origin

    let host: String
    let port: UInt16
    let insecure: Bool

    // MARK: Serial state (behind `lock`)

    /// Guards all mutable connection + per-stream send-window state. Never held across a call into
    /// a stream, a transport send, or a continuation resume.
    private struct State {
        var phase: Phase = .idle

        var dialed: OutboundConnector.Dialed?
        var tlsClient: TLSClient?
        var connection: ProxyConnection?

        var streams: [UInt32: MITMScriptHTTP2Stream] = [:]
        /// Per-stream *send* flow-control window (bytes we may still send on that stream). Presence
        /// also tracks liveness — a removed/finished stream has no entry, so a build pass sees it gone.
        var sendWindows: [UInt32: Int] = [:]
        var nextStreamID: UInt32 = 1
        var maxConcurrentStreams: UInt32 = MITMScriptHTTP2Connection.ownMaxConcurrentStreams

        var connectionSendWindow = MITMScriptHTTP2Connection.httpVersionDefaultWindow
        var connectionRecvConsumed = 0
        var peerInitialWindowSize = MITMScriptHTTP2Connection.httpVersionDefaultWindow

        var receiveBuffer = Data()
        /// In-progress header block: the initiating HEADERS' flags + accumulated fragment (RFC 7540 §6.10).
        var pendingHeaders: (streamID: UInt32, flags: UInt8, block: Data)?

        /// Readiness awaiters coalesced behind one handshake; each resumes exactly once at `.ready`
        /// or on fail/close.
        var readyContinuations: [CheckedContinuation<Void, Error>] = []
        /// Send-side parks waiting on a WINDOW_UPDATE that re-opens flow control (or a stream/session end).
        var flowResumptions: [CheckedContinuation<Void, Never>] = []

        var negotiatedHTTP1 = false
    }
    private let lock = Mutex(State())

    /// Connection-scoped HPACK decoder; the dynamic table is shared across all streams (RFC 7541 §2.2).
    /// Touched only by the single read-loop task (setup → `ingest`), so it needs no separate lock.
    private let hpackDecoder = HPACKDecoder()

    /// Called when the connection becomes permanently unusable, so the pool can evict it.
    var onClose: (() -> Void)?
    /// Called once when the origin is discovered to be HTTP/1.1-only, so the pool can cache it.
    var onNegotiatedHTTP1: (() -> Void)?

    // MARK: Pool-visible snapshot (held in a Mutex, read off-lock by the pool)

    private struct PoolSnapshot {
        var state: Phase = .idle
        /// `streams.count + reserved`, so a slot claimed by an in-flight `perform` isn't lost to `refreshPoolSnapshot`.
        var streamCount = 0
        var reserved = 0
        var maxConcurrent: UInt32 = MITMScriptHTTP2Connection.ownMaxConcurrentStreams
    }
    private let poolSnapshot = Mutex(PoolSnapshot())

    // MARK: Init

    init(host: String, port: UInt16, insecure: Bool) {
        self.host = host
        self.port = port
        self.insecure = insecure
    }

    // MARK: - Multiplexer

    var isClosed: Bool { poolSnapshot.withLock { $0.state == .closed } }
    var activeStreamCount: Int { poolSnapshot.withLock { $0.streamCount } }
    var poolIsGoingAway: Bool { poolSnapshot.withLock { $0.state == .goingAway } }

    /// Atomically checks capacity and reserves a stream slot; accepts in-progress connections so a
    /// burst of requests coalesces behind one handshake. The caller MUST follow up with `perform`,
    /// which releases the reservation exactly once.
    func tryReserveStream() -> Bool {
        poolSnapshot.withLock { snapshot in
            switch snapshot.state {
            case .idle, .connecting, .prefaceSent, .ready: break
            case .goingAway, .closed: return false
            }
            guard snapshot.streamCount < Int(snapshot.maxConcurrent) else { return false }
            snapshot.reserved += 1
            snapshot.streamCount += 1
            return true
        }
    }

    private func releaseReservation() {
        poolSnapshot.withLock { if $0.reserved > 0 { $0.reserved -= 1 } }
    }

    /// Republishes the pool-visible snapshot from the current state. Reads `lock` and writes
    /// `poolSnapshot` sequentially (never nested) so the two mutexes can't deadlock.
    private func refreshPoolSnapshot() {
        let (phase, count, maxConcurrent) = lock.withLock { ($0.phase, $0.streams.count, $0.maxConcurrentStreams) }
        poolSnapshot.withLock { snapshot in
            snapshot.state = phase
            snapshot.streamCount = count + snapshot.reserved
            snapshot.maxConcurrent = maxConcurrent
        }
    }

    // MARK: - Request entry point

    /// Runs one request/response on a new stream. A reservation must already have been made by the
    /// pool (see `tryReserveStream`); this releases it exactly once.
    func perform(
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval
    ) async throws -> MITMScriptHTTPClient.Response {
        do {
            try await ensureReady()
        } catch {
            releaseReservation()
            refreshPoolSnapshot()
            throw error
        }

        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<MITMScriptHTTPClient.Response, Error>) in
            enum Start { case rejected(Error); case go(MITMScriptHTTP2Stream) }
            let outcome: Start = lock.withLock { state in
                guard state.phase != .closed else {
                    return .rejected(state.negotiatedHTTP1 ? MITMScriptHTTP2Error.needsHTTP1Fallback
                                                           : MITMScriptHTTP2Error.connectionClosed("connection closed"))
                }
                let sid = state.nextStreamID
                state.nextStreamID &+= 2   // client streams are odd (RFC 7540 §5.1.1)
                let stream = MITMScriptHTTP2Stream(
                    streamID: sid,
                    connection: self,
                    request: request,
                    hostHeader: hostHeader,
                    maxBytes: maxBytes,
                    resourceTimeout: resourceTimeout,
                    continuation: continuation
                )
                state.streams[sid] = stream
                state.sendWindows[sid] = state.peerInitialWindowSize
                return .go(stream)
            }

            releaseReservation()
            refreshPoolSnapshot()

            switch outcome {
            case .rejected(let error):
                continuation.resume(throwing: error)
            case .go(let stream):
                stream.start()
            }
        }
    }

    // MARK: - Setup

    /// Coalesces awaiters behind one handshake; resolves at `.ready` or on fail/close.
    private func ensureReady() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            enum Ready { case now; case park; case beginAndPark; case fail(Error) }
            let action: Ready = lock.withLock { state in
                switch state.phase {
                case .ready:
                    return .now
                case .idle:
                    state.readyContinuations.append(continuation)
                    state.phase = .connecting
                    return .beginAndPark
                case .connecting, .prefaceSent:
                    state.readyContinuations.append(continuation)
                    return .park
                case .goingAway, .closed:
                    return .fail(state.negotiatedHTTP1 ? MITMScriptHTTP2Error.needsHTTP1Fallback
                                                       : MITMScriptHTTP2Error.connectionClosed("connection closed"))
                }
            }
            switch action {
            case .now:
                continuation.resume()
            case .park:
                break
            case .beginAndPark:
                refreshPoolSnapshot()
                beginSetup()
            case .fail(let error):
                continuation.resume(throwing: error)
            }
        }
    }

    private func beginSetup() {
        Task { [weak self] in
            guard let self else { return }
            do {
                let dialed = try await OutboundConnector.dial(host: self.host, port: self.port)
                let proceed = self.lock.withLock { state -> Bool in
                    guard state.phase == .connecting else { return false }
                    state.dialed = dialed
                    return true
                }
                if proceed {
                    self.startTLS(dialed: dialed)
                } else {
                    // Closed mid-dial: drop the orphaned transport instead of leaking the socket.
                    dialed.connection.cancel()
                    await dialed.proxyClient?.cancel()
                }
            } catch {
                self.failSetup(error)
            }
        }
    }

    private func startTLS(dialed: OutboundConnector.Dialed) {
        let configuration = TLSConfiguration(serverName: host, alpn: ["h2", "http/1.1"], insecureSkipVerify: insecure)
        let client = TLSClient(configuration: configuration)
        lock.withLock { $0.tlsClient = client }
        Task { [weak self] in
            guard let self else { return }
            do {
                let tlsConnection = try await client.connect(overTunnel: dialed.connection)

                enum TLSOutcome { case stale; case http1; case proceed }
                let outcome: TLSOutcome = self.lock.withLock { state in
                    guard state.phase == .connecting else { return .stale }
                    guard client.negotiatedALPN == "h2" else {
                        // HTTP/1.1-only origin: cache it and fail waiters over to the HTTP/1.1 path —
                        // one live connection can't serve N concurrent HTTP/1.1 exchanges.
                        state.negotiatedHTTP1 = true
                        return .http1
                    }
                    state.connection = TLSProxyConnection(tlsConnection: tlsConnection)
                    return .proceed
                }

                switch outcome {
                case .stale:
                    break
                case .http1:
                    self.onNegotiatedHTTP1?()
                    self.failSetup(MITMScriptHTTP2Error.needsHTTP1Fallback)
                case .proceed:
                    self.sendConnectionPreface()
                }
            } catch {
                self.failSetup(error)
            }
        }
    }

    private func sendConnectionPreface() {
        let transport: ProxyConnection? = lock.withLock { $0.connection }
        guard let transport else { failSetup(MITMScriptHTTP2Error.notReady); return }

        var data = Data()
        data.append(Self.connectionPreface)
        data.append(NaiveHTTP2Framer.settingsFrame([
            (id: 0x1, value: Self.headerTableSize),
            (id: 0x2, value: 0),                                   // ENABLE_PUSH off
            (id: 0x3, value: Self.ownMaxConcurrentStreams),        // server-initiated streams (moot with push off)
            (id: 0x4, value: UInt32(Self.streamRecvWindow)),       // INITIAL_WINDOW_SIZE
            (id: 0x5, value: Self.maxFrameSize),
            (id: 0x6, value: UInt32(Self.maxHeaderListSize)),
        ]).serialized)
        let bump = UInt32(Self.connectionRecvWindow - Self.httpVersionDefaultWindow)
        data.append(NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: bump).serialized)

        let payload = data
        Task { [weak self] in
            let sendError: Error?
            do { try await transport.send(payload); sendError = nil }
            catch { sendError = error }
            guard let self else { return }

            if let sendError { self.failSetup(sendError); return }

            let started = self.lock.withLock { state -> Bool in
                guard state.phase == .connecting else { return false }
                state.phase = .prefaceSent
                return true
            }
            guard started else { return }
            self.refreshPoolSnapshot()
            self.startReadLoop()
        }
    }

    // MARK: - Read loop

    /// One persistent task that pulls transport bytes, appends to the receive buffer, and drains
    /// every complete frame each pass (replacing the former per-read recursive `Task` + `queue.async`).
    private func startReadLoop() {
        Task { [weak self] in
            while true {
                guard let self else { return }
                let transport: ProxyConnection? = self.lock.withLock { $0.phase != .closed ? $0.connection : nil }
                guard let transport else { return }

                let data: Data?
                do { data = try await transport.receive() }
                catch { self.handleSessionError(error); return }

                guard let data, !data.isEmpty else {
                    self.handleSessionError(MITMScriptHTTP2Error.connectionClosed("connection closed by peer"))
                    return
                }

                let overflow: Bool = self.lock.withLock { state in
                    guard state.phase != .closed else { return false }
                    state.receiveBuffer.append(data)
                    return state.receiveBuffer.count > Self.maxReceiveBufferSize
                }
                if overflow {
                    // The loop drains fully each pass, so this only trips if a single frame is absurd.
                    self.handleSessionError(MITMScriptHTTP2Error.protocolError("receive buffer exceeded \(Self.maxReceiveBufferSize) bytes"))
                    return
                }

                self.drainFrames()
                if self.lock.withLock({ $0.phase == .closed }) { return }
            }
        }
    }

    /// Pops and routes each complete frame from the receive buffer. Runs on the read-loop task, so
    /// frames are processed strictly one at a time; each `routeFrame` does its state work under
    /// `lock` and performs stream/transport effects with the lock released.
    private func drainFrames() {
        while true {
            let frame: NaiveHTTP2Frame? = lock.withLock { state in
                guard state.phase != .closed else { return nil }
                return NaiveHTTP2Framer.deserialize(from: &state.receiveBuffer)
            }
            guard let frame else { break }
            routeFrame(frame)
        }
        lock.withLock { state in
            if state.receiveBuffer.isEmpty { state.receiveBuffer = Data() }   // release backing store
        }
    }

    private func routeFrame(_ frame: NaiveHTTP2Frame) {
        // §6.10: an in-progress header block accepts only a CONTINUATION on the same stream.
        let pending: (streamID: UInt32, flags: UInt8, block: Data)? = lock.withLock { $0.pendingHeaders }
        if let pending {
            guard frame.type == .continuation, frame.streamID == pending.streamID else {
                connectionError("expected CONTINUATION on stream \(pending.streamID)")
                return
            }
            appendContinuation(frame)
            return
        }

        switch frame.type {
        case .settings:
            handleSettings(frame)
        case .ping:
            if !frame.hasFlag(NaiveHTTP2FrameFlags.ack) {
                sendControlFrame(NaiveHTTP2Framer.pingAckFrame(opaqueData: frame.payload))
            }
        case .goaway:
            handleGoaway(frame)
        case .windowUpdate:
            handleWindowUpdate(frame)
        case .headers:
            beginHeaders(frame)
        case .data:
            handleData(frame)
        case .rstStream:
            let stream: MITMScriptHTTP2Stream? = lock.withLock { state in
                guard let stream = state.streams[frame.streamID] else { return nil }
                state.streams.removeValue(forKey: stream.streamID)
                state.sendWindows.removeValue(forKey: stream.streamID)
                return stream
            }
            if let stream {
                refreshPoolSnapshot()
                let code = NaiveHTTP2Framer.parseRstStream(payload: frame.payload) ?? 0
                stream.handleReset(errorCode: code)
            }
        case .continuation:
            // CONTINUATION with no header block in progress is a connection error (§6.10).
            connectionError("unexpected CONTINUATION on stream \(frame.streamID)")
        }
    }

    // MARK: - HEADERS (connection-scoped decode)

    private func beginHeaders(_ frame: NaiveHTTP2Frame) {
        guard let fragment = strippedHeaderBlockFragment(frame) else {
            connectionError("malformed HEADERS framing")
            return
        }
        if frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
            completeHeaderBlock(streamID: frame.streamID, flags: frame.flags, block: fragment)
        } else {
            guard fragment.count <= Self.maxHeaderListSize else {
                connectionError("header block exceeds \(Self.maxHeaderListSize) bytes")
                return
            }
            lock.withLock { $0.pendingHeaders = (frame.streamID, frame.flags, fragment) }
        }
    }

    private func appendContinuation(_ frame: NaiveHTTP2Frame) {
        enum Step { case none; case overflow; case complete(streamID: UInt32, flags: UInt8, block: Data) }
        let step: Step = lock.withLock { state in
            guard var pending = state.pendingHeaders else { return .none }
            pending.block.append(frame.payload)
            guard pending.block.count <= Self.maxHeaderListSize else {
                return .overflow
            }
            if frame.hasFlag(NaiveHTTP2FrameFlags.endHeaders) {
                state.pendingHeaders = nil
                return .complete(streamID: pending.streamID, flags: pending.flags, block: pending.block)
            } else {
                state.pendingHeaders = pending
                return .none
            }
        }
        switch step {
        case .none:
            break
        case .overflow:
            connectionError("header block exceeds \(Self.maxHeaderListSize) bytes")
        case .complete(let streamID, let flags, let block):
            completeHeaderBlock(streamID: streamID, flags: flags, block: block)
        }
    }

    /// Decodes HPACK unconditionally, THEN routes the fields — never gate the decode on stream
    /// existence, or a finished/reset stream's HEADERS would desync the shared dynamic table.
    private func completeHeaderBlock(streamID: UInt32, flags: UInt8, block: Data) {
        // hpackDecoder is touched only here, on the single read-loop task, so it needs no lock.
        guard let decoded = hpackDecoder.decodeHeaders(from: block) else {
            // A failed decode leaves the dynamic table in an unknown state — connection-fatal.
            connectionError("HPACK decode failed")
            return
        }
        let endStream = (flags & NaiveHTTP2FrameFlags.endStream) != 0
        let stream: MITMScriptHTTP2Stream? = lock.withLock { $0.streams[streamID] }
        stream?.handleHeaders(fields: decoded.fields, endStream: endStream)
    }

    /// Removes leading pad-length + trailing padding (PADDED) and the 5 priority bytes (PRIORITY)
    /// so only the HPACK fragment reaches the decoder (RFC 7540 §6.2). Malformed framing → nil.
    private func strippedHeaderBlockFragment(_ frame: NaiveHTTP2Frame) -> Data? {
        var bytes = frame.payload[...]
        if frame.hasFlag(NaiveHTTP2FrameFlags.padded) {
            guard let padLength = bytes.first else { return nil }
            bytes = bytes.dropFirst()
            guard bytes.count >= Int(padLength) else { return nil }
            bytes = bytes.dropLast(Int(padLength))
        }
        if (frame.flags & Self.priorityFlag) != 0 {
            guard bytes.count >= 5 else { return nil }
            bytes = bytes.dropFirst(5)
        }
        return Data(bytes)
    }

    // MARK: - DATA (connection-scoped flow control)

    private func handleData(_ frame: NaiveHTTP2Frame) {
        let endStream = frame.hasFlag(NaiveHTTP2FrameFlags.endStream)
        let body = Self.unpaddedDataPayload(frame)

        // Credit the full payload (incl. padding) even for finished streams, or orphaned DATA
        // leaks connection flow-control credit until the whole connection stalls.
        let (windowUpdate, transport, stream): (NaiveHTTP2Frame?, ProxyConnection?, MITMScriptHTTP2Stream?) = lock.withLock { state in
            var update: NaiveHTTP2Frame?
            if frame.payload.count > 0 {
                state.connectionRecvConsumed += frame.payload.count
                if state.connectionRecvConsumed >= Self.connectionRecvWindow / 2 {
                    let increment = UInt32(state.connectionRecvConsumed)
                    state.connectionRecvConsumed = 0
                    update = NaiveHTTP2Framer.windowUpdateFrame(streamID: 0, increment: increment)
                }
            }
            return (update, state.connection, state.streams[frame.streamID])
        }
        if let windowUpdate, let transport {
            sendFrame(windowUpdate, on: transport)
        }
        stream?.handleData(body, fullPayloadCount: frame.payload.count, endStream: endStream)
    }

    /// Body payload with HTTP/2 DATA padding removed; flow control still counts the full payload.
    private static func unpaddedDataPayload(_ frame: NaiveHTTP2Frame) -> Data {
        guard frame.hasFlag(NaiveHTTP2FrameFlags.padded) else { return frame.payload }
        guard let padLength = frame.payload.first else { return Data() }
        let withoutPadByte = frame.payload.dropFirst()
        guard withoutPadByte.count >= Int(padLength) else { return Data(withoutPadByte) }
        return Data(withoutPadByte.dropLast(Int(padLength)))
    }

    // MARK: - Control-frame handlers

    private func handleSettings(_ frame: NaiveHTTP2Frame) {
        if frame.hasFlag(NaiveHTTP2FrameFlags.ack) { return }

        var readyToResume: [CheckedContinuation<Void, Error>] = []
        let transport: ProxyConnection? = lock.withLock { state in
            for (id, value) in NaiveHTTP2Framer.parseSettings(payload: frame.payload) {
                switch id {
                case 0x3: // MAX_CONCURRENT_STREAMS
                    state.maxConcurrentStreams = min(Self.ownMaxConcurrentStreams, value)
                case 0x4: // INITIAL_WINDOW_SIZE — adjusts every live stream's send window.
                    let delta = Int(value) - state.peerInitialWindowSize
                    state.peerInitialWindowSize = Int(value)
                    for sid in state.sendWindows.keys { state.sendWindows[sid]! += delta }
                default:
                    break
                }
            }
            if state.phase == .prefaceSent {
                state.phase = .ready
                readyToResume = state.readyContinuations
                state.readyContinuations.removeAll()
            }
            return state.connection
        }

        if let transport {
            sendFrame(NaiveHTTP2Framer.settingsAckFrame(), on: transport)
        }
        for continuation in readyToResume { continuation.resume() }
        refreshPoolSnapshot()
    }

    private func handleGoaway(_ frame: NaiveHTTP2Frame) {
        let parsed = NaiveHTTP2Framer.parseGoaway(payload: frame.payload)
        if let parsed {
            logger.warning("[MITMScriptHTTP2] GOAWAY lastStreamID=\(parsed.lastStreamID) errorCode=\(parsed.errorCode)")
        }

        var readyToFail: [CheckedContinuation<Void, Error>] = []
        var doomed: [MITMScriptHTTP2Stream] = []
        let closeNow: Bool = lock.withLock { state in
            let previous = state.phase
            state.phase = .goingAway
            if let parsed {
                // Streams above lastStreamID were never processed by the peer — fail them.
                for (id, stream) in state.streams where id > parsed.lastStreamID {
                    state.streams.removeValue(forKey: id)
                    state.sendWindows.removeValue(forKey: id)
                    doomed.append(stream)
                }
            }
            if previous == .connecting || previous == .prefaceSent {
                readyToFail = state.readyContinuations
                state.readyContinuations.removeAll()
            }
            return state.streams.isEmpty
        }

        refreshPoolSnapshot()
        for stream in doomed { stream.failFromSession(MITMScriptHTTP2Error.goaway) }
        for continuation in readyToFail { continuation.resume(throwing: MITMScriptHTTP2Error.goaway) }
        if closeNow { close(error: MITMScriptHTTP2Error.goaway) }
    }

    private func handleWindowUpdate(_ frame: NaiveHTTP2Frame) {
        guard let increment = NaiveHTTP2Framer.parseWindowUpdate(payload: frame.payload), increment > 0 else { return }

        enum Update { case ok; case overflow }
        var parks: [CheckedContinuation<Void, Never>] = []
        let result: Update = lock.withLock { state in
            if frame.streamID == 0 {
                let updated = state.connectionSendWindow + Int(increment)
                guard updated <= 0x7FFF_FFFF else { return .overflow }
                state.connectionSendWindow = updated
            } else if state.sendWindows[frame.streamID] != nil {
                state.sendWindows[frame.streamID]! += Int(increment)
            }
            // A re-opened window (connection- or stream-level) wakes parked sends; each re-checks its
            // own min(connection, stream) window before building more frames.
            parks = state.flowResumptions
            state.flowResumptions.removeAll()
            return .ok
        }
        switch result {
        case .overflow:
            connectionError("connection send window overflow")
        case .ok:
            for continuation in parks { continuation.resume() }
        }
    }

    /// Called by a finishing stream so a send parked on this connection's flow window unblocks and
    /// re-observes liveness/window.
    func wakeFlowParks() {
        let parks: [CheckedContinuation<Void, Never>] = lock.withLock { state in
            let parks = state.flowResumptions
            state.flowResumptions.removeAll()
            return parks
        }
        for continuation in parks { continuation.resume() }
    }

    // MARK: - Sending

    /// The header block must fit one frame; we don't emit CONTINUATION on the send side.
    func sendHeaders(streamID: UInt32, headerBlock: Data, endStream: Bool) async throws {
        guard headerBlock.count <= Int(Self.maxFrameSize) else {
            throw MITMScriptHTTP2Error.requestHeadersTooLarge
        }
        let frame = NaiveHTTP2Framer.headersFrame(streamID: streamID, headerBlock: headerBlock, endStream: endStream)
        let transport = try currentTransport()
        try await transport.send(frame.serialized)
    }

    /// One outcome of a flow-control-bounded frame-build pass, decided under `lock`.
    private enum DataSendStep {
        case notReady
        case streamGone(UInt32)
        case done
        case park
        case send(frame: Data, nextOffset: Int, isLast: Bool, transport: ProxyConnection)
    }

    /// Sends `data` as DATA frames, respecting connection + stream send windows and MAX_FRAME_SIZE.
    /// When the window is exhausted it parks on a continuation resumed by the next WINDOW_UPDATE
    /// (or a stream/session end), instead of the old 50 ms poll.
    func sendData(_ data: Data, on stream: MITMScriptHTTP2Stream, endStream: Bool) async throws {
        var offset = 0
        while true {
            let step = buildDataStep(data, on: stream, offset: offset, endStream: endStream)
            switch step {
            case .notReady:
                throw MITMScriptHTTP2Error.notReady
            case .streamGone(let sid):
                throw MITMScriptHTTP2Error.streamReset(sid)
            case .done:
                return
            case .park:
                await parkForFlow(stream: stream)
            case .send(let frame, let nextOffset, let isLast, let transport):
                try await transport.send(frame)
                if isLast { return }
                offset = nextOffset
            }
        }
    }

    /// Builds one DATA frame under the current flow window, debiting the connection- and stream-level
    /// windows atomically under `lock`.
    private func buildDataStep(_ data: Data, on stream: MITMScriptHTTP2Stream, offset: Int, endStream: Bool) -> DataSendStep {
        lock.withLock { state in
            guard state.phase == .ready || state.phase == .goingAway else { return .notReady }
            guard let streamSendWindow = state.sendWindows[stream.streamID] else { return .streamGone(stream.streamID) }
            guard let connection = state.connection else { return .notReady }

            if offset >= data.count {
                if endStream {
                    let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: Data(), endStream: true)
                    return .send(frame: frame.serialized, nextOffset: offset, isLast: true, transport: connection)
                }
                return .done
            }

            let maxByFlow = min(state.connectionSendWindow, streamSendWindow)
            let chunkSize = min(data.count - offset, min(NaiveHTTP2Framer.maxDataPayload, maxByFlow))
            guard chunkSize > 0 else { return .park }

            state.connectionSendWindow -= chunkSize
            state.sendWindows[stream.streamID]! -= chunkSize
            let start = data.startIndex + offset
            let chunk = data.subdata(in: start..<(start + chunkSize))
            let isLast = offset + chunkSize >= data.count
            let frame = NaiveHTTP2Framer.dataFrame(streamID: stream.streamID, payload: chunk, endStream: endStream && isLast)
            return .send(frame: frame.serialized, nextOffset: offset + chunkSize, isLast: isLast, transport: connection)
        }
    }

    /// Suspends until a WINDOW_UPDATE re-opens the send window, or the stream/session ends. Re-checks
    /// under `lock` before parking so a window re-open racing the caller isn't missed.
    private func parkForFlow(stream: MITMScriptHTTP2Stream) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let resumeNow: Bool = lock.withLock { state in
                if state.phase == .closed { return true }
                guard let streamSendWindow = state.sendWindows[stream.streamID] else { return true }
                if min(state.connectionSendWindow, streamSendWindow) > 0 { return true }
                state.flowResumptions.append(continuation)
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    /// Fire-and-forget control frame (SETTINGS ACK, PING ACK, WINDOW_UPDATE, RST_STREAM).
    func sendControlFrame(_ frame: NaiveHTTP2Frame) {
        let transport: ProxyConnection? = lock.withLock { $0.connection }
        guard let transport else { return }
        sendFrame(frame, on: transport)
    }

    /// Fire-and-forget send of one already-built frame on a captured transport.
    private func sendFrame(_ frame: NaiveHTTP2Frame, on transport: ProxyConnection) {
        let serialized = frame.serialized
        Task {
            do { try await transport.send(serialized) }
            catch { logger.debug("[MITMScriptHTTP2] control frame send failed: \(error.localizedDescription)") }
        }
    }

    private func currentTransport() throws -> ProxyConnection {
        guard let connection = lock.withLock({ $0.connection }) else {
            throw MITMScriptHTTP2Error.notReady
        }
        return connection
    }

    // MARK: - Stream teardown (called by streams)

    /// Called by a stream as it finishes. Sends RST_STREAM(CANCEL) when the stream is abandoned
    /// before END_STREAM (timeout, cap, cancel) so the peer reclaims its slot; never on a clean end.
    func removeStream(_ stream: MITMScriptHTTP2Stream, sendRST: Bool) {
        enum Outcome { case gone; case removed(rst: Bool, closeGoaway: Bool, transport: ProxyConnection?) }
        let outcome: Outcome = lock.withLock { state in
            guard state.streams.removeValue(forKey: stream.streamID) != nil else { return .gone }
            state.sendWindows.removeValue(forKey: stream.streamID)
            let rst = sendRST && (state.phase == .ready || state.phase == .goingAway)
            let closeGoaway = state.phase == .goingAway && state.streams.isEmpty
            return .removed(rst: rst, closeGoaway: closeGoaway, transport: state.connection)
        }
        guard case .removed(let rst, let closeGoaway, let transport) = outcome else { return }

        if rst, let transport {
            sendFrame(NaiveHTTP2Framer.rstStreamFrame(streamID: stream.streamID, errorCode: 0x8 /* CANCEL */), on: transport)
        }
        refreshPoolSnapshot()
        if closeGoaway {
            close(error: MITMScriptHTTP2Error.goaway)
        }
    }

    // MARK: - Errors / teardown

    private func connectionError(_ message: String) {
        logger.warning("[MITMScriptHTTP2] \(message)")
        handleSessionError(MITMScriptHTTP2Error.protocolError(message))
    }

    private func handleSessionError(_ error: Error) {
        teardown(reason: error)
    }

    private func failSetup(_ error: Error) {
        teardown(reason: error)
    }

    /// Central close/teardown: flips to `.closed`, tears down the transport, and fails every waiter
    /// and live stream. Idempotent.
    private func teardown(reason: Error) {
        var readyToFail: [CheckedContinuation<Void, Error>] = []
        var parks: [CheckedContinuation<Void, Never>] = []
        var victims: [MITMScriptHTTP2Stream] = []
        let proceed: Bool = lock.withLock { state in
            guard state.phase != .closed else { return false }
            state.phase = .closed
            readyToFail = state.readyContinuations
            state.readyContinuations.removeAll()
            parks = state.flowResumptions
            state.flowResumptions.removeAll()
            victims = Array(state.streams.values)
            state.streams.removeAll()
            state.sendWindows.removeAll()
            state.pendingHeaders = nil
            return true
        }
        guard proceed else { return }

        teardownTransport()
        for continuation in readyToFail { continuation.resume(throwing: reason) }
        for continuation in parks { continuation.resume() }
        refreshPoolSnapshot()
        for stream in victims { stream.failFromSession(reason) }
        onClose?()
    }

    /// The TLS wrapper, TLS client, and dialed proxy transport are separate objects —
    /// cancel all three or the pooled connection leaks a socket.
    private func teardownTransport() {
        let (connection, tlsClient, dialed): (ProxyConnection?, TLSClient?, OutboundConnector.Dialed?) = lock.withLock { state in
            let captured = (state.connection, state.tlsClient, state.dialed)
            state.connection = nil
            state.tlsClient = nil
            state.dialed = nil
            return captured
        }
        if let connection {
            connection.cancel()
        } else {
            dialed?.connection.cancel()   // TLS never wrapped it (setup failed early)
        }
        tlsClient?.cancel()
        dialed?.proxyClient?.cancel()
    }

    // MARK: - Multiplexer.close

    func close(error: Error?) {
        teardown(reason: error ?? MITMScriptHTTP2Error.connectionClosed("connection closed"))
    }
}
