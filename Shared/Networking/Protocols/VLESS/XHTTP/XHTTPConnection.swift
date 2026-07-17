//
//  XHTTPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "XHTTPConnection")

// MARK: - XHTTP Channel Role

/// A detached session pairs a `.downloadOnly` leg (GET) with an `.uploadOnly` leg (POSTs) sharing one session ID.
nonisolated enum XHTTPChannelRole {
    case combined
    case downloadOnly
    case uploadOnly
}

// MARK: - XHTTPConnection

nonisolated class XHTTPConnection: @unchecked Sendable {

    let configuration: XHTTPConfiguration
    let mode: XHTTPMode
    let sessionId: String

    // Download / stream-one transport.
    let download: any ByteTransport

    // Upload transport factory (packet-up and stream-up), async-native.
    let uploadConnectionFactory: (() async throws -> any ByteTransport)?

    var role: XHTTPChannelRole = .combined
    /// Upload leg owned by this download leg when detached; sends are delegated to it.
    var uploadChannel: XHTTPConnection?

    /// Non-nil when the transport is a pooled, shared xmux connection; teardown then
    /// releases the lease instead of closing the shared transport (others may still use it).
    var xmuxLease: XHTTPXMUXMultiplexerLease?

    // Packet-up: one POST at a time, no more often than `scMinPostsIntervalMs` apart. Each POST
    // links after the previous on this chain, so they run strictly one at a time (rate-limit wait
    // included) without a lock held across the `await`.
    let packetUpChain = SerialSendChain()

    // HTTP/2 state
    let useHTTP2: Bool
    /// Demuxes the byte transport into H2 frames (1:1 path); idle on H3/shared-H2 legs.
    let h2FrameReader: H2FrameReader

    /// Caps the H2 frame reader's buffer to bound memory growth.
    static let maxH2ReadBufferSize = 2_097_152

    // HTTP/2 multiplexing stream IDs (set at setup, read on the send/receive path; not `state`-guarded).
    var h2UploadStreamId: UInt32 = 3      // Fixed upload stream for stream-up
    /// Download (GET) stream id when reading H2 frames; set out of range on an
    /// `.uploadOnly` leg so its POST responses are drained, not delivered.
    var h2DownloadStreamId: UInt32 = 1

    // HTTP/3 state (modes multiplexed onto QUIC streams via HTTP3Multiplexer)
    var h3Multiplexer: HTTP3Multiplexer?

    var useHTTP3: Bool { h3Multiplexer != nil }

    // Pooled shared-H2 multiplexing state (xmux). When `sharedH2` is set, this session's
    // streams ride a shared connection instead of running its own 1:1 H2 framing.
    var sharedH2: XHTTPH2Multiplexer?

    var usesSharedH2: Bool { sharedH2 != nil }

    // MARK: - Guarded State

    /// All mutable per-connection state, guarded by the `state` mutex. Continuations parked here
    /// are always resumed *after* `withLock` returns, never while the lock is held.
    nonisolated struct State {
        // Upload transport, established at setup (packet-up and stream-up).
        var uploadTransport: (any ByteTransport)?

        var nextSeq: Int64 = 0
        var chunkedDecoder = ChunkedTransferDecoder()
        var downloadHeadersParsed = false
        var _isConnected = false

        /// Timestamp of the last packet-up POST, for `scMinPostsIntervalMs` rate limiting.
        var packetUpLastFlushTime: UInt64 = 0

        /// Leftover data after HTTP response headers.
        var headerBuffer = Data()

        // HTTP/2 flow-control & framing state
        var h2DataBuffer = Data()
        /// Connection-level send window (RFC 7540 §6.9); updated by WINDOW_UPDATE on stream 0 only.
        var h2PeerConnectionWindow: Int = 65535
        /// Send window for the active upload stream; updated by SETTINGS INITIAL_WINDOW_SIZE and stream WINDOW_UPDATE.
        var h2PeerStreamSendWindow: Int = 65535
        var h2PeerInitialWindowSize: Int = 65535
        var h2LocalWindowSize: Int = 4_194_304  // Match h2StreamWindowSize (4MB)
        var h2MaxFrameSize: Int = 16384
        var h2ResponseReceived = false
        var h2StreamClosed = false

        /// Sends blocked on flow control; the WINDOW_UPDATE handler resumes all, each re-checks its window.
        var h2FlowGate = H2FlowGate()
        /// Send windows for packet-up streams blocked on flow control, keyed by stream ID.
        var h2PacketStreamWindows: [UInt32: Int] = [:]

        /// Bytes received but not yet acknowledged via WINDOW_UPDATE (connection level).
        var h2ConnectionReceiveConsumed: Int = 0
        /// Bytes received but not yet acknowledged via WINDOW_UPDATE (stream level, download stream).
        var h2StreamReceiveConsumed: Int = 0

        /// Next stream ID for packet-up uploads.
        var h2NextPacketStreamId: UInt32 = 3

        // HTTP/3 streams
        /// Download stream: the GET response body, or the full-duplex stream in stream-one.
        var h3Download: XHTTPH3RequestStream?
        /// Persistent upload POST stream (stream-up only).
        var h3Upload: XHTTPH3RequestStream?
        var h3Closed = false

        // Pooled shared-H2 (xmux) streams
        /// GET download stream, or the full-duplex stream in stream-one.
        var sharedH2Download: XHTTPH2Stream?
        /// Persistent upload POST stream (stream-up only).
        var sharedH2Upload: XHTTPH2Stream?
    }

    let state = Mutex(State())

    var isConnected: Bool {
        let v = state.withLock { $0._isConnected }
        // Detached: healthy only while both legs are up.
        return v && (uploadChannel?.isConnected ?? true)
    }

    // MARK: - X-Padding

    /// Applies X-Padding to the raw HTTP request (Referer-based by default, obfs placements otherwise).
    func applyPadding(to request: inout String, forPath path: String) {
        let padding = configuration.generatePadding()

        if !configuration.xPaddingObfsMode {
            request += "Referer: https://\(configuration.host)\(path)?\(configuration.xPaddingKey)=\(padding)\r\n"
            return
        }

        switch configuration.xPaddingPlacement {
        case .header:
            request += "\(configuration.xPaddingHeader): \(padding)\r\n"
        case .queryInHeader:
            request += "\(configuration.xPaddingHeader): https://\(configuration.host)\(path)?\(configuration.xPaddingKey)=\(padding)\r\n"
        case .cookie:
            request += "Cookie: \(configuration.xPaddingKey)=\(padding)\r\n"
        case .query:
            // Appended to the URL in the request line.
            break
        default:
            break
        }
    }

    func pathWithQueryPadding(_ basePath: String) -> String {
        if configuration.xPaddingObfsMode && configuration.xPaddingPlacement == .query {
            let padding = configuration.generatePadding()
            return "\(basePath)?\(configuration.xPaddingKey)=\(padding)"
        }
        return basePath
    }

    // MARK: - Session/Seq Metadata

    func applySessionId(to request: inout String, path: inout String) {
        guard !sessionId.isEmpty else { return }
        let key = configuration.normalizedSessionKey
        switch configuration.sessionPlacement {
        case .path:
            path = appendToPath(path, sessionId)
        case .query:
            // Will be appended to URL
            break
        case .header:
            request += "\(key): \(sessionId)\r\n"
        case .cookie:
            request += "Cookie: \(key)=\(sessionId)\r\n"
        default:
            break
        }
    }

    func queryParamsForMeta(seq: Int64? = nil) -> String {
        var parts: [String] = []
        if !sessionId.isEmpty && configuration.sessionPlacement == .query {
            let key = configuration.normalizedSessionKey
            parts.append("\(key)=\(sessionId)")
        }
        if let seq, configuration.seqPlacement == .query {
            let key = configuration.normalizedSeqKey
            parts.append("\(key)=\(seq)")
        }
        return parts.joined(separator: "&")
    }

    func applySeq(to request: inout String, path: inout String, seq: Int64) {
        let key = configuration.normalizedSeqKey
        switch configuration.seqPlacement {
        case .path:
            path = appendToPath(path, "\(seq)")
        case .query:
            // Handled in queryParamsForMeta
            break
        case .header:
            request += "\(key): \(seq)\r\n"
        case .cookie:
            request += "Cookie: \(key)=\(seq)\r\n"
        default:
            break
        }
    }

    func appendToPath(_ path: String, _ segment: String) -> String {
        if path.hasSuffix("/") {
            return path + segment
        }
        return path + "/" + segment
    }

    // MARK: - Uplink Data Placement

    /// A packet-up payload fragment carried outside the request body under header/cookie placement.
    enum UplinkDataField {
        /// A distinct request header line: `name: value`.
        case header(name: String, value: String)
        /// A `name=value` pair to place in a Cookie header.
        case cookie(pair: String)
    }

    var uplinkDataIsNonBody: Bool {
        configuration.uplinkDataPlacement == .header || configuration.uplinkDataPlacement == .cookie
    }

    /// Splits a packet-up payload into header or cookie fields per `uplinkDataPlacement`:
    /// base64url (no padding), chunked by `uplinkChunkSize`, named `{key}-{i}` (header) or
    /// `{key}_{i}` (cookie). Empty array for body/auto placement or empty payload (stays in body).
    func uplinkDataFields(for payload: Data) -> [UplinkDataField] {
        guard uplinkDataIsNonBody else { return [] }
        let encoded = payload.base64URLEncodedString()
        guard !encoded.isEmpty else { return [] }
        let key = configuration.uplinkDataKey
        // base64url output is ASCII, so chunking by Character == chunking by byte.
        let characters = Array(encoded)
        let chunkSize = configuration.uplinkChunkSize > 0 ? configuration.uplinkChunkSize : characters.count
        var fields: [UplinkDataField] = []
        var start = 0
        var index = 0
        while start < characters.count {
            let end = min(start + chunkSize, characters.count)
            let chunk = String(characters[start..<end])
            switch configuration.uplinkDataPlacement {
            case .header: fields.append(.header(name: "\(key)-\(index)", value: chunk))
            case .cookie: fields.append(.cookie(pair: "\(key)_\(index)=\(chunk)"))
            default: break
            }
            start = end
            index += 1
        }
        return fields
    }

    func buildRequestLine(method: String, path: String, queryParts: [String]) -> String {
        var url = path
        var allQuery = queryParts.filter { !$0.isEmpty }
        // Config-level query: the part of the configured path after "?".
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            allQuery.insert(configQuery, at: 0)
        }
        if configuration.xPaddingObfsMode && configuration.xPaddingPlacement == .query {
            let padding = configuration.generatePadding()
            allQuery.append("\(configuration.xPaddingKey)=\(padding)")
        }
        if !allQuery.isEmpty {
            url += "?" + allQuery.joined(separator: "&")
        }
        return "\(method) \(url) HTTP/1.1\r\n"
    }

    // MARK: - Initializers

    init(download: any ByteTransport, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: (() async throws -> any ByteTransport)? = nil) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.useHTTP2 = useHTTP2
        self.uploadConnectionFactory = uploadConnectionFactory
        self.download = download
        self.h2FrameReader = H2FrameReader(maxBufferSize: Self.maxH2ReadBufferSize, receive: download.receive)
        state.withLock { $0._isConnected = true }
    }

    /// Over HTTP/3, byte I/O is multiplexed by the session, so the download closures are the no-op `.unused`.
    convenience init(h3Multiplexer: HTTP3Multiplexer, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String) {
        self.init(download: NullByteTransport(), configuration: configuration, mode: mode, sessionId: sessionId)
        self.h3Multiplexer = h3Multiplexer
    }

    /// Over a shared multiplexing H2 connection (xmux), streams are virtual, so the download
    /// closures are the no-op `.unused` and `useHTTP2` stays false (the shared path is used instead).
    convenience init(sharedH2: XHTTPH2Multiplexer, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String) {
        self.init(download: NullByteTransport(), configuration: configuration, mode: mode, sessionId: sessionId)
        self.sharedH2 = sharedH2
    }

    // MARK: - Setup

    /// Performs the initial HTTP handshake; detached sessions set up the download leg, then the upload leg.
    func performSetup() async throws {
        try await performLegSetup()
        if let uploadChannel {
            try await uploadChannel.performLegSetup()
        }
    }

    private func performLegSetup() async throws {
        if usesSharedH2 {
            try await performSharedH2Setup()
        } else if useHTTP3 {
            try await performH3Setup()
        } else if useHTTP2 {
            try await performH2Setup()
        } else {
            switch role {
            case .downloadOnly:
                try await performDownloadOnlyHTTP11Setup()
            case .uploadOnly:
                try await performUploadOnlyHTTP11Setup()
            case .combined:
                if mode == .streamOne {
                    try await performStreamOneSetup()
                } else if mode == .streamUp {
                    try await performStreamUpSetup()
                } else {
                    try await performPacketUpSetup()
                }
            }
        }
    }

    // MARK: - Send

    func send(_ data: Data) async throws {
        // Detached: writes go to the upload leg; this (download) leg only reads.
        if let uploadChannel {
            try await uploadChannel.send(data)
            return
        }
        if mode == .packetUp {
            try await sendPacketUp(data)
            return
        }
        if usesSharedH2 {
            // stream-up sends on the upload stream; stream-one on the full-duplex download stream.
            let stream = state.withLock { state in (mode == .streamUp) ? state.sharedH2Upload : state.sharedH2Download }
            guard let stream else { throw XHTTPError.connectionClosed }
            try await stream.sendData(data, endStream: false)
            return
        }
        if useHTTP3 {
            let stream = state.withLock { state in (mode == .streamUp) ? state.h3Upload : state.h3Download }
            guard let stream else { throw XHTTPError.connectionClosed }
            try await stream.sendBody(data, fin: false)
            return
        }
        if useHTTP2 {
            // stream-up sends on the upload stream; stream-one shares stream 1.
            try await sendH2Data(data: data, streamId: mode == .streamUp ? h2UploadStreamId : 1)
        } else if mode == .streamOne {
            try await sendStreamOne(data: data)
        } else if mode == .streamUp {
            try await sendStreamUp(data: data)
        }
    }

    // MARK: - Receive

    func receive() async throws -> Data? {
        if usesSharedH2 {
            guard let stream = state.withLock({ $0.sharedH2Download }) else { return nil }
            return try await stream.receive()
        }
        if useHTTP3 {
            return try await receiveH3Data()
        }
        if useHTTP2 {
            return try await receiveH2Data()
        }

        // HTTP/1.1 chunked download.
        enum ChunkedRead { case data(Data); case eof; case read }
        while true {
            let step: ChunkedRead = state.withLock { state in
                if let decoded = state.chunkedDecoder.nextChunk() { return .data(decoded) }
                if state.chunkedDecoder.isFinished { return .eof }
                return .read
            }
            switch step {
            case .data(let decoded): return decoded
            case .eof: return nil
            case .read: break
            }

            let chunk = try await download.receive()
            guard case .bytes(let data) = chunk, !data.isEmpty else {
                return nil // EOF
            }
            state.withLock { $0.chunkedDecoder.feed(data) }
        }
    }

    // MARK: - Cancel

    func cancel() {
        // `h3Multiplexer`/`xmuxLease` are set-once class properties read here inside the lock to
        // preserve the original critical section; the parked flow-control continuations are
        // resumed only after `withLock` returns.
        let teardown = state.withLock { state -> (
            h3Download: XHTTPH3RequestStream?,
            h3Upload: XHTTPH3RequestStream?,
            h3Session: HTTP3Multiplexer?,
            sharedH2Download: XHTTPH2Stream?,
            sharedH2Upload: XHTTPH2Stream?,
            lease: XHTTPXMUXMultiplexerLease?,
            upload: (any ByteTransport)?
        ) in
            state._isConnected = false
            state.chunkedDecoder = ChunkedTransferDecoder()
            state.headerBuffer.removeAll()
            h2FrameReader.reset()
            state.h2DataBuffer.removeAll()
            state.h2StreamClosed = true
            state.h3Closed = true
            let h3DownloadStream = state.h3Download
            let h3UploadStream = state.h3Upload
            let h3Session = h3Multiplexer
            let sharedH2DownloadStream = state.sharedH2Download
            let sharedH2UploadStream = state.sharedH2Upload
            state.sharedH2Download = nil
            state.sharedH2Upload = nil
            let lease = xmuxLease
            xmuxLease = nil
            let upload = state.uploadTransport
            state.uploadTransport = nil
            // Sends parked on H2 flow control wake here; each re-enters its send, sees the closed
            // stream, and completes with `.connectionClosed` rather than hanging forever.
            state.h2FlowGate.wakeAll()
            return (h3DownloadStream, h3UploadStream, h3Session,
                    sharedH2DownloadStream, sharedH2UploadStream, lease, upload)
        }

        download.cancel()
        teardown.upload?.cancel()
        teardown.h3Download?.close()
        teardown.h3Upload?.close()
        teardown.sharedH2Download?.close()
        teardown.sharedH2Upload?.close()
        if let lease = teardown.lease {
            // Pooled transport: keep it open for other/future sessions; just release our slot.
            lease.release()
        } else {
            teardown.h3Session?.close()
        }
        uploadChannel?.cancel()
    }

    // MARK: - Packet-Up

    /// Sends one packet-up payload as its own POST, serialized behind `packetUpMutex` and
    /// rate-limited to at most one POST per `scMinPostsIntervalMs`. The async send surface is
    /// single-writer, so payloads already arrive one at a time — the callback path's coalescing
    /// queue is unnecessary. HTTP/1.1 re-splits an oversized payload into back-to-back POSTs.
    private func sendPacketUp(_ data: Data) async throws {
        try await packetUpChain.run { [self] in
            let closed = state.withLock { state in
                !state._isConnected || (useHTTP2 && state.h2StreamClosed) || (useHTTP3 && state.h3Closed)
            }
            if closed { throw XHTTPError.connectionClosed }

            try await rateLimitPacketUp()

            if usesSharedH2 {
                try await sendSharedH2PacketUp(data: data)
            } else if useHTTP3 {
                try await sendH3PacketUp(data: data)
            } else if useHTTP2 {
                try await sendH2PacketUp(data: data)
            } else {
                try await sendPacketUpHTTP11(data: data)
            }
        }
    }

    /// Waits out the remainder of `scMinPostsIntervalMs` since the last POST, then stamps the clock.
    private func rateLimitPacketUp() async throws {
        let delayMs = configuration.scMinPostsIntervalMs
        if delayMs > 0 {
            let waitMs: Int = state.withLock { state in
                guard state.packetUpLastFlushTime != 0 else { return 0 }
                let elapsedNs = DispatchTime.now().uptimeNanoseconds &- state.packetUpLastFlushTime
                let elapsedMs = Int(min(elapsedNs / 1_000_000, UInt64(Int.max)))
                return elapsedMs >= delayMs ? 0 : delayMs - elapsedMs
            }
            if waitMs > 0 {
                try await Task.sleep(for: .milliseconds(waitMs))
            }
        }
        state.withLock { $0.packetUpLastFlushTime = DispatchTime.now().uptimeNanoseconds }
    }
}

// MARK: - XMUX Connection Pooling

/// A poolable underlying XHTTP transport that multiple XHTTP sessions can share
/// (a multiplexing H2 connection or an H3/QUIC session).
nonisolated protocol XHTTPXMUXMultiplexerPoolable: AnyObject {
    /// True once the connection can no longer carry new sessions.
    var isPoolClosed: Bool { get }
    /// Tears down the underlying connection once the pool retires it with no active leases.
    func poolClose()
}

/// A reserved slot on a pooled connection. The holder drives one XHTTP session over
/// `connection`, calls `noteRequest()` per HTTP request, and `release()` once when done.
nonisolated final class XHTTPXMUXMultiplexerLease {
    let connection: XHTTPXMUXMultiplexerPoolable
    private weak var manager: XHTTPXMUXMultiplexerManager?
    /// Strong so the connection outlives all its sessions, even after the pool retires it.
    private let client: XHTTPXMUXMultiplexerClient
    private let released = Mutex(false)

    init(connection: XHTTPXMUXMultiplexerPoolable, manager: XHTTPXMUXMultiplexerManager, client: XHTTPXMUXMultiplexerClient) {
        self.connection = connection
        self.manager = manager
        self.client = client
    }

    /// Decrements the connection's remaining-request budget (`hMaxRequestTimes`).
    func noteRequest() {
        manager?.noteRequest(client)
    }

    /// Releases this session's concurrency slot. Idempotent.
    func release() {
        let alreadyReleased: Bool = released.withLock { released in
            if released { return true }
            released = true
            return false
        }
        if alreadyReleased { return }
        manager?.releaseSlot(client)
    }
}

nonisolated final class XHTTPXMUXMultiplexerClient {
    enum State { case dialing, ready, failed }
    var state: State = .dialing
    var connection: XHTTPXMUXMultiplexerPoolable?
    /// Concurrent sessions currently leased on this connection.
    var openUsage = 0
    /// Remaining session assignments (`cMaxReuseTimes - 1`); -1 = unlimited.
    var leftUsage: Int
    /// Remaining HTTP requests (`hMaxRequestTimes`); `Int.max` = unlimited.
    var leftRequests: Int
    /// Wall-clock retirement time (`hMaxReusableSecs`); nil = never.
    let unreusableAt: CFAbsoluteTime?
    /// The in-flight dial for this connection, created by the leader under the pool lock. Every
    /// joiner awaits its value, so the coalescing needs no waiter array of continuations.
    var dialTask: Task<XHTTPXMUXMultiplexerPoolable?, Never>?

    init(leftUsage: Int, leftRequests: Int, unreusableAt: CFAbsoluteTime?) {
        self.leftUsage = leftUsage
        self.leftRequests = leftRequests
        self.unreusableAt = unreusableAt
    }

    /// Retired when failed, closed, out of reuses/requests, or past its lifetime.
    /// Caller holds the manager lock.
    func isRetired(now: CFAbsoluteTime) -> Bool {
        // Never retire mid-dial: pruning a dialing client would strand its waiters, whose
        // completions only fire when the dial resolves.
        if state == .dialing { return false }
        if state == .failed { return true }
        if connection?.isPoolClosed == true { return true }
        if leftUsage == 0 || leftRequests <= 0 { return true }
        if let unreusableAt, now > unreusableAt { return true }
        return false
    }
}

/// Intentionally not a ``MultiplexerPool`` subclass: XMUX reuse follows Xray's per-connection
/// retirement policy (`cMaxReuseTimes` / `hMaxRequestTimes` / `hMaxReusableSecs`, see
/// ``XHTTPXMUXMultiplexerClient/isRetired(now:)``) rather than the base's idle-age sweep.
/// All state is guarded by the `clients` mutex.
nonisolated final class XHTTPXMUXMultiplexerManager {
    private let config: XHTTPXMUXMultiplexerConfiguration
    /// `maxConcurrency` range rolled once at creation, fixed for the manager's lifetime.
    private let concurrency: Int
    /// `maxConnections` resolved once at creation.
    private let connections: Int
    /// Destination-bound dial: resolves to a fresh poolable connection, or nil on failure.
    private let newConnection: @Sendable () async -> XHTTPXMUXMultiplexerPoolable?
    private let clients = Mutex<[XHTTPXMUXMultiplexerClient]>([])

    fileprivate weak var registry: XHTTPXMUXMultiplexerRegistry?
    fileprivate var registryKey: String?

    init(config: XHTTPXMUXMultiplexerConfiguration, newConnection: @escaping @Sendable () async -> XHTTPXMUXMultiplexerPoolable?) {
        self.config = config
        self.concurrency = config.maxConcurrency.random()
        self.connections = config.maxConnections.random()
        self.newConnection = newConnection
    }

    /// Acquires a slot, reusing a pooled connection or dialing a new one per policy.
    /// Resolves to nil if a freshly-dialed connection fails.
    func acquire() async -> XHTTPXMUXMultiplexerLease? {
        let now = CFAbsoluteTimeGetCurrent()
        // Prune retired clients; tear down those with no active sessions left.
        var retiredIdle: [XHTTPXMUXMultiplexerPoolable] = []
        clients.withLock { clients in
            clients.removeAll { client in
                guard client.isRetired(now: now) else { return false }
                if client.openUsage == 0, let connection = client.connection { retiredIdle.append(connection) }
                return true
            }
        }
        for connection in retiredIdle { connection.poolClose() }

        // Decide under the lock: reuse a ready connection, join a still-dialing one, fail,
        // or lead a fresh dial. Any dial/await happens after the lock is released.
        enum Decision {
            case ready(XHTTPXMUXMultiplexerPoolable, XHTTPXMUXMultiplexerClient)
            case failed
            case join(XHTTPXMUXMultiplexerClient)
            case dial(XHTTPXMUXMultiplexerClient)
        }
        let decision: Decision = clients.withLock { clients in
            if let client = selectReusable(in: clients) {
                client.openUsage += 1
                if client.leftUsage > 0 { client.leftUsage -= 1 }
                switch client.state {
                case .ready:
                    return .ready(client.connection!, client)
                case .dialing:
                    // Share this still-dialing connection once its dial resolves.
                    return .join(client)
                case .failed:
                    return .failed
                }
            }

            // Policy requires a new pooled connection.
            let reuseRand = config.cMaxReuseTimes.random()
            let leftUsage = reuseRand > 0 ? reuseRand - 1 : -1
            let reqRand = config.hMaxRequestTimes.random()
            let leftRequests = reqRand > 0 ? reqRand : Int.max
            let secsRand = config.hMaxReusableSecs.random()
            let unreusableAt: CFAbsoluteTime? = secsRand > 0 ? now + Double(secsRand) : nil

            let client = XHTTPXMUXMultiplexerClient(leftUsage: leftUsage, leftRequests: leftRequests, unreusableAt: unreusableAt)
            client.openUsage = 1
            clients.append(client)
            // Create the memoized dial under the lock so a joiner deciding `.join` on this client
            // always finds `dialTask` set.
            client.dialTask = Task { [weak self] in await self?.performDial(for: client) ?? nil }
            return .dial(client)
        }

        switch decision {
        case .ready(let connection, let client):
            return makeLease(connection, client)
        case .failed:
            return nil
        case .dial(let client), .join(let client):
            // Leader and joiners both await the client's memoized dial task (the leader created it
            // under the lock in the decision above, so a joiner always finds it set).
            guard let connection = await client.dialTask?.value else { return nil }
            return makeLease(connection, client)
        }
    }

    /// The memoized dial body: dials a new pooled connection, resolves the client's state, and
    /// evicts an empty pool on failure. Its result is shared by the leader and every joiner via
    /// `client.dialTask.value`.
    private func performDial(for client: XHTTPXMUXMultiplexerClient) async -> XHTTPXMUXMultiplexerPoolable? {
        let connection = await newConnection()
        var drained = false
        clients.withLock { clients in
            if let connection {
                client.connection = connection
                client.state = .ready
            } else {
                client.state = .failed
                clients.removeAll { $0 === client }
                drained = clients.isEmpty
            }
        }
        // A failed first dial leaves an empty pool; evict the manager shell.
        if drained { registry?.evictIfEmpty(self) }
        return connection
    }

    /// Selects a reusable pooled connection (lock held); nil ⇒ dial a new connection.
    private func selectReusable(in clients: [XHTTPXMUXMultiplexerClient]) -> XHTTPXMUXMultiplexerClient? {
        if clients.isEmpty { return nil }
        if connections > 0 && clients.count < connections { return nil }
        let eligible = concurrency > 0 ? clients.filter { $0.openUsage < concurrency } : clients
        guard !eligible.isEmpty else { return nil }
        return eligible.randomElement()
    }

    private func makeLease(_ connection: XHTTPXMUXMultiplexerPoolable, _ client: XHTTPXMUXMultiplexerClient) -> XHTTPXMUXMultiplexerLease {
        XHTTPXMUXMultiplexerLease(connection: connection, manager: self, client: client)
    }

    func releaseSlot(_ client: XHTTPXMUXMultiplexerClient) {
        var shouldClose = false
        let drained: Bool = clients.withLock { clients in
            if client.openUsage > 0 { client.openUsage -= 1 }
            // A retired connection with no remaining sessions is dropped and torn down.
            shouldClose = client.openUsage == 0 && client.isRetired(now: CFAbsoluteTimeGetCurrent())
            if shouldClose { clients.removeAll { $0 === client } }
            return clients.isEmpty
        }
        if shouldClose { client.connection?.poolClose() }
        // Last session for this destination ended; ask the registry to drop the shell.
        if drained { registry?.evictIfEmpty(self) }
    }

    func noteRequest(_ client: XHTTPXMUXMultiplexerClient) {
        clients.withLock { _ in
            if client.leftRequests > 0 && client.leftRequests != Int.max { client.leftRequests -= 1 }
        }
    }

    fileprivate func hasNoClients() -> Bool {
        clients.withLock { $0.isEmpty }
    }

    /// Closes every pooled connection and empties the pool (called by the registry's `reclaim()`).
    func closeAll() {
        let pooledConnections: [XHTTPXMUXMultiplexerPoolable] = clients.withLock { clients in
            let pooled = clients.compactMap { $0.connection }
            clients.removeAll()
            return pooled
        }
        for connection in pooledConnections { connection.poolClose() }
    }
}

nonisolated final class XHTTPXMUXMultiplexerRegistry: Sendable {
    nonisolated static let shared = XHTTPXMUXMultiplexerRegistry()
    private let managers = Mutex<[String: XHTTPXMUXMultiplexerManager]>([:])
    private init() {}

    /// The factory is destination-bound and must not capture per-session/per-flow state.
    func manager(
        key: String,
        config: XHTTPXMUXMultiplexerConfiguration,
        makeFactory: () -> (@Sendable () async -> XHTTPXMUXMultiplexerPoolable?)
    ) -> XHTTPXMUXMultiplexerManager {
        // Built before taking the lock so the caller's factory closure never runs under it;
        // discarded unused when a manager already exists for this key.
        let factory = makeFactory()
        return managers.withLock { managers in
            if let existing = managers[key] { return existing }
            let manager = XHTTPXMUXMultiplexerManager(config: config, newConnection: factory)
            manager.registry = self
            manager.registryKey = key
            managers[key] = manager
            return manager
        }
    }

    /// Drops `manager` once its pool has fully drained, so an idle destination doesn't
    /// retain a manager shell (config + factory closure + key) for the process lifetime.
    fileprivate func evictIfEmpty(_ manager: XHTTPXMUXMultiplexerManager) {
        guard let key = manager.registryKey else { return }
        managers.withLock { managers in
            guard managers[key] === manager else { return }   // already replaced/removed
            if manager.hasNoClients() {
                managers.removeValue(forKey: key)
            }
        }
    }
}

extension XHTTPXMUXMultiplexerRegistry: TransportPool {
    /// Drops every pooled connection so XHTTP doesn't reuse a socket the kernel killed
    /// during sleep/path-change.
    func reclaim() {
        let allManagers: [XHTTPXMUXMultiplexerManager] = managers.withLock { managers in
            let all = Array(managers.values)
            managers.removeAll()
            return all
        }
        for manager in allManagers { manager.closeAll() }
    }
}

/// An HTTP/3 session can carry many XHTTP sessions as independent QUIC streams.
extension HTTP3Multiplexer: XHTTPXMUXMultiplexerPoolable {
    var isPoolClosed: Bool { isClosed }
    func poolClose() { close() }
}

// MARK: - Shared Multiplexing HTTP/2 Connection (xmux)
//
// Carries many XHTTP sessions as independent H2 streams over one socket. Gated behind
// xmux config; without xmux, sessions use the 1:1 H2 path (XHTTPConnection+H2*.swift).

/// All mutable state is guarded by the owning connection's lock.
nonisolated final class XHTTPH2Stream: @unchecked Sendable {
    let streamId: UInt32
    fileprivate weak var connection: XHTTPH2Multiplexer?

    fileprivate var receiveBuffer = Data()
    fileprivate var ended = false
    fileprivate var failure: Error?
    /// Single-flight receive gate: ``XHTTPH2Multiplexer/receive(stream:)`` enrolls a one-shot waiter
    /// here when there's nothing to hand back; any data/EOF/error path finishes it (under the
    /// connection lock) so the receiver re-checks. Replaces a stored `CheckedContinuation`.
    fileprivate var receiveWaiter: AsyncStream<Void>.Continuation?
    /// When true, inbound data is discarded (an upload leg's response).
    fileprivate var draining = false
    fileprivate var receiveConsumed = 0

    fileprivate var sendWindow: Int

    init(streamId: UInt32, connection: XHTTPH2Multiplexer, sendWindow: Int) {
        self.streamId = streamId
        self.connection = connection
        self.sendWindow = sendWindow
    }

    func sendHeaders(_ headerBlock: Data, endStream: Bool) async throws {
        guard let connection else { throw XHTTPError.connectionClosed }
        try await connection.sendHeaders(streamId: streamId, headerBlock: headerBlock, endStream: endStream)
    }

    func sendData(_ data: Data, endStream: Bool) async throws {
        guard let connection else { throw XHTTPError.connectionClosed }
        try await connection.sendData(stream: self, data: data, offset: 0, endStream: endStream)
    }

    func receive() async throws -> Data? {
        guard let connection else { throw XHTTPError.connectionClosed }
        return try await connection.receive(stream: self)
    }

    /// Discards any further inbound data on this stream (an upload leg's response).
    func drainResponse() { connection?.drain(stream: self) }

    func close() { connection?.removeStream(self) }
}

/// One always-on read loop demuxes frames to per-stream buffers. State under the `state` mutex.
nonisolated final class XHTTPH2Multiplexer: XHTTPXMUXMultiplexerPoolable, @unchecked Sendable {
    private let transport: any ByteTransport
    /// Demuxes the shared socket into H2 frames; one always-on read loop drives it.
    private let frameReader: H2FrameReader

    nonisolated private struct State {
        var streams: [UInt32: XHTTPH2Stream] = [:]
        var nextStreamId: UInt32 = 1
        var closedFlag = false
        /// Holds dial objects (TLS/Reality client) alive for the connection's lifetime.
        var retained: [AnyObject] = []

        // Peer flow-control windows (for our sends).
        var peerConnWindow = 65535
        var peerInitialWindow = 65535
        var maxFrameSize = 16384
        var flowGate = H2FlowGate()

        // Local receive-window accounting (replenished as sessions consume data).
        var connReceiveConsumed = 0
    }

    private let state = Mutex(State())
    private static let localStreamWindow = 4_194_304          // 4 MB
    private static let localConnWindow: UInt32 = 1_073_741_824 // 1 GB
    private static let maxReadBuffer = 8_388_608               // 8 MB

    /// Control frames to write outside the state lock (window updates). Receive hand-off now
    /// happens in `receive` itself via the per-stream gate, so there's no deliver closure.
    private struct PumpEffect {
        var frames: [Data] = []
    }

    init(transport: any ByteTransport) {
        self.transport = transport
        frameReader = H2FrameReader(maxBufferSize: Self.maxReadBuffer, receive: { try await transport.receive() })
    }

    /// Keeps a dial-time object (TLS/Reality client) alive for the connection's lifetime.
    func retain(_ object: AnyObject) {
        state.withLock { $0.retained.append(object) }
    }

    var isPoolClosed: Bool { state.withLock { $0.closedFlag } }
    func poolClose() { cancel() }

    // MARK: Setup

    /// Sends the client preface + SETTINGS, returning once the server's SETTINGS arrives.
    func connect() async throws {
        var initData = XHTTPConnection.h2Preface
        var settings = Data()
        settings.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]) // ENABLE_PUSH = 0
        let win = XHTTPConnection.h2StreamWindowSize
        settings.append(contentsOf: [0x00, 0x04,
            UInt8((win >> 24) & 0xFF), UInt8((win >> 16) & 0xFF), UInt8((win >> 8) & 0xFF), UInt8(win & 0xFF)])
        settings.append(contentsOf: [0x00, 0x06, 0x00, 0xA0, 0x00, 0x00]) // MAX_HEADER_LIST_SIZE
        initData.append(frame(type: XHTTPConnection.h2FrameSettings, flags: 0, streamId: 0, payload: settings))
        initData.append(frame(type: XHTTPConnection.h2FrameWindowUpdate, flags: 0, streamId: 0,
                              payload: uint32Data(Self.localConnWindow)))

        do {
            try await transport.send(initData)
        } catch {
            throw XHTTPError.setupFailed("shared H2 preface: \(error.localizedDescription)")
        }

        // Read frames until the server's initial SETTINGS arrives, then start the pump.
        while true {
            let f: H2Framing.Frame
            do {
                f = try await frameReader.readFrame()
            } catch {
                throw XHTTPError.setupFailed("shared H2 settings read: \(error.localizedDescription)")
            }
            switch f.type {
            case XHTTPConnection.h2FrameSettings where f.flags & XHTTPConnection.h2FlagAck == 0:
                applySettings(f.payload)
                try? await transport.send(frame(type: XHTTPConnection.h2FrameSettings,
                                                flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: Data()))
                startPump()
                return
            case XHTTPConnection.h2FrameWindowUpdate:
                handleConnWindowUpdate(f.payload)
            case XHTTPConnection.h2FramePing where f.flags & XHTTPConnection.h2FlagAck == 0:
                try? await transport.send(frame(type: XHTTPConnection.h2FramePing,
                                                flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: f.payload))
            case XHTTPConnection.h2FrameGoaway:
                throw XHTTPError.setupFailed("shared H2: server GOAWAY")
            default:
                break
            }
        }
    }

    // MARK: Read loop

    private func startPump() {
        Task { [weak self] in
            while true {
                guard let self else { return }
                let f: H2Framing.Frame
                do {
                    f = try await self.frameReader.readFrame()
                } catch {
                    if let x = error as? XHTTPError, case .streamEnded = x {
                        // Clean FIN of the shared H2 connection → EOF for every muxed stream.
                        self.failAll(nil)
                    } else {
                        self.failAll(XHTTPError.connectionClosed)
                    }
                    return
                }
                await self.routeFrame(f)
                if self.state.withLock({ $0.closedFlag }) { return }
            }
        }
    }

    /// Returns a description for a non-200 response `:status` (HPACK static-indexed error codes),
    /// or nil for 200 / an encoding we don't decode.
    private static func h2StatusError(_ block: Data) -> String? {
        guard let first = block.first else { return nil }
        switch first {
        case 0x89: return "HTTP 204"; case 0x8a: return "HTTP 206"; case 0x8b: return "HTTP 304"
        case 0x8c: return "HTTP 400"; case 0x8d: return "HTTP 404"; case 0x8e: return "HTTP 500"
        default:   return nil
        }
    }

    private func routeFrame(_ decodedFrame: H2Framing.Frame) async {
        switch decodedFrame.type {
        case XHTTPConnection.h2FrameData:
            if let effect = handleData(streamId: decodedFrame.streamId, flags: decodedFrame.flags, payload: decodedFrame.payload) {
                await apply(effect)
            }
        case XHTTPConnection.h2FrameHeaders:
            if let effect = handleHeaders(streamId: decodedFrame.streamId, flags: decodedFrame.flags, payload: decodedFrame.payload) {
                await apply(effect)
            }
        case XHTTPConnection.h2FrameWindowUpdate:
            if decodedFrame.streamId == 0 { handleConnWindowUpdate(decodedFrame.payload) }
            else { handleStreamWindowUpdate(streamId: decodedFrame.streamId, payload: decodedFrame.payload) }
        case XHTTPConnection.h2FrameSettings where decodedFrame.flags & XHTTPConnection.h2FlagAck == 0:
            applySettings(decodedFrame.payload)
            try? await transport.send(frame(type: XHTTPConnection.h2FrameSettings, flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: Data()))
        case XHTTPConnection.h2FramePing where decodedFrame.flags & XHTTPConnection.h2FlagAck == 0:
            try? await transport.send(frame(type: XHTTPConnection.h2FramePing, flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: decodedFrame.payload))
        case XHTTPConnection.h2FrameRstStream:
            if let effect = handleEnd(streamId: decodedFrame.streamId) { await apply(effect) }
        case XHTTPConnection.h2FrameGoaway:
            failAll(XHTTPError.connectionClosed)
        default:
            break
        }
    }

    /// Runs an effect's control-frame writes, then resumes any waiting receive.
    private func apply(_ effect: PumpEffect) async {
        for frame in effect.frames { try? await transport.send(frame) }
    }

    private func handleData(streamId: UInt32, flags: UInt8, payload: Data) -> PumpEffect? {
        let endStream = flags & XHTTPConnection.h2FlagEndStream != 0
        return state.withLock { state in
            guard let stream = state.streams[streamId] else {
                // Unknown/closed stream: still replenish the connection window so peers keep flowing.
                state.connReceiveConsumed += payload.count
                guard let windowUpdateFrame = connWindowUpdateLocked(&state) else { return nil }
                return PumpEffect(frames: [windowUpdateFrame])
            }
            if stream.draining {
                state.connReceiveConsumed += payload.count
                stream.receiveConsumed += payload.count
                let updates = windowUpdatesLocked(stream, &state)
                if endStream { state.streams.removeValue(forKey: streamId) }
                return PumpEffect(frames: updates)
            }
            if !payload.isEmpty { stream.receiveBuffer.append(payload) }
            if endStream { stream.ended = true }
            wakeReceiverLocked(stream)
            return nil
        }
    }

    private func handleHeaders(streamId: UInt32, flags: UInt8, payload: Data) -> PumpEffect? {
        // A non-200 response means the request was rejected (e.g. a 400 on a detached download GET
        // whose session the server can't pair). Surface it as an explicit error.
        if let statusError = Self.h2StatusError(payload) {
            return state.withLock { state in
                guard let stream = state.streams[streamId] else { return nil }
                if stream.failure == nil {
                    stream.failure = XHTTPError.setupFailed("shared H2 stream \(streamId): \(statusError)")
                }
                wakeReceiverLocked(stream)
                return nil
            }
        }
        // Body arrives as DATA; only a HEADERS carrying END_STREAM closes the stream.
        guard flags & XHTTPConnection.h2FlagEndStream != 0 else { return nil }
        return handleEnd(streamId: streamId)
    }

    private func handleEnd(streamId: UInt32) -> PumpEffect? {
        state.withLock { state in
            guard let stream = state.streams[streamId] else { return nil }
            if stream.draining { state.streams.removeValue(forKey: streamId); return nil }
            stream.ended = true
            wakeReceiverLocked(stream)
            return nil
        }
    }

    private func handleConnWindowUpdate(_ payload: Data) {
        guard payload.count >= 4 else { return }
        let increment = Int(readUInt32(payload) & 0x7FFFFFFF)
        state.withLock { state in
            state.peerConnWindow += increment
            state.flowGate.wakeAll()
        }
    }

    private func handleStreamWindowUpdate(streamId: UInt32, payload: Data) {
        guard payload.count >= 4 else { return }
        let inc = Int(readUInt32(payload) & 0x7FFFFFFF)
        state.withLock { state in
            state.streams[streamId]?.sendWindow += inc
            state.flowGate.wakeAll()
        }
    }

    /// Lock held. Wakes a parked ``receive(stream:)`` so it re-evaluates the stream's
    /// buffer/EOF/error state (and replenishes the receive window on consume). The window-update
    /// frames and the actual hand-off now live in `receive`, so this just finishes the gate.
    private func wakeReceiverLocked(_ stream: XHTTPH2Stream) {
        stream.receiveWaiter?.finish()
        stream.receiveWaiter = nil
    }

    // MARK: Send

    func sendHeaders(streamId: UInt32, headerBlock: Data, endStream: Bool) async throws {
        let f: Data? = state.withLock { state in
            if state.closedFlag { return nil }
            let flags = XHTTPConnection.h2FlagEndHeaders | (endStream ? XHTTPConnection.h2FlagEndStream : 0)
            return frame(type: XHTTPConnection.h2FrameHeaders, flags: flags, streamId: streamId, payload: headerBlock)
        }
        guard let f else { throw XHTTPError.connectionClosed }
        try await transport.send(f)
    }

    func sendData(stream: XHTTPH2Stream, data: Data, offset: Int, endStream: Bool) async throws {
        // Pure half-close (no more payload): emit a bare END_STREAM DATA frame.
        if offset >= data.count {
            guard endStream else { return }
            let f: Data? = state.withLock { state in
                if state.closedFlag { return nil }
                return frame(type: XHTTPConnection.h2FrameData, flags: XHTTPConnection.h2FlagEndStream, streamId: stream.streamId, payload: Data())
            }
            guard let f else { throw XHTTPError.connectionClosed }
            try await transport.send(f)
            return
        }

        enum BuildStep {
            case closed
            case park
            case built(frames: Data, nextOffset: Int)
        }
        var currentOffset = offset
        while currentOffset < data.count {
            let step: BuildStep = state.withLock { state in
                if state.closedFlag { return .closed }
                let window = min(state.peerConnWindow, stream.sendWindow)
                guard window > 0 else { return .park }
                var frames = Data()
                var current = currentOffset
                var remainingWindow = window
                while current < data.count {
                    let chunk = min(data.count - current, min(state.maxFrameSize, remainingWindow))
                    guard chunk > 0 else { break }
                    let isLast = (current + chunk) >= data.count
                    let flags: UInt8 = (isLast && endStream) ? XHTTPConnection.h2FlagEndStream : 0
                    frames.append(frame(type: XHTTPConnection.h2FrameData, flags: flags, streamId: stream.streamId,
                                        payload: Data(data[data.startIndex + current ..< data.startIndex + current + chunk])))
                    current += chunk
                    remainingWindow -= chunk
                }
                let sent = window - remainingWindow
                state.peerConnWindow -= sent
                stream.sendWindow -= sent
                return .built(frames: frames, nextOffset: current)
            }
            switch step {
            case .closed:
                throw XHTTPError.connectionClosed
            case .park:
                await parkForFlow(stream: stream)
            case .built(let frames, let nextOffset):
                try await transport.send(frames)
                currentOffset = nextOffset
            }
        }
    }

    /// Suspends until a WINDOW_UPDATE re-opens this stream's send window (or the connection closes).
    /// Re-checks under the lock before parking so a window re-open racing the caller isn't missed.
    private func parkForFlow(stream: XHTTPH2Stream) async {
        await H2FlowGate.park {
            state.withLock { state -> AsyncStream<Never>? in
                if state.closedFlag { return nil }
                if min(state.peerConnWindow, stream.sendWindow) > 0 { return nil }
                return state.flowGate.enroll()
            }
        }
    }

    func receive(stream: XHTTPH2Stream) async throws -> Data? {
        enum Outcome { case data(Data, frames: [Data]), eof, error(Error), wait(AsyncStream<Void>) }
        while true {
            let outcome: Outcome = state.withLock { state in
                if let failure = stream.failure {
                    return .error(failure)
                }
                if !stream.receiveBuffer.isEmpty {
                    // Consume-time flow control: replenish the receive window only as the session
                    // drains the buffer, so a slow reader backpressures the peer.
                    let data = stream.receiveBuffer
                    stream.receiveBuffer = Data()
                    state.connReceiveConsumed += data.count
                    stream.receiveConsumed += data.count
                    let updates = windowUpdatesLocked(stream, &state)
                    return .data(data, frames: updates)
                }
                if stream.ended {
                    state.streams.removeValue(forKey: stream.streamId)
                    return .eof
                }
                if state.closedFlag {
                    return .error(XHTTPError.connectionClosed)
                }
                let (waitStream, continuation) = AsyncStream<Void>.makeStream()
                stream.receiveWaiter = continuation
                return .wait(waitStream)
            }
            switch outcome {
            case .data(let data, let frames):
                // WINDOW_UPDATEs are fire-and-forget (order vs. the pump is immaterial).
                if !frames.isEmpty {
                    let transport = self.transport
                    Task { for frame in frames { try? await transport.send(frame) } }
                }
                return data
            case .eof:
                return nil
            case .error(let error):
                throw error
            case .wait(let waitStream):
                for await _ in waitStream { break }
                // A finished gate (data/close) loops to re-check; a cancelled task must not spin.
                try Task.checkCancellation()
            }
        }
    }

    // MARK: Streams

    func openStream() -> XHTTPH2Stream {
        state.withLock { state in
            let id = state.nextStreamId
            state.nextStreamId += 2
            let stream = XHTTPH2Stream(streamId: id, connection: self, sendWindow: state.peerInitialWindow)
            state.streams[id] = stream
            return stream
        }
    }

    func drain(stream: XHTTPH2Stream) {
        state.withLock { _ in
            stream.draining = true
            stream.receiveBuffer = Data()
        }
    }

    func removeStream(_ stream: XHTTPH2Stream) {
        let shouldReset: Bool = state.withLock { state in
            let known = state.streams[stream.streamId] != nil
            state.streams.removeValue(forKey: stream.streamId)
            return known && !stream.ended && !state.closedFlag
        }
        if shouldReset {
            var code = Data(count: 4); code[3] = 0x08 // CANCEL
            let f = frame(type: XHTTPConnection.h2FrameRstStream, flags: 0, streamId: stream.streamId, payload: code)
            let transport = self.transport
            Task { try? await transport.send(f) }
        }
    }

    func cancel() { failAll(XHTTPError.connectionClosed) }

    /// Tears down all muxed streams. A nil error delivers a graceful EOF to each pending
    /// receive (e.g. a clean transport FIN of the shared H2 connection); a non-nil error
    /// surfaces as a failure.
    private func failAll(_ error: Error?) {
        let didClose: Bool = state.withLock { state in
            if state.closedFlag { return false }
            state.closedFlag = true
            // Stamp each stream so a parked receive re-check surfaces the right terminal result:
            // a non-nil error as a failure, a nil error (clean FIN) as graceful EOF.
            for stream in state.streams.values {
                if let error {
                    if stream.failure == nil { stream.failure = error }
                } else {
                    stream.ended = true
                }
                wakeReceiverLocked(stream)
            }
            state.streams.removeAll()
            // Sends parked on flow control wake here; each re-enters `sendData`, sees the closed
            // connection, and throws `.connectionClosed` rather than hanging forever.
            state.flowGate.wakeAll()
            return true
        }
        guard didClose else { return }
        frameReader.reset()
        transport.cancel()
    }

    // MARK: Frame I/O

    private func frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        H2Framing.frame(type: type, flags: flags, streamId: streamId, payload: payload)
    }

    private func applySettings(_ payload: Data) {
        var index = payload.startIndex
        while index + 6 <= payload.endIndex {
            let id = (UInt16(payload[index]) << 8) | UInt16(payload[index + 1])
            let value = (UInt32(payload[index + 2]) << 24) | (UInt32(payload[index + 3]) << 16)
                    | (UInt32(payload[index + 4]) << 8) | UInt32(payload[index + 5])
            state.withLock { state in
                if id == 0x04 { // INITIAL_WINDOW_SIZE
                    let delta = Int(value) - state.peerInitialWindow
                    state.peerInitialWindow = Int(value)
                    for s in state.streams.values { s.sendWindow += delta }
                } else if id == 0x05 { // MAX_FRAME_SIZE
                    state.maxFrameSize = Int(value)
                }
            }
            index += 6
        }
    }

    /// Conn-level WINDOW_UPDATE once >= 50% of the advertised window is consumed. Lock held.
    private func connWindowUpdateLocked(_ state: inout State) -> Data? {
        guard state.connReceiveConsumed >= Int(Self.localConnWindow) / 2 else { return nil }
        let inc = UInt32(state.connReceiveConsumed)
        state.connReceiveConsumed = 0
        return frame(type: XHTTPConnection.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: uint32Data(inc))
    }

    /// Conn + stream WINDOW_UPDATEs as thresholds are crossed. Lock held.
    private func windowUpdatesLocked(_ stream: XHTTPH2Stream, _ state: inout State) -> [Data] {
        var out: [Data] = []
        if let c = connWindowUpdateLocked(&state) { out.append(c) }
        if stream.receiveConsumed >= Self.localStreamWindow / 2, !stream.ended {
            let inc = UInt32(stream.receiveConsumed)
            stream.receiveConsumed = 0
            out.append(frame(type: XHTTPConnection.h2FrameWindowUpdate, flags: 0, streamId: stream.streamId, payload: uint32Data(inc)))
        }
        return out
    }

    private func readUInt32(_ d: Data) -> UInt32 { H2Framing.readUInt32(d) }

    private func uint32Data(_ v: UInt32) -> Data { H2Framing.uint32Data(v) }
}

// MARK: - Pooled HTTP/1.1 Upload Connection (xmux)
//
// Pools the packet-up *upload* POST socket across sessions (the download GET stays fresh).
// HTTP/1.1 can't multiplex, so a connection carries one session at a time and is reused only
// when verifiably clean — every POST's response fully read. Anything it can't frame (chunked,
// length-less, unexpected) marks it unreusable, so the worst case is a fresh dial, never a
// mis-framed response.

nonisolated final class XHTTPH1Multiplexer: XHTTPXMUXMultiplexerPoolable, @unchecked Sendable {
    private let transport: any ByteTransport

    nonisolated private enum ParseState { case headers; case body(Int) }

    nonisolated private struct State {
        var outstanding = 0       // POSTs written minus responses fully parsed
        var dirty = false         // unparseable/unexpected response → never reuse
        var closed = false
        var retained: [AnyObject] = []
        var parseState: ParseState = .headers
        var parseBuffer = Data()
    }

    private let state = Mutex(State())

    /// Lease for the current session; refreshed on each pool acquire.
    var lease: XHTTPXMUXMultiplexerLease?

    init(transport: any ByteTransport) {
        self.transport = transport
        startDrain()
    }

    /// Keeps a dial-time object (TLS/Reality client) alive for the connection's lifetime.
    func retain(_ object: AnyObject) { state.withLock { $0.retained.append(object) } }

    var isPoolClosed: Bool { state.withLock { $0.closed || $0.dirty } }

    func poolClose() {
        let alreadyClosed: Bool = state.withLock { state in
            if state.closed { return true }
            state.closed = true
            return false
        }
        if alreadyClosed { return }
        transport.cancel()
    }

    /// Transport handed to the XHTTP session: each write is one POST; the session needn't read
    /// (this connection drains internally); cancel returns the connection to the pool.
    var sessionTransport: any ByteTransport {
        SessionTransport(multiplexer: self)
    }

    /// One POST per send, no reads, pool-return on cancel — the H1-pool multiplexer's
    /// per-session byte surface. Holds its owner weakly (the owner outlives it in the pool).
    private final class SessionTransport: ByteTransport, @unchecked Sendable {
        private weak var multiplexer: XHTTPH1Multiplexer?

        init(multiplexer: XHTTPH1Multiplexer) {
            self.multiplexer = multiplexer
        }

        var isReady: Bool { multiplexer?.isPoolClosed == false }

        func send(_ data: Data) async throws {
            guard let multiplexer else { throw XHTTPError.connectionClosed }
            multiplexer.state.withLock { $0.outstanding += 1 }
            try await multiplexer.transport.send(data)
        }

        func receive() async throws -> TransportChunk { .end }

        func cancel() { multiplexer?.releaseToPool() }
    }

    private func releaseToPool() {
        let lease: XHTTPXMUXMultiplexerLease? = state.withLock { state in
            // Only a fully-drained, well-framed connection may be reused.
            if state.dirty || state.outstanding != 0 || !state.parseBuffer.isEmpty { state.dirty = true }
            let lease = self.lease
            self.lease = nil
            return lease
        }
        lease?.release()
    }

    // MARK: Internal drain + response parser

    private func startDrain() {
        Task { [weak self] in
            while true {
                guard let self else { return }
                let chunk: TransportChunk
                do {
                    chunk = try await self.transport.receive()
                } catch {
                    self.state.withLock { $0.closed = true }
                    return
                }
                switch chunk {
                case .bytes(let data):
                    if !data.isEmpty { self.consume(data) }
                case .end:
                    self.state.withLock { $0.closed = true }
                    return
                }
                if self.state.withLock({ $0.closed }) { return }
            }
        }
    }

    /// Counts completed responses (Content-Length framed). Anything it can't frame marks the
    /// connection unreusable rather than risk mis-framing a reused socket.
    private func consume(_ data: Data) {
        state.withLock { state in
            if state.dirty || state.closed { return }
            state.parseBuffer.append(data)
            while true {
                switch state.parseState {
                case .headers:
                    guard let r = state.parseBuffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) else { return }
                    let headerData = Data(state.parseBuffer[state.parseBuffer.startIndex..<r.lowerBound])
                    state.parseBuffer = Data(state.parseBuffer[r.upperBound...])
                    guard let header = String(data: headerData, encoding: .ascii), header.hasPrefix("HTTP/1.") else {
                        state.dirty = true; return
                    }
                    let lower = header.lowercased()
                    if lower.contains("transfer-encoding:"), lower.contains("chunked") {
                        state.dirty = true; return
                    }
                    guard let length = Self.contentLength(in: header) else {
                        // No Content-Length and not chunked → connection-delimited → can't reuse.
                        state.dirty = true; return
                    }
                    if length == 0 { completeResponseLocked(&state) } else { state.parseState = .body(length) }
                case .body(let remaining):
                    guard !state.parseBuffer.isEmpty else { return }
                    let take = min(remaining, state.parseBuffer.count)
                    state.parseBuffer.removeFirst(take)
                    state.parseBuffer = state.parseBuffer.isEmpty ? Data() : Data(state.parseBuffer)
                    let left = remaining - take
                    if left == 0 { state.parseState = .headers; completeResponseLocked(&state) }
                    else { state.parseState = .body(left); return }
                }
            }
        }
    }

    /// Lock held.
    private func completeResponseLocked(_ state: inout State) {
        state.parseState = .headers
        if state.outstanding <= 0 { state.dirty = true; return } // unexpected/extra response
        state.outstanding -= 1
    }

    private static func contentLength(in header: String) -> Int? {
        for line in header.components(separatedBy: "\r\n") {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2,
               parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "content-length" {
                return Int(parts[1].trimmingCharacters(in: .whitespaces))
            }
        }
        return nil
    }
}
