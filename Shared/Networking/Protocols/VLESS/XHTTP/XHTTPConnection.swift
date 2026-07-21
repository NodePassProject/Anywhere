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

nonisolated final class XHTTPConnection: Sendable {

    let configuration: XHTTPConfiguration
    let mode: XHTTPMode
    let sessionId: String

    // Download / stream-one transport.
    let download: any ByteTransport

    // Upload transport factory (packet-up and stream-up), async-native.
    let uploadConnectionFactory: (@Sendable () async throws -> any ByteTransport)?

    // The seven setup values below are written once at setup and read on the send/receive path;
    // their storage lives in `state` (see `State`). Reads are read-only atomic snapshots; the
    // one-time writes go through the explicit `configure…`/`adopt…` methods so no caller mistakes
    // a lock-guarded field for a plain settable variable. Reads inside an existing `withLock` use
    // the `state` fields directly to avoid re-entering the lock.
    var role: XHTTPChannelRole { state.withLock { $0.role } }
    /// Sets the channel role. Called once by the coordinator before the leg goes on the wire.
    func configureRole(_ role: XHTTPChannelRole) { state.withLock { $0.role = role } }

    /// Upload leg owned by this download leg when detached; sends are delegated to it.
    var uploadChannel: XHTTPConnection? { state.withLock { $0.uploadChannel } }
    /// Attaches the owned upload leg. Called once by the coordinator during detached setup.
    func attachUploadChannel(_ channel: XHTTPConnection?) { state.withLock { $0.uploadChannel = channel } }

    /// Non-nil when the transport is a pooled, shared xmux connection; teardown then
    /// releases the lease instead of closing the shared transport (others may still use it).
    var xmuxLease: XHTTPXMUXMultiplexerLease? { state.withLock { $0.xmuxLease } }
    /// Records the xmux pool lease. Called once by the coordinator at acquisition.
    func configureXMUXLease(_ lease: XHTTPXMUXMultiplexerLease) { state.withLock { $0.xmuxLease = lease } }

    // Packet-up: one POST at a time, no more often than `scMinPostsIntervalMs` apart. Each POST
    // runs in submission order on this serializer, so they go strictly one at a time (rate-limit
    // wait included) without a lock held across the `await`.
    let packetUpChain = SerialSender()

    // HTTP/2 state
    let useHTTP2: Bool
    /// Demuxes the byte transport into H2 frames (1:1 path); idle on H3/shared-H2 legs.
    let h2FrameReader: H2FrameReader

    /// Caps the H2 frame reader's buffer to bound memory growth.
    static let maxH2ReadBufferSize = 2_097_152

    // HTTP/2 multiplexing stream IDs (set at H2 setup, read on the send/receive path).
    var h2UploadStreamId: UInt32 { state.withLock { $0.h2UploadStreamId } }      // Fixed upload stream for stream-up
    /// Download (GET) stream id when reading H2 frames; set out of range on an
    /// `.uploadOnly` leg so its POST responses are drained, not delivered.
    var h2DownloadStreamId: UInt32 { state.withLock { $0.h2DownloadStreamId } }
    /// Sets both H2 stream ids together at H2 setup, so they publish as one unit.
    func configureH2StreamIDs(upload: UInt32, download: UInt32) {
        state.withLock { $0.h2UploadStreamId = upload; $0.h2DownloadStreamId = download }
    }

    // HTTP/3 state (modes multiplexed onto QUIC streams via HTTP3Multiplexer)
    var h3Multiplexer: HTTP3Multiplexer? { state.withLock { $0.h3Multiplexer } }
    /// Adopts the pooled H3 session. Called once from the convenience init before the leg is shared.
    func adoptH3Multiplexer(_ multiplexer: HTTP3Multiplexer) { state.withLock { $0.h3Multiplexer = multiplexer } }

    var useHTTP3: Bool { h3Multiplexer != nil }

    // Pooled shared-H2 multiplexing state (xmux). When `sharedH2` is set, this session's
    // streams ride a shared connection instead of running its own 1:1 H2 framing.
    var sharedH2: XHTTPH2Multiplexer? { state.withLock { $0.sharedH2 } }
    /// Adopts the shared xmux H2 connection. Called once from the convenience init before sharing.
    func adoptSharedH2(_ multiplexer: XHTTPH2Multiplexer) { state.withLock { $0.sharedH2 = multiplexer } }

    var usesSharedH2: Bool { sharedH2 != nil }

    // MARK: - Guarded State

    /// All mutable per-connection state, guarded by the `state` mutex. Continuations parked here
    /// are always resumed *after* `withLock` returns, never while the lock is held.
    nonisolated struct State {
        // Setup values: written once during `performSetup`, read on the send/receive path.
        var role: XHTTPChannelRole = .combined
        /// Upload leg owned by this download leg when detached; sends are delegated to it.
        var uploadChannel: XHTTPConnection?
        /// Non-nil when the transport is a pooled, shared xmux connection.
        var xmuxLease: XHTTPXMUXMultiplexerLease?
        /// Fixed upload stream for stream-up.
        var h2UploadStreamId: UInt32 = 3
        /// Download (GET) stream id; set out of range on an `.uploadOnly` leg so its POST
        /// responses are drained, not delivered.
        var h2DownloadStreamId: UInt32 = 1
        /// HTTP/3 multiplexer (QUIC streams); nil unless the leg runs over H3.
        var h3Multiplexer: HTTP3Multiplexer?
        /// Pooled shared-H2 multiplexer (xmux); when set, streams ride a shared connection.
        var sharedH2: XHTTPH2Multiplexer?
        
        var uploadTransport: (any ByteTransport)?
        var uploadDrainTask: Task<Void, Never>?

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

    init(download: any ByteTransport, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: (@Sendable () async throws -> any ByteTransport)? = nil) {
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
        adoptH3Multiplexer(h3Multiplexer)
    }

    /// Over a shared multiplexing H2 connection (xmux), streams are virtual, so the download
    /// closures are the no-op `.unused` and `useHTTP2` stays false (the shared path is used instead).
    convenience init(sharedH2: XHTTPH2Multiplexer, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String) {
        self.init(download: NullByteTransport(), configuration: configuration, mode: mode, sessionId: sessionId)
        adoptSharedH2(sharedH2)
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
            guard let stream else { throw AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)) }
            try await stream.sendData(data, endStream: false)
            return
        }
        if useHTTP3 {
            let stream = state.withLock { state in (mode == .streamUp) ? state.h3Upload : state.h3Download }
            guard let stream else { throw AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)) }
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
        // `h3Multiplexer`/`xmuxLease` now live in `State`, read here directly under the lock; the
        // parked flow-control continuations are resumed only after `withLock` returns.
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
            let h3Session = state.h3Multiplexer
            let sharedH2DownloadStream = state.sharedH2Download
            let sharedH2UploadStream = state.sharedH2Upload
            state.sharedH2Download = nil
            state.sharedH2Upload = nil
            let lease = state.xmuxLease
            state.xmuxLease = nil
            let upload = state.uploadTransport
            state.uploadTransport = nil
            state.uploadDrainTask?.cancel()
            state.uploadDrainTask = nil
            state.h2FlowGate.wakeAll()
            return (
                h3DownloadStream,
                h3UploadStream,
                h3Session,
                sharedH2DownloadStream,
                sharedH2UploadStream,
                lease,
                upload
            )
        }

        download.cancel()
        teardown.upload?.cancel()
        teardown.h3Download?.close()
        teardown.h3Upload?.close()
        teardown.sharedH2Download?.close()
        teardown.sharedH2Upload?.close()
        if let lease = teardown.lease {
            lease.release()
        } else {
            teardown.h3Session?.close()
        }
        uploadChannel?.cancel()
    }

    // MARK: - Packet-Up
    
    private func sendPacketUp(_ data: Data) async throws {
        try await packetUpChain.run { [self] in
            let closed = state.withLock { state in
                !state._isConnected || (useHTTP2 && state.h2StreamClosed) || (state.h3Multiplexer != nil && state.h3Closed)
            }
            if closed { throw AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)) }

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

nonisolated protocol XHTTPXMUXMultiplexerPoolable: AnyObject, Sendable {
    var isPoolClosed: Bool { get }
    func poolClose()
}

nonisolated final class XHTTPXMUXMultiplexerLease: Sendable {
    let connection: XHTTPXMUXMultiplexerPoolable
    
    private struct WeakManager: Sendable { weak var value: XHTTPXMUXMultiplexerManager? }
    private let managerBox: WeakManager
    private var manager: XHTTPXMUXMultiplexerManager? { managerBox.value }
    
    private let clientID: UInt64
    
    private let released = Atomic(false)

    init(connection: XHTTPXMUXMultiplexerPoolable, manager: XHTTPXMUXMultiplexerManager, clientID: UInt64) {
        self.connection = connection
        self.managerBox = WeakManager(value: manager)
        self.clientID = clientID
    }
    
    func noteRequest() {
        manager?.noteRequest(clientID)
    }
    
    func release() {
        guard released.compareExchange(expected: false, desired: true, ordering: .relaxed).exchanged else { return }
        manager?.releaseSlot(clientID)
    }
}

nonisolated final class XHTTPXMUXMultiplexerManager: Sendable {
    private let config: XHTTPXMUXMultiplexerConfiguration
    
    private let concurrency: Int
    
    private let connections: Int
    
    private let newConnection: @Sendable () async -> XHTTPXMUXMultiplexerPoolable?

    private enum Phase { case dialing, ready, failed }
    
    private struct ClientEntry {
        var phase: Phase = .dialing
        var connection: XHTTPXMUXMultiplexerPoolable?
        var openUsage = 0
        var leftUsage: Int
        var leftRequests: Int
        let unreusableAt: CFAbsoluteTime?
        var dialTask: Task<XHTTPXMUXMultiplexerPoolable?, Never>?
        
        func isRetired(now: CFAbsoluteTime) -> Bool {
            if phase == .dialing { return false }
            if phase == .failed { return true }
            if connection?.isPoolClosed == true { return true }
            if leftUsage == 0 || leftRequests <= 0 { return true }
            if let unreusableAt, now > unreusableAt { return true }
            return false
        }
    }

    private struct PoolState {
        var entries: [UInt64: ClientEntry] = [:]
        var nextID: UInt64 = 0
    }
    private let pool = Mutex(PoolState())
    
    private let registry: XHTTPXMUXMultiplexerRegistry?
    fileprivate let registryKey: String?

    fileprivate init(
        config: XHTTPXMUXMultiplexerConfiguration,
        newConnection: @escaping @Sendable () async -> XHTTPXMUXMultiplexerPoolable?,
        registry: XHTTPXMUXMultiplexerRegistry? = nil,
        registryKey: String? = nil
    ) {
        self.config = config
        self.concurrency = config.maxConcurrency.random()
        self.connections = config.maxConnections.random()
        self.newConnection = newConnection
        self.registry = registry
        self.registryKey = registryKey
    }
    
    func acquire() async -> XHTTPXMUXMultiplexerLease? {
        let now = CFAbsoluteTimeGetCurrent()
        var retiredIdle: [XHTTPXMUXMultiplexerPoolable] = []
        pool.withLock { pool in
            let retiredIDs = pool.entries.compactMap { $0.value.isRetired(now: now) ? $0.key : nil }
            for id in retiredIDs {
                if pool.entries[id]!.openUsage == 0, let connection = pool.entries[id]!.connection {
                    retiredIdle.append(connection)
                }
                pool.entries[id] = nil
            }
        }
        for connection in retiredIdle { connection.poolClose() }
        
        enum Decision {
            case ready(XHTTPXMUXMultiplexerPoolable, UInt64)
            case failed
            case dialOrJoin(UInt64)
        }
        let decision: Decision = pool.withLock { pool in
            if let id = selectReusable(in: pool.entries) {
                pool.entries[id]!.openUsage += 1
                if pool.entries[id]!.leftUsage > 0 { pool.entries[id]!.leftUsage -= 1 }
                switch pool.entries[id]!.phase {
                case .ready:
                    return .ready(pool.entries[id]!.connection!, id)
                case .dialing:
                    return .dialOrJoin(id)
                case .failed:
                    return .failed
                }
            }
            
            let reuseRand = config.cMaxReuseTimes.random()
            let leftUsage = reuseRand > 0 ? reuseRand - 1 : -1
            let reqRand = config.hMaxRequestTimes.random()
            let leftRequests = reqRand > 0 ? reqRand : Int.max
            let secsRand = config.hMaxReusableSecs.random()
            let unreusableAt: CFAbsoluteTime? = secsRand > 0 ? now + Double(secsRand) : nil

            let id = pool.nextID
            pool.nextID &+= 1
            var entry = ClientEntry(leftUsage: leftUsage, leftRequests: leftRequests, unreusableAt: unreusableAt)
            entry.openUsage = 1
            entry.dialTask = Task { [weak self] in await self?.performDial(for: id) ?? nil }
            pool.entries[id] = entry
            return .dialOrJoin(id)
        }

        switch decision {
        case .ready(let connection, let id):
            return makeLease(connection, id)
        case .failed:
            return nil
        case .dialOrJoin(let id):
            let task = pool.withLock { $0.entries[id]?.dialTask }
            guard let connection = await task?.value else { return nil }
            return makeLease(connection, id)
        }
    }
    
    private func performDial(for id: UInt64) async -> XHTTPXMUXMultiplexerPoolable? {
        let connection = await newConnection()
        var drained = false
        pool.withLock { pool in
            if let connection {
                pool.entries[id]?.connection = connection
                pool.entries[id]?.phase = .ready
            } else {
                pool.entries[id] = nil
                drained = pool.entries.isEmpty
            }
        }
        if drained { registry?.evictIfEmpty(self) }
        return connection
    }
    
    private func selectReusable(in entries: [UInt64: ClientEntry]) -> UInt64? {
        if entries.isEmpty { return nil }
        if connections > 0 && entries.count < connections { return nil }
        let eligible = concurrency > 0 ? entries.filter { $0.value.openUsage < concurrency } : entries
        return eligible.keys.randomElement()
    }

    private func makeLease(_ connection: XHTTPXMUXMultiplexerPoolable, _ clientID: UInt64) -> XHTTPXMUXMultiplexerLease {
        XHTTPXMUXMultiplexerLease(connection: connection, manager: self, clientID: clientID)
    }

    func releaseSlot(_ clientID: UInt64) {
        var shouldClose: XHTTPXMUXMultiplexerPoolable?
        let drained: Bool = pool.withLock { pool in
            guard pool.entries[clientID] != nil else { return pool.entries.isEmpty }
            if pool.entries[clientID]!.openUsage > 0 { pool.entries[clientID]!.openUsage -= 1 }
            if pool.entries[clientID]!.openUsage == 0,
               pool.entries[clientID]!.isRetired(now: CFAbsoluteTimeGetCurrent()) {
                shouldClose = pool.entries[clientID]!.connection
                pool.entries[clientID] = nil
            }
            return pool.entries.isEmpty
        }
        shouldClose?.poolClose()
        if drained { registry?.evictIfEmpty(self) }
    }

    func noteRequest(_ clientID: UInt64) {
        pool.withLock { pool in
            guard pool.entries[clientID] != nil else { return }
            let left = pool.entries[clientID]!.leftRequests
            if left > 0 && left != Int.max { pool.entries[clientID]!.leftRequests = left - 1 }
        }
    }

    fileprivate func hasNoClients() -> Bool {
        pool.withLock { $0.entries.isEmpty }
    }
    
    func closeAll() {
        let pooledConnections: [XHTTPXMUXMultiplexerPoolable] = pool.withLock { pool in
            let pooled = pool.entries.values.compactMap { $0.connection }
            pool.entries.removeAll()
            return pooled
        }
        for connection in pooledConnections { connection.poolClose() }
    }
}

nonisolated final class XHTTPXMUXMultiplexerRegistry: Sendable {
    nonisolated static let shared = XHTTPXMUXMultiplexerRegistry()
    private let managers = Mutex<[String: XHTTPXMUXMultiplexerManager]>([:])
    
    private init() {}
    
    func manager(
        key: String,
        config: XHTTPXMUXMultiplexerConfiguration,
        makeFactory: () -> (@Sendable () async -> XHTTPXMUXMultiplexerPoolable?)
    ) -> XHTTPXMUXMultiplexerManager {
        let factory = makeFactory()
        return managers.withLock { managers in
            if let existing = managers[key] { return existing }
            let manager = XHTTPXMUXMultiplexerManager(
                config: config, newConnection: factory, registry: self, registryKey: key
            )
            managers[key] = manager
            return manager
        }
    }
    
    fileprivate func evictIfEmpty(_ manager: XHTTPXMUXMultiplexerManager) {
        guard let key = manager.registryKey else { return }
        managers.withLock { managers in
            guard managers[key] === manager else { return }
            if manager.hasNoClients() {
                managers.removeValue(forKey: key)
            }
        }
    }
}

nonisolated extension XHTTPXMUXMultiplexerRegistry: TransportPool {
    func reclaim() {
        let allManagers: [XHTTPXMUXMultiplexerManager] = managers.withLock { managers in
            let all = Array(managers.values)
            managers.removeAll()
            return all
        }
        for manager in allManagers { manager.closeAll() }
    }
}

extension HTTP3Multiplexer: XHTTPXMUXMultiplexerPoolable {
    nonisolated var isPoolClosed: Bool { isClosed }
    nonisolated func poolClose() { close() }
}

// MARK: - Shared Multiplexing HTTP/2 Connection

nonisolated final class XHTTPH2Stream: Sendable {
    let streamId: UInt32
    private let multiplexer: XHTTPH2Multiplexer

    init(streamId: UInt32, multiplexer: XHTTPH2Multiplexer) {
        self.streamId = streamId
        self.multiplexer = multiplexer
    }

    func sendHeaders(_ headerBlock: Data, endStream: Bool) async throws {
        try await multiplexer.sendHeaders(streamId: streamId, headerBlock: headerBlock, endStream: endStream)
    }

    func sendData(_ data: Data, endStream: Bool) async throws {
        try await multiplexer.sendData(streamId: streamId, data: data, offset: 0, endStream: endStream)
    }

    func receive() async throws -> Data? {
        try await multiplexer.receive(streamId: streamId)
    }
    
    func drainResponse() { multiplexer.drain(streamId: streamId) }

    func close() { multiplexer.removeStream(streamId) }
}

nonisolated final class XHTTPH2Multiplexer: XHTTPXMUXMultiplexerPoolable, Sendable {
    private let transport: any ByteTransport
    private let frameReader: H2FrameReader
    
    nonisolated struct StreamState {
        var receiveBuffer = Data()
        var ended = false
        var failure: Error?
        var receiveWaiter: AsyncStream<Void>.Continuation?
        var draining = false
        var receiveConsumed = 0
        var sendWindow: Int
        var sendEnded = false
    }

    nonisolated private struct State {
        var streams: [UInt32: StreamState] = [:]
        var nextStreamId: UInt32 = 1
        var closedFlag = false
        var pumpTask: Task<Void, Never>?
        var retained: [any Sendable] = []
        
        var peerConnWindow = 65535
        var peerInitialWindow = 65535
        var maxFrameSize = 16384
        var flowGate = H2FlowGate()
        
        var connReceiveConsumed = 0
    }

    private let state = Mutex(State())
    private static let localStreamWindow = 4_194_304
    private static let localConnWindow: UInt32 = 1_073_741_824
    private static let maxReadBuffer = 8_388_608
    
    private struct PumpEffect {
        var frames: [Data] = []
    }

    init(transport: any ByteTransport) {
        self.transport = transport
        frameReader = H2FrameReader(maxBufferSize: Self.maxReadBuffer, receive: { try await transport.receive() })
    }

    /// Keeps a dial-time object (TLS/Reality client) alive for the connection's lifetime.
    func retain(_ object: any Sendable) {
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
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "shared H2 preface: \(error.localizedDescription)"))
        }

        // Read frames until the server's initial SETTINGS arrives, then start the pump.
        while true {
            let f: H2Framing.Frame
            do {
                f = try await frameReader.readFrame()
            } catch {
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "shared H2 settings read: \(error.localizedDescription)"))
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
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "shared H2: server GOAWAY"))
            default:
                break
            }
        }
    }

    // MARK: Read loop

    private func startPump() {
        let task = Task { [weak self] in
            while true {
                guard let self else { return }
                let f: H2Framing.Frame
                do {
                    f = try await self.frameReader.readFrame()
                } catch {
                    if case AnywhereError.proxy(.xhttp, .streamClosed) = error {
                        // Clean FIN of the shared H2 connection → EOF for every muxed stream.
                        self.failAll(nil)
                    } else {
                        self.failAll(AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)))
                    }
                    return
                }
                await self.routeFrame(f)
                if self.state.withLock({ $0.closedFlag }) { return }
            }
        }
        let stored: Bool = state.withLock { state in
            guard !state.closedFlag else { return false }
            state.pumpTask = task
            return true
        }
        if !stored { task.cancel() }
    }
    
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
            if let effect = handleEnd(streamId: decodedFrame.streamId, reset: true) { await apply(effect) }
        case XHTTPConnection.h2FrameGoaway:
            failAll(AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)))
        default:
            break
        }
    }
    
    private func apply(_ effect: PumpEffect) async {
        for frame in effect.frames { try? await transport.send(frame) }
    }

    private func handleData(streamId: UInt32, flags: UInt8, payload: Data) -> PumpEffect? {
        let endStream = flags & XHTTPConnection.h2FlagEndStream != 0
        return state.withLock { state in
            guard var stream = state.streams[streamId] else {
                state.connReceiveConsumed += payload.count
                guard let windowUpdateFrame = connWindowUpdateLocked(&state) else { return nil }
                return PumpEffect(frames: [windowUpdateFrame])
            }
            if stream.draining {
                state.connReceiveConsumed += payload.count
                stream.receiveConsumed += payload.count
                let updates = windowUpdatesLocked(streamId, &stream, &state)
                if endStream {
                    if stream.sendEnded { state.streams.removeValue(forKey: streamId) }
                    else { stream.ended = true; state.streams[streamId] = stream }
                } else {
                    state.streams[streamId] = stream
                }
                return PumpEffect(frames: updates)
            }
            if !payload.isEmpty { stream.receiveBuffer.append(payload) }
            if endStream { stream.ended = true }
            wakeReceiverLocked(&stream)
            state.streams[streamId] = stream
            return nil
        }
    }

    private func handleHeaders(streamId: UInt32, flags: UInt8, payload: Data) -> PumpEffect? {
        if let statusError = Self.h2StatusError(payload) {
            return state.withLock { state in
                guard var stream = state.streams[streamId] else { return nil }
                if stream.failure == nil {
                    stream.failure = AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "shared H2 stream \(streamId): \(statusError)"))
                }
                wakeReceiverLocked(&stream)
                state.streams[streamId] = stream
                return nil
            }
        }
        guard flags & XHTTPConnection.h2FlagEndStream != 0 else { return nil }
        return handleEnd(streamId: streamId)
    }

    private func handleEnd(streamId: UInt32, reset: Bool = false) -> PumpEffect? {
        state.withLock { state in
            guard var stream = state.streams[streamId] else { return nil }
            if stream.draining {
                if reset || stream.sendEnded { state.streams.removeValue(forKey: streamId) }
                else { stream.ended = true; state.streams[streamId] = stream }
                return nil
            }
            stream.ended = true
            wakeReceiverLocked(&stream)
            state.streams[streamId] = stream
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
    
    private func wakeReceiverLocked(_ stream: inout StreamState) {
        stream.receiveWaiter?.finish()
        stream.receiveWaiter = nil
    }

    // MARK: Send

    func sendHeaders(streamId: UInt32, headerBlock: Data, endStream: Bool) async throws {
        let f: Data? = state.withLock { state in
            if state.closedFlag { return nil }
            if endStream { state.streams[streamId]?.sendEnded = true }
            let flags = XHTTPConnection.h2FlagEndHeaders | (endStream ? XHTTPConnection.h2FlagEndStream : 0)
            return frame(type: XHTTPConnection.h2FrameHeaders, flags: flags, streamId: streamId, payload: headerBlock)
        }
        guard let f else { throw AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)) }
        try await transport.send(f)
    }

    func sendData(streamId: UInt32, data: Data, offset: Int, endStream: Bool) async throws {
        if offset >= data.count {
            guard endStream else { return }
            let f: Data? = state.withLock { state in
                if state.closedFlag { return nil }
                state.streams[streamId]?.sendEnded = true
                return frame(type: XHTTPConnection.h2FrameData, flags: XHTTPConnection.h2FlagEndStream, streamId: streamId, payload: Data())
            }
            guard let f else { throw AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)) }
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
                guard var stream = state.streams[streamId] else { return .closed }
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
                    frames.append(frame(type: XHTTPConnection.h2FrameData, flags: flags, streamId: streamId,
                                        payload: Data(data[data.startIndex + current ..< data.startIndex + current + chunk])))
                    current += chunk
                    remainingWindow -= chunk
                }
                let sent = window - remainingWindow
                state.peerConnWindow -= sent
                stream.sendWindow -= sent
                if current >= data.count && endStream { stream.sendEnded = true }
                state.streams[streamId] = stream
                return .built(frames: frames, nextOffset: current)
            }
            switch step {
            case .closed:
                throw AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil))
            case .park:
                await parkForFlow(streamId: streamId)
            case .built(let frames, let nextOffset):
                try await transport.send(frames)
                currentOffset = nextOffset
            }
        }
    }
    
    private func parkForFlow(streamId: UInt32) async {
        await H2FlowGate.park {
            state.withLock { state -> AsyncStream<Never>? in
                if state.closedFlag { return nil }
                guard let stream = state.streams[streamId] else { return nil }
                if min(state.peerConnWindow, stream.sendWindow) > 0 { return nil }
                return state.flowGate.enroll()
            }
        }
    }

    func receive(streamId: UInt32) async throws -> Data? {
        enum Outcome { case data(Data, frames: [Data]), eof, error(Error), wait(AsyncStream<Void>) }
        while true {
            let outcome: Outcome = state.withLock { state in
                guard var stream = state.streams[streamId] else { return .eof }
                if let failure = stream.failure {
                    return .error(failure)
                }
                if !stream.receiveBuffer.isEmpty {
                    let data = stream.receiveBuffer
                    stream.receiveBuffer = Data()
                    state.connReceiveConsumed += data.count
                    stream.receiveConsumed += data.count
                    let updates = windowUpdatesLocked(streamId, &stream, &state)
                    state.streams[streamId] = stream
                    return .data(data, frames: updates)
                }
                if stream.ended {
                    if stream.sendEnded { state.streams.removeValue(forKey: streamId) }
                    return .eof
                }
                if state.closedFlag {
                    return .error(AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil)))
                }
                let (waitStream, continuation) = AsyncStream<Void>.makeStream()
                stream.receiveWaiter = continuation
                state.streams[streamId] = stream
                return .wait(waitStream)
            }
            switch outcome {
            case .data(let data, let frames):
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
                try Task.checkCancellation()
            }
        }
    }

    // MARK: Streams

    func openStream() -> XHTTPH2Stream {
        state.withLock { state in
            let id = state.nextStreamId
            state.nextStreamId += 2
            state.streams[id] = StreamState(sendWindow: state.peerInitialWindow)
            return XHTTPH2Stream(streamId: id, multiplexer: self)
        }
    }

    func drain(streamId: UInt32) {
        state.withLock { state in
            guard var stream = state.streams[streamId] else { return }
            stream.draining = true
            stream.receiveBuffer = Data()
            state.streams[streamId] = stream
        }
    }

    func removeStream(_ streamId: UInt32) {
        let shouldReset: Bool = state.withLock { state in
            guard let stream = state.streams[streamId] else { return false }
            state.streams.removeValue(forKey: streamId)
            return !stream.ended && !state.closedFlag
        }
        if shouldReset {
            var code = Data(count: 4); code[3] = 0x08 // CANCEL
            let f = frame(type: XHTTPConnection.h2FrameRstStream, flags: 0, streamId: streamId, payload: code)
            let transport = self.transport
            Task { try? await transport.send(f) }
        }
    }

    func cancel() { failAll(AnywhereError.proxy(.xhttp, .connectionClosed(detail: nil))) }
    
    private func failAll(_ error: Error?) {
        let (didClose, pumpTask): (Bool, Task<Void, Never>?) = state.withLock { state in
            if state.closedFlag { return (false, nil) }
            state.closedFlag = true
            let pumpTask = state.pumpTask
            state.pumpTask = nil
            for (id, var stream) in state.streams {
                if let error {
                    if stream.failure == nil { stream.failure = error }
                } else {
                    stream.ended = true
                }
                wakeReceiverLocked(&stream)
                state.streams[id] = stream
            }
            state.flowGate.wakeAll()
            return (true, pumpTask)
        }
        guard didClose else { return }
        pumpTask?.cancel()
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
                    for key in state.streams.keys { state.streams[key]?.sendWindow += delta }
                } else if id == 0x05 { // MAX_FRAME_SIZE
                    state.maxFrameSize = Int(value)
                }
            }
            index += 6
        }
    }
    
    private func connWindowUpdateLocked(_ state: inout State) -> Data? {
        guard state.connReceiveConsumed >= Int(Self.localConnWindow) / 2 else { return nil }
        let inc = UInt32(state.connReceiveConsumed)
        state.connReceiveConsumed = 0
        return frame(type: XHTTPConnection.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: uint32Data(inc))
    }
    
    private func windowUpdatesLocked(_ streamId: UInt32, _ stream: inout StreamState, _ state: inout State) -> [Data] {
        var out: [Data] = []
        if let c = connWindowUpdateLocked(&state) { out.append(c) }
        if stream.receiveConsumed >= Self.localStreamWindow / 2, !stream.ended {
            let inc = UInt32(stream.receiveConsumed)
            stream.receiveConsumed = 0
            out.append(
                frame(type: XHTTPConnection.h2FrameWindowUpdate, flags: 0, streamId: streamId, payload: uint32Data(inc))
            )
        }
        return out
    }

    private func readUInt32(_ d: Data) -> UInt32 { H2Framing.readUInt32(d) }

    private func uint32Data(_ v: UInt32) -> Data { H2Framing.uint32Data(v) }
}

// MARK: - Pooled HTTP/1.1 Upload Connection

nonisolated final class XHTTPH1Multiplexer: XHTTPXMUXMultiplexerPoolable, Sendable {
    private let transport: any ByteTransport

    nonisolated private enum ParseState { case headers; case body(Int) }

    nonisolated private struct State {
        var outstanding = 0
        var dirty = false
        var closed = false
        var retained: [any Sendable] = []
        var parseState: ParseState = .headers
        var parseBuffer = Data()
        var lease: XHTTPXMUXMultiplexerLease?
        var drainTask: Task<Void, Never>?
    }

    private let state = Mutex(State())
    
    var lease: XHTTPXMUXMultiplexerLease? { state.withLock { $0.lease } }
    func adoptLease(_ lease: XHTTPXMUXMultiplexerLease) { state.withLock { $0.lease = lease } }

    init(transport: any ByteTransport) {
        self.transport = transport
        startDrain()
    }
    
    func retain(_ object: any Sendable) { state.withLock { $0.retained.append(object) } }

    var isPoolClosed: Bool { state.withLock { $0.closed || $0.dirty } }

    func poolClose() {
        let (alreadyClosed, drainTask): (Bool, Task<Void, Never>?) = state.withLock { state in
            if state.closed { return (true, nil) }
            state.closed = true
            let drainTask = state.drainTask
            state.drainTask = nil
            return (false, drainTask)
        }
        if alreadyClosed { return }
        drainTask?.cancel()
        transport.cancel()
    }
    
    var sessionTransport: any ByteTransport {
        SessionTransport(multiplexer: self)
    }
    
    private final class SessionTransport: ByteTransport, Sendable {
        private let multiplexer: XHTTPH1Multiplexer

        init(multiplexer: XHTTPH1Multiplexer) {
            self.multiplexer = multiplexer
        }

        var isReady: Bool { !multiplexer.isPoolClosed }

        func send(_ data: Data) async throws {
            multiplexer.state.withLock { $0.outstanding += 1 }
            try await multiplexer.transport.send(data)
        }

        func receive() async throws -> TransportChunk { .end }

        func cancel() { multiplexer.releaseToPool() }
    }

    private func releaseToPool() {
        let lease: XHTTPXMUXMultiplexerLease? = state.withLock { state in
            if state.dirty || state.outstanding != 0 || !state.parseBuffer.isEmpty { state.dirty = true }
            let lease = state.lease
            state.lease = nil
            return lease
        }
        lease?.release()
    }

    // MARK: Internal drain + response parser

    private func startDrain() {
        let task = Task { [weak self] in
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
        let stored: Bool = state.withLock { state in
            guard !state.closed else { return false }
            state.drainTask = task
            return true
        }
        if !stored { task.cancel() }
    }
    
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
    
    private func completeResponseLocked(_ state: inout State) {
        state.parseState = .headers
        if state.outstanding <= 0 { state.dirty = true; return }
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
