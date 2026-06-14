//
//  XHTTPConnection.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation

private let logger = AnywhereLogger(category: "XHTTP")

// MARK: - XHTTP Channel Role

/// Which half of an XHTTP session a connection drives; a detached session pairs
/// a `.downloadOnly` leg (GET) with an `.uploadOnly` leg (POSTs) sharing one session ID.
enum XHTTPChannelRole {
    case combined
    case downloadOnly
    case uploadOnly
}

// MARK: - XHTTPConnection

/// XHTTP connection implementing packet-up, stream-up, and stream-one modes.
nonisolated class XHTTPConnection {

    let configuration: XHTTPConfiguration
    let mode: XHTTPMode
    let sessionId: String

    // Download / stream-one connection
    let downloadSend: (Data, @escaping (Error?) -> Void) -> Void
    let downloadReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    let downloadCancel: () -> Void

    // Upload connection factory (packet-up and stream-up)
    let uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)?

    // Upload connection state (packet-up and stream-up)
    var uploadSend: ((Data, @escaping (Error?) -> Void) -> Void)?
    var uploadReceive: ((@escaping (Data?, Bool, Error?) -> Void) -> Void)?
    var uploadCancel: (() -> Void)?

    /// Role of this connection in an up/download-detached session.
    var role: XHTTPChannelRole = .combined
    /// Upload leg owned by this download leg when detached; sends are delegated to it.
    var uploadChannel: XHTTPConnection?

    /// Non-nil when the transport is a pooled, shared xmux connection; teardown then
    /// releases the lease instead of closing the shared transport (others may still use it).
    var xmuxLease: XMUXLease?

    // State
    var nextSeq: Int64 = 0
    var chunkedDecoder = ChunkedTransferDecoder()
    var downloadHeadersParsed = false
    var _isConnected = false
    let lock = UnfairLock()

    // Packet-up batching: sends queue here; a single in-flight flush drains one POST per `scMinPostsIntervalMs`.
    var packetUpQueue: [(Data, (Error?) -> Void)] = []
    var packetUpFlushPending = false
    var packetUpLastFlushTime: UInt64 = 0

    /// Leftover data after HTTP response headers.
    var headerBuffer = Data()

    // HTTP/2 state
    let useHTTP2: Bool
    /// Demuxes the byte transport into H2 frames (1:1 path); idle on H3/shared-H2 legs.
    let h2FrameReader: H2FrameReader
    var h2DataBuffer = Data()

    /// Caps the H2 frame reader's buffer to bound memory growth.
    static let maxH2ReadBufferSize = 2_097_152
    /// Connection-level send window (RFC 7540 §6.9); updated by WINDOW_UPDATE on stream 0 only.
    var h2PeerConnectionWindow: Int = 65535
    /// Send window for the active upload stream; updated by SETTINGS INITIAL_WINDOW_SIZE and stream WINDOW_UPDATE.
    var h2PeerStreamSendWindow: Int = 65535
    var h2PeerInitialWindowSize: Int = 65535
    var h2LocalWindowSize: Int = 4_194_304  // Match h2StreamWindowSize (4MB)
    var h2MaxFrameSize: Int = 16384
    var h2ResponseReceived = false
    var h2StreamClosed = false

    /// Sends blocked on flow control; the WINDOW_UPDATE handler invokes all, each re-checks its window.
    var h2FlowResumptions: [() -> Void] = []
    /// Send windows for packet-up streams blocked on flow control, keyed by stream ID.
    var h2PacketStreamWindows: [UInt32: Int] = [:]

    /// Bytes received but not yet acknowledged via WINDOW_UPDATE (connection level).
    var h2ConnectionReceiveConsumed: Int = 0
    /// Bytes received but not yet acknowledged via WINDOW_UPDATE (stream level, download stream).
    var h2StreamReceiveConsumed: Int = 0

    // HTTP/2 multiplexing state (for stream-up / packet-up over H2)
    var h2UploadStreamId: UInt32 = 3      // Fixed upload stream for stream-up
    var h2NextPacketStreamId: UInt32 = 3   // Next stream ID for packet-up uploads
    /// Download (GET) stream id when reading H2 frames; set out of range on an
    /// `.uploadOnly` leg so its POST responses are drained, not delivered.
    var h2DownloadStreamId: UInt32 = 1

    // HTTP/3 state (modes multiplexed onto QUIC streams via HTTP3Session)
    var h3Session: HTTP3Session?
    /// Download stream: the GET response body, or the full-duplex stream in stream-one.
    var h3Download: HTTP3RequestStream?
    /// Persistent upload POST stream (stream-up only).
    var h3Upload: HTTP3RequestStream?
    var h3Closed = false

    var useHTTP3: Bool { h3Session != nil }

    // Pooled shared-H2 multiplexing state (xmux). When `sharedH2` is set, this session's
    // streams ride a shared connection instead of running its own 1:1 H2 framing.
    var sharedH2: XHTTPSharedH2Connection?
    /// GET download stream, or the full-duplex stream in stream-one.
    var sharedH2Download: XHTTPH2Stream?
    /// Persistent upload POST stream (stream-up only).
    var sharedH2Upload: XHTTPH2Stream?

    var usesSharedH2: Bool { sharedH2 != nil }

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
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

    /// Returns the request path with query-based padding appended if needed.
    func pathWithQueryPadding(_ basePath: String) -> String {
        if configuration.xPaddingObfsMode && configuration.xPaddingPlacement == .query {
            let padding = configuration.generatePadding()
            return "\(basePath)?\(configuration.xPaddingKey)=\(padding)"
        }
        return basePath
    }

    // MARK: - Session/Seq Metadata

    /// Applies session ID to the request path, headers, query, or cookie based on configuration.
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

    /// Returns query string components for session/seq placed in query params.
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

    /// Applies sequence number to the request path, headers, or cookie based on configuration.
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

    /// Whether packet-up payloads travel outside the request body (header/cookie placement).
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
        let chars = Array(encoded)
        let chunkSize = configuration.uplinkChunkSize > 0 ? configuration.uplinkChunkSize : chars.count
        var fields: [UplinkDataField] = []
        var start = 0
        var index = 0
        while start < chars.count {
            let end = min(start + chunkSize, chars.count)
            let chunk = String(chars[start..<end])
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

    /// Designated initializer taking a pre-built download `TransportClosures`.
    init(download: TransportClosures, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.useHTTP2 = useHTTP2
        self.uploadConnectionFactory = uploadConnectionFactory
        self.downloadSend = download.send
        self.downloadReceive = download.receive
        self.downloadCancel = download.cancel
        self.h2FrameReader = H2FrameReader(maxBufferSize: Self.maxH2ReadBufferSize, receive: download.receive)
        self._isConnected = true
    }

    convenience init(transport: RawTCPSocket, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.init(download: TransportClosures(rawTCP: transport), configuration: configuration, mode: mode, sessionId: sessionId, useHTTP2: useHTTP2, uploadConnectionFactory: uploadConnectionFactory)
    }

    convenience init(tlsConnection: TLSRecordConnection, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.init(download: TransportClosures(tls: tlsConnection), configuration: configuration, mode: mode, sessionId: sessionId, useHTTP2: useHTTP2, uploadConnectionFactory: uploadConnectionFactory)
    }

    convenience init(tunnel: ProxyConnection, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.init(download: TransportClosures(tunnel: tunnel), configuration: configuration, mode: mode, sessionId: sessionId, useHTTP2: useHTTP2, uploadConnectionFactory: uploadConnectionFactory)
    }

    /// Over HTTP/3, byte I/O is multiplexed by the session, so the download closures are the no-op `.unused`.
    convenience init(h3Session: HTTP3Session, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String) {
        self.init(download: .unused, configuration: configuration, mode: mode, sessionId: sessionId)
        self.h3Session = h3Session
    }

    /// Over a shared multiplexing H2 connection (xmux), streams are virtual, so the download
    /// closures are the no-op `.unused` and `useHTTP2` stays false (the shared path is used instead).
    convenience init(sharedH2: XHTTPSharedH2Connection, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String) {
        self.init(download: .unused, configuration: configuration, mode: mode, sessionId: sessionId)
        self.sharedH2 = sharedH2
    }

    // MARK: - Setup

    /// Performs the initial HTTP handshake; detached sessions set up the download leg, then the upload leg.
    func performSetup(completion: @escaping (Error?) -> Void) {
        guard let uploadChannel else {
            performLegSetup(completion: completion)
            return
        }
        performLegSetup { error in
            if let error {
                completion(error)
                return
            }
            uploadChannel.performLegSetup(completion: completion)
        }
    }

    private func performLegSetup(completion: @escaping (Error?) -> Void) {
        if usesSharedH2 {
            performSharedH2Setup(completion: completion)
        } else if useHTTP3 {
            performH3Setup(completion: completion)
        } else if useHTTP2 {
            performH2Setup(completion: completion)
        } else {
            switch role {
            case .downloadOnly:
                performDownloadOnlyHTTP11Setup(completion: completion)
            case .uploadOnly:
                performUploadOnlyHTTP11Setup(completion: completion)
            case .combined:
                if mode == .streamOne {
                    performStreamOneSetup(completion: completion)
                } else if mode == .streamUp {
                    performStreamUpSetup(completion: completion)
                } else {
                    performPacketUpSetup(completion: completion)
                }
            }
        }
    }

    // MARK: - Send

    func send(data: Data, completion: @escaping (Error?) -> Void) {
        // Detached: writes go to the upload leg; this (download) leg only reads.
        if let uploadChannel {
            uploadChannel.send(data: data, completion: completion)
            return
        }
        if mode == .packetUp {
            enqueuePacketUpSend(data: data, completion: completion)
            return
        }
        if usesSharedH2 {
            // stream-up sends on the upload stream; stream-one on the full-duplex download stream.
            guard let stream = (mode == .streamUp) ? sharedH2Upload : sharedH2Download else {
                completion(XHTTPError.connectionClosed)
                return
            }
            stream.sendData(data, endStream: false, completion: completion)
            return
        }
        if useHTTP3 {
            let stream = (mode == .streamUp) ? h3Upload : h3Download
            guard let stream else { completion(XHTTPError.connectionClosed); return }
            stream.sendBody(data, fin: false, completion: completion)
            return
        }
        if useHTTP2 {
            if mode == .streamUp {
                sendH2Data(data: data, streamId: h2UploadStreamId, completion: completion)
            } else {
                // stream-one: upload and download share stream 1
                sendH2Data(data: data, streamId: 1, completion: completion)
            }
        } else if mode == .streamOne {
            sendStreamOne(data: data, completion: completion)
        } else if mode == .streamUp {
            sendStreamUp(data: data, completion: completion)
        }
    }

    func send(data: Data) {
        send(data: data) { _ in }
    }

    // MARK: - Receive

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        if usesSharedH2 {
            guard let download = sharedH2Download else { completion(nil, nil); return }
            download.receive(completion: completion)
            return
        }
        if useHTTP3 {
            receiveH3Data(completion: completion)
            return
        }
        if useHTTP2 {
            receiveH2Data(completion: completion)
            return
        }

        lock.lock()
        if let decoded = chunkedDecoder.nextChunk() {
            lock.unlock()
            completion(decoded, nil)
            return
        }

        if chunkedDecoder.isFinished {
            lock.unlock()
            completion(nil, nil)
            return
        }
        lock.unlock()

        downloadReceive { [weak self] data, _, error in
            guard let self else {
                completion(nil, XHTTPError.connectionClosed)
                return
            }

            if let error {
                completion(nil, error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(nil, nil) // EOF
                return
            }

            self.lock.lock()
            self.chunkedDecoder.feed(data)

            if let decoded = self.chunkedDecoder.nextChunk() {
                self.lock.unlock()
                completion(decoded, nil)
            } else if self.chunkedDecoder.isFinished {
                self.lock.unlock()
                completion(nil, nil)
            } else {
                self.lock.unlock()
                self.receive(completion: completion)
            }
        }
    }

    // MARK: - Cancel

    func cancel() {
        lock.lock()
        _isConnected = false
        chunkedDecoder = ChunkedTransferDecoder()
        headerBuffer.removeAll()
        h2FrameReader.reset()
        h2DataBuffer.removeAll()
        h2StreamClosed = true
        h3Closed = true
        let h3Dl = h3Download
        let h3Up = h3Upload
        let h3Sess = h3Session
        let sh2Dl = sharedH2Download
        let sh2Up = sharedH2Upload
        sharedH2Download = nil
        sharedH2Upload = nil
        let lease = xmuxLease
        xmuxLease = nil
        let uploadCancelFn = uploadCancel
        uploadSend = nil
        uploadReceive = nil
        uploadCancel = nil
        let pendingPackets = packetUpQueue
        packetUpQueue.removeAll()
        packetUpFlushPending = false
        // Sends parked on H2 flow control; each re-enters its send, sees the closed stream,
        // and completes with `.connectionClosed` rather than hanging forever.
        let flowResumptions = h2FlowResumptions
        h2FlowResumptions.removeAll()
        lock.unlock()

        for (_, completion) in pendingPackets {
            completion(XHTTPError.connectionClosed)
        }
        for resume in flowResumptions {
            resume()
        }

        downloadCancel()
        uploadCancelFn?()
        h3Dl?.close()
        h3Up?.close()
        sh2Dl?.close()
        sh2Up?.close()
        if let lease {
            // Pooled transport: keep it open for other/future sessions; just release our slot.
            lease.release()
        } else {
            h3Sess?.close()
        }
        uploadChannel?.cancel()
    }

    // MARK: - Packet-Up Batching

    /// Queues a write for the next batched POST in packet-up mode.
    func enqueuePacketUpSend(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if !_isConnected || (useHTTP2 && h2StreamClosed) || (useHTTP3 && h3Closed) {
            lock.unlock()
            completion(XHTTPError.connectionClosed)
            return
        }
        packetUpQueue.append((data, completion))
        let shouldSchedule = !packetUpFlushPending
        if shouldSchedule {
            packetUpFlushPending = true
        }
        lock.unlock()
        if shouldSchedule {
            schedulePacketUpFlush()
        }
    }

    /// Schedules a flush respecting `scMinPostsIntervalMs` since the last flush start.
    private func schedulePacketUpFlush() {
        lock.lock()
        let delayMs = configuration.scMinPostsIntervalMs
        let elapsedMs: Int
        if packetUpLastFlushTime == 0 {
            elapsedMs = .max
        } else {
            let now = DispatchTime.now().uptimeNanoseconds
            let elapsedNs = now &- packetUpLastFlushTime
            elapsedMs = Int(min(elapsedNs / 1_000_000, UInt64(Int.max)))
        }
        lock.unlock()

        let runFlush: () -> Void = { [weak self] in
            self?.flushPacketUpBatch()
        }
        if delayMs <= 0 || elapsedMs >= delayMs {
            DispatchQueue.global().async(execute: runFlush)
        } else {
            let remaining = delayMs - elapsedMs
            DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(remaining), execute: runFlush)
        }
    }

    /// Drains the queue (up to `scMaxEachPostBytes`) into one POST, then chains into the next flush if needed.
    private func flushPacketUpBatch() {
        lock.lock()

        if !_isConnected || (useHTTP2 && h2StreamClosed) || (useHTTP3 && h3Closed) {
            let pending = packetUpQueue
            packetUpQueue.removeAll()
            packetUpFlushPending = false
            lock.unlock()
            for (_, completion) in pending {
                completion(XHTTPError.connectionClosed)
            }
            return
        }

        guard !packetUpQueue.isEmpty else {
            packetUpFlushPending = false
            lock.unlock()
            return
        }

        let maxSize = max(1, configuration.scMaxEachPostBytes)
        var batchedData = Data()
        var batchedCompletions: [(Error?) -> Void] = []
        while !packetUpQueue.isEmpty {
            let (chunk, completion) = packetUpQueue[0]
            // The first chunk may exceed maxSize on its own (sendPacketUp re-splits it).
            if !batchedData.isEmpty && batchedData.count + chunk.count > maxSize {
                break
            }
            batchedData.append(chunk)
            batchedCompletions.append(completion)
            packetUpQueue.removeFirst()
        }

        packetUpLastFlushTime = DispatchTime.now().uptimeNanoseconds
        let isShared = usesSharedH2
        let isH2 = useHTTP2
        let isH3 = useHTTP3
        lock.unlock()

        let onComplete: (Error?) -> Void = { [weak self] error in
            for completion in batchedCompletions {
                completion(error)
            }
            guard let self else { return }
            self.lock.lock()
            if error != nil || self.packetUpQueue.isEmpty {
                self.packetUpFlushPending = false
                self.lock.unlock()
                return
            }
            // packetUpFlushPending stays true; chain into the next flush.
            self.lock.unlock()
            self.schedulePacketUpFlush()
        }

        if isShared {
            sendSharedH2PacketUp(data: batchedData, completion: onComplete)
        } else if isH3 {
            sendH3PacketUp(data: batchedData, completion: onComplete)
        } else if isH2 {
            sendH2PacketUp(data: batchedData, completion: onComplete)
        } else {
            sendPacketUp(data: batchedData, completion: onComplete)
        }
    }
}

// MARK: - XMUX Connection Pooling

/// A poolable underlying XHTTP transport that multiple XHTTP sessions can share
/// (a multiplexing H2 connection or an H3/QUIC session).
protocol XMUXPoolable: AnyObject {
    /// True once the connection can no longer carry new sessions.
    var isPoolClosed: Bool { get }
    /// Tears down the underlying connection once the pool retires it with no active leases.
    func poolClose()
}

/// A reserved slot on a pooled connection. The holder drives one XHTTP session over
/// `connection`, calls `noteRequest()` per HTTP request, and `release()` once when done.
nonisolated final class XMUXLease {
    let connection: XMUXPoolable
    private weak var manager: XMUXManager?
    /// Strong so the connection outlives all its sessions, even after the pool retires it.
    private let client: XMUXClient
    private var released = false
    private let lock = UnfairLock()

    init(connection: XMUXPoolable, manager: XMUXManager, client: XMUXClient) {
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
        lock.lock()
        if released { lock.unlock(); return }
        released = true
        lock.unlock()
        manager?.releaseSlot(client)
    }
}

/// One pooled connection plus its xmux usage/rotation counters.
nonisolated final class XMUXClient {
    enum State { case dialing, ready, failed }
    var state: State = .dialing
    var connection: XMUXPoolable?
    /// Concurrent sessions currently leased on this connection.
    var openUsage = 0
    /// Remaining session assignments (`cMaxReuseTimes - 1`); -1 = unlimited.
    var leftUsage: Int
    /// Remaining HTTP requests (`hMaxRequestTimes`); `Int.max` = unlimited.
    var leftRequests: Int
    /// Wall-clock retirement time (`hMaxReusableSecs`); nil = never.
    let unreusableAt: CFAbsoluteTime?
    /// Completions waiting for this connection's in-flight dial to finish.
    var waiters: [(XMUXPoolable?) -> Void] = []

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

/// Pools and rotates underlying connections for one XHTTP destination.
/// All state is guarded by `lock`.
nonisolated final class XMUXManager {
    private let config: XMUXConfiguration
    /// `maxConcurrency` range rolled once at creation, fixed for the manager's lifetime.
    private let concurrency: Int
    /// `maxConnections` resolved once at creation.
    private let connections: Int
    private let newConnection: (@escaping (XMUXPoolable?) -> Void) -> Void
    private var clients: [XMUXClient] = []
    private let lock = UnfairLock()

    init(config: XMUXConfiguration, newConnection: @escaping (@escaping (XMUXPoolable?) -> Void) -> Void) {
        self.config = config
        self.concurrency = config.maxConcurrency.random()
        self.connections = config.maxConnections.random()
        self.newConnection = newConnection
    }

    /// Acquires a slot, reusing a pooled connection or dialing a new one per policy.
    /// Completes with nil if a freshly-dialed connection fails.
    func acquire(completion: @escaping (XMUXLease?) -> Void) {
        // Prune retired clients; tear down those with no active sessions left.
        lock.lock()
        let now = CFAbsoluteTimeGetCurrent()
        var retiredIdle: [XMUXPoolable] = []
        clients.removeAll { client in
            guard client.isRetired(now: now) else { return false }
            if client.openUsage == 0, let conn = client.connection { retiredIdle.append(conn) }
            return true
        }
        lock.unlock()
        for conn in retiredIdle { conn.poolClose() }

        lock.lock()
        if let client = selectReusable() {
            client.openUsage += 1
            if client.leftUsage > 0 { client.leftUsage -= 1 }
            switch client.state {
            case .ready:
                let conn = client.connection!
                lock.unlock()
                completion(makeLease(conn, client))
            case .dialing:
                // Share this still-dialing connection once its dial resolves.
                client.waiters.append { [weak self, weak client] conn in
                    guard let self, let client, let conn else { completion(nil); return }
                    completion(self.makeLease(conn, client))
                }
                lock.unlock()
            case .failed:
                lock.unlock()
                completion(nil)
            }
            return
        }

        // Policy requires a new pooled connection.
        let reuseRand = config.cMaxReuseTimes.random()
        let leftUsage = reuseRand > 0 ? reuseRand - 1 : -1
        let reqRand = config.hMaxRequestTimes.random()
        let leftRequests = reqRand > 0 ? reqRand : Int.max
        let secsRand = config.hMaxReusableSecs.random()
        let unreusableAt: CFAbsoluteTime? = secsRand > 0 ? now + Double(secsRand) : nil

        let client = XMUXClient(leftUsage: leftUsage, leftRequests: leftRequests, unreusableAt: unreusableAt)
        client.openUsage = 1
        clients.append(client)
        lock.unlock()

        newConnection { [weak self, weak client] conn in
            guard let self, let client else { completion(nil); return }
            self.lock.lock()
            let waiters = client.waiters
            client.waiters.removeAll()
            if let conn {
                client.connection = conn
                client.state = .ready
                self.lock.unlock()
                completion(self.makeLease(conn, client))
            } else {
                client.state = .failed
                self.clients.removeAll { $0 === client }
                self.lock.unlock()
                completion(nil)
            }
            for waiter in waiters { waiter(conn) }
        }
    }

    /// Selects a reusable pooled connection (lock held); nil ⇒ dial a new connection.
    private func selectReusable() -> XMUXClient? {
        if clients.isEmpty { return nil }
        if connections > 0 && clients.count < connections { return nil }
        let eligible = concurrency > 0 ? clients.filter { $0.openUsage < concurrency } : clients
        guard !eligible.isEmpty else { return nil }
        return eligible.randomElement()
    }

    private func makeLease(_ conn: XMUXPoolable, _ client: XMUXClient) -> XMUXLease {
        XMUXLease(connection: conn, manager: self, client: client)
    }

    func releaseSlot(_ client: XMUXClient) {
        lock.lock()
        if client.openUsage > 0 { client.openUsage -= 1 }
        // A retired connection with no remaining sessions is dropped and torn down.
        let shouldClose = client.openUsage == 0 && client.isRetired(now: CFAbsoluteTimeGetCurrent())
        if shouldClose { clients.removeAll { $0 === client } }
        lock.unlock()
        if shouldClose { client.connection?.poolClose() }
    }

    func noteRequest(_ client: XMUXClient) {
        lock.lock()
        if client.leftRequests > 0 && client.leftRequests != Int.max { client.leftRequests -= 1 }
        lock.unlock()
    }
}

/// Global registry of per-destination xmux managers.
nonisolated final class XMUXRegistry {
    static let shared = XMUXRegistry()
    private var managers: [String: XMUXManager] = [:]
    private let lock = UnfairLock()
    private init() {}

    /// Returns the manager for `key`, creating it on first use with a destination-bound
    /// connection factory. The factory must not capture per-session/per-flow state.
    func manager(
        key: String,
        config: XMUXConfiguration,
        makeFactory: () -> (@escaping (XMUXPoolable?) -> Void) -> Void
    ) -> XMUXManager {
        lock.lock()
        defer { lock.unlock() }
        if let existing = managers[key] { return existing }
        let manager = XMUXManager(config: config, newConnection: makeFactory())
        managers[key] = manager
        return manager
    }
}

/// An HTTP/3 session can carry many XHTTP sessions as independent QUIC streams.
extension HTTP3Session: XMUXPoolable {
    var isPoolClosed: Bool { poolIsClosed }
    func poolClose() { close() }
}

// MARK: - Shared Multiplexing HTTP/2 Connection (xmux)
//
// Carries many XHTTP sessions as independent H2 streams over one socket. Gated behind
// xmux config; the default 1:1 H2 path (XHTTPConnection+H2*.swift) is unchanged.

/// One virtual HTTP/2 stream on a shared connection: a single XHTTP request/response.
/// All mutable state is guarded by the owning connection's lock.
nonisolated final class XHTTPH2Stream {
    let streamId: UInt32
    fileprivate weak var connection: XHTTPSharedH2Connection?

    fileprivate var receiveBuffer = Data()
    fileprivate var ended = false
    fileprivate var failure: Error?
    fileprivate var pendingReceive: ((Data?, Error?) -> Void)?
    /// When true, inbound data is discarded (an upload leg's response).
    fileprivate var draining = false
    fileprivate var receiveConsumed = 0

    fileprivate var sendWindow: Int

    init(streamId: UInt32, connection: XHTTPSharedH2Connection, sendWindow: Int) {
        self.streamId = streamId
        self.connection = connection
        self.sendWindow = sendWindow
    }

    func sendHeaders(_ headerBlock: Data, endStream: Bool, completion: @escaping (Error?) -> Void) {
        guard let connection else { completion(XHTTPError.connectionClosed); return }
        connection.sendHeaders(streamId: streamId, headerBlock: headerBlock, endStream: endStream, completion: completion)
    }

    func sendData(_ data: Data, endStream: Bool, completion: @escaping (Error?) -> Void) {
        guard let connection else { completion(XHTTPError.connectionClosed); return }
        connection.sendData(stream: self, data: data, offset: 0, endStream: endStream, completion: completion)
    }

    func receive(completion: @escaping (Data?, Error?) -> Void) {
        guard let connection else { completion(nil, XHTTPError.connectionClosed); return }
        connection.receive(stream: self, completion: completion)
    }

    /// Discards any further inbound data on this stream (an upload leg's response).
    func drainResponse() { connection?.drain(stream: self) }

    func close() { connection?.closeStream(self) }
}

/// A shared HTTP/2 connection multiplexing many XHTTP sessions (xmux). Owns one byte
/// transport; one always-on read loop demuxes frames to per-stream buffers. State under `lock`.
nonisolated final class XHTTPSharedH2Connection: XMUXPoolable {
    private let transportSend: (Data, @escaping (Error?) -> Void) -> Void
    private let transportCancel: () -> Void
    /// Demuxes the shared socket into H2 frames; one always-on read loop drives it.
    private let frameReader: H2FrameReader

    private let lock = UnfairLock()
    private var streams: [UInt32: XHTTPH2Stream] = [:]
    private var nextStreamId: UInt32 = 1
    private var closedFlag = false
    /// Holds dial objects (TLS/Reality client) alive for the connection's lifetime.
    private var retained: [AnyObject] = []

    // Peer flow-control windows (for our sends).
    private var peerConnWindow = 65535
    private var peerInitialWindow = 65535
    private var maxFrameSize = 16384
    private var flowResumptions: [() -> Void] = []

    // Local receive-window accounting (replenished as sessions consume data).
    private var connReceiveConsumed = 0
    private static let localStreamWindow = 4_194_304          // 4 MB
    private static let localConnWindow: UInt32 = 1_073_741_824 // 1 GB
    private static let maxReadBuffer = 8_388_608               // 8 MB

    init(transport: TransportClosures) {
        transportSend = transport.send
        transportCancel = transport.cancel
        frameReader = H2FrameReader(maxBufferSize: Self.maxReadBuffer, receive: transport.receive)
    }

    /// Keeps a dial-time object (TLS/Reality client) alive for the connection's lifetime.
    func retain(_ object: AnyObject) {
        lock.lock(); retained.append(object); lock.unlock()
    }

    var isPoolClosed: Bool { lock.lock(); defer { lock.unlock() }; return closedFlag }
    func poolClose() { cancel() }

    // MARK: Setup

    /// Sends the client preface + SETTINGS, completing once the server's SETTINGS arrives.
    func connect(completion: @escaping (Error?) -> Void) {
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

        transportSend(initData) { [weak self] error in
            guard let self else { completion(XHTTPError.connectionClosed); return }
            if let error { completion(XHTTPError.setupFailed("shared H2 preface: \(error.localizedDescription)")); return }
            self.awaitServerSettings(completion: completion)
        }
    }

    private func awaitServerSettings(completion: @escaping (Error?) -> Void) {
        frameReader.readFrame { [weak self] result in
            guard let self else { completion(XHTTPError.connectionClosed); return }
            switch result {
            case .failure(let e):
                completion(XHTTPError.setupFailed("shared H2 settings read: \(e.localizedDescription)"))
            case .success(let f):
                switch f.type {
                case XHTTPConnection.h2FrameSettings where f.flags & XHTTPConnection.h2FlagAck == 0:
                    self.applySettings(f.payload)
                    self.transportSend(self.frame(type: XHTTPConnection.h2FrameSettings,
                                                  flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: Data())) { _ in }
                    self.startPump()
                    completion(nil)
                case XHTTPConnection.h2FrameWindowUpdate:
                    self.handleConnWindowUpdate(f.payload)
                    self.awaitServerSettings(completion: completion)
                case XHTTPConnection.h2FramePing where f.flags & XHTTPConnection.h2FlagAck == 0:
                    self.transportSend(self.frame(type: XHTTPConnection.h2FramePing,
                                                  flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: f.payload)) { _ in }
                    self.awaitServerSettings(completion: completion)
                case XHTTPConnection.h2FrameGoaway:
                    completion(XHTTPError.setupFailed("shared H2: server GOAWAY"))
                default:
                    self.awaitServerSettings(completion: completion)
                }
            }
        }
    }

    // MARK: Read loop

    private func startPump() {
        frameReader.readFrame { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure:
                self.failAll(XHTTPError.connectionClosed)
            case .success(let f):
                self.dispatch(f)
                self.lock.lock()
                let closed = self.closedFlag
                self.lock.unlock()
                if !closed { self.startPump() }
            }
        }
    }

    private func dispatch(_ f: (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)) {
        switch f.type {
        case XHTTPConnection.h2FrameData:
            handleData(streamId: f.streamId, flags: f.flags, payload: f.payload)
        case XHTTPConnection.h2FrameHeaders:
            handleHeaders(streamId: f.streamId, flags: f.flags)
        case XHTTPConnection.h2FrameWindowUpdate:
            if f.streamId == 0 { handleConnWindowUpdate(f.payload) }
            else { handleStreamWindowUpdate(streamId: f.streamId, payload: f.payload) }
        case XHTTPConnection.h2FrameSettings where f.flags & XHTTPConnection.h2FlagAck == 0:
            applySettings(f.payload)
            transportSend(frame(type: XHTTPConnection.h2FrameSettings, flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: Data())) { _ in }
        case XHTTPConnection.h2FramePing where f.flags & XHTTPConnection.h2FlagAck == 0:
            transportSend(frame(type: XHTTPConnection.h2FramePing, flags: XHTTPConnection.h2FlagAck, streamId: 0, payload: f.payload)) { _ in }
        case XHTTPConnection.h2FrameRstStream:
            handleEnd(streamId: f.streamId)
        case XHTTPConnection.h2FrameGoaway:
            failAll(XHTTPError.connectionClosed)
        default:
            break
        }
    }

    private func handleData(streamId: UInt32, flags: UInt8, payload: Data) {
        let endStream = flags & XHTTPConnection.h2FlagEndStream != 0
        lock.lock()
        guard let stream = streams[streamId] else {
            // Unknown/closed stream: still replenish the connection window so peers keep flowing.
            connReceiveConsumed += payload.count
            let wu = connWindowUpdateLocked()
            lock.unlock()
            if let wu { transportSend(wu) { _ in } }
            return
        }
        if stream.draining {
            connReceiveConsumed += payload.count
            stream.receiveConsumed += payload.count
            let updates = windowUpdatesLocked(stream)
            if endStream { streams.removeValue(forKey: streamId) }
            lock.unlock()
            for u in updates { transportSend(u) { _ in } }
            return
        }
        if !payload.isEmpty { stream.receiveBuffer.append(payload) }
        if endStream { stream.ended = true }
        let work = makeDeliveryLocked(stream)
        lock.unlock()
        work?()
    }

    private func handleHeaders(streamId: UInt32, flags: UInt8) {
        // Body arrives as DATA; only a HEADERS carrying END_STREAM closes the stream.
        guard flags & XHTTPConnection.h2FlagEndStream != 0 else { return }
        handleEnd(streamId: streamId)
    }

    private func handleEnd(streamId: UInt32) {
        lock.lock()
        guard let stream = streams[streamId] else { lock.unlock(); return }
        if stream.draining { streams.removeValue(forKey: streamId); lock.unlock(); return }
        stream.ended = true
        let work = makeDeliveryLocked(stream)
        lock.unlock()
        work?()
    }

    private func handleConnWindowUpdate(_ payload: Data) {
        guard payload.count >= 4 else { return }
        let inc = Int(readUInt32(payload) & 0x7FFFFFFF)
        lock.lock()
        peerConnWindow += inc
        let resumptions = flowResumptions; flowResumptions.removeAll()
        lock.unlock()
        for r in resumptions { r() }
    }

    private func handleStreamWindowUpdate(streamId: UInt32, payload: Data) {
        guard payload.count >= 4 else { return }
        let inc = Int(readUInt32(payload) & 0x7FFFFFFF)
        lock.lock()
        streams[streamId]?.sendWindow += inc
        let resumptions = flowResumptions; flowResumptions.removeAll()
        lock.unlock()
        for r in resumptions { r() }
    }

    /// Lock held. Hands buffered data/EOF/error to a waiting receiver; returns the work to run after unlock.
    private func makeDeliveryLocked(_ stream: XHTTPH2Stream) -> (() -> Void)? {
        guard let pending = stream.pendingReceive else { return nil }
        if let failure = stream.failure {
            stream.pendingReceive = nil
            return { pending(nil, failure) }
        }
        if !stream.receiveBuffer.isEmpty {
            let data = stream.receiveBuffer
            stream.receiveBuffer = Data()
            stream.pendingReceive = nil
            connReceiveConsumed += data.count
            stream.receiveConsumed += data.count
            let updates = windowUpdatesLocked(stream)
            return { [weak self] in
                for u in updates { self?.transportSend(u) { _ in } }
                pending(data, nil)
            }
        }
        if stream.ended {
            stream.pendingReceive = nil
            streams.removeValue(forKey: stream.streamId)
            return { pending(nil, nil) }
        }
        return nil
    }

    // MARK: Send

    func sendHeaders(streamId: UInt32, headerBlock: Data, endStream: Bool, completion: @escaping (Error?) -> Void) {
        lock.lock()
        if closedFlag { lock.unlock(); completion(XHTTPError.connectionClosed); return }
        let flags = XHTTPConnection.h2FlagEndHeaders | (endStream ? XHTTPConnection.h2FlagEndStream : 0)
        let f = frame(type: XHTTPConnection.h2FrameHeaders, flags: flags, streamId: streamId, payload: headerBlock)
        lock.unlock()
        transportSend(f, completion)
    }

    func sendData(stream: XHTTPH2Stream, data: Data, offset: Int, endStream: Bool, completion: @escaping (Error?) -> Void) {
        if offset >= data.count {
            guard endStream else { completion(nil); return }
            lock.lock()
            if closedFlag { lock.unlock(); completion(XHTTPError.connectionClosed); return }
            let f = frame(type: XHTTPConnection.h2FrameData, flags: XHTTPConnection.h2FlagEndStream, streamId: stream.streamId, payload: Data())
            lock.unlock()
            transportSend(f, completion)
            return
        }
        lock.lock()
        if closedFlag { lock.unlock(); completion(XHTTPError.connectionClosed); return }
        let window = min(peerConnWindow, stream.sendWindow)
        guard window > 0 else {
            flowResumptions.append { [weak self] in
                self?.sendData(stream: stream, data: data, offset: offset, endStream: endStream, completion: completion)
            }
            lock.unlock()
            return
        }
        var frames = Data()
        var cur = offset
        var remainingWindow = window
        while cur < data.count {
            let chunk = min(data.count - cur, min(maxFrameSize, remainingWindow))
            guard chunk > 0 else { break }
            let isLast = (cur + chunk) >= data.count
            let flags: UInt8 = (isLast && endStream) ? XHTTPConnection.h2FlagEndStream : 0
            frames.append(frame(type: XHTTPConnection.h2FrameData, flags: flags, streamId: stream.streamId,
                                payload: Data(data[data.startIndex + cur ..< data.startIndex + cur + chunk])))
            cur += chunk
            remainingWindow -= chunk
        }
        let sent = window - remainingWindow
        peerConnWindow -= sent
        stream.sendWindow -= sent
        lock.unlock()

        let nextOffset = cur
        transportSend(frames) { [weak self] error in
            if let error { completion(error); return }
            if nextOffset < data.count {
                self?.sendData(stream: stream, data: data, offset: nextOffset, endStream: endStream, completion: completion)
            } else {
                completion(nil)
            }
        }
    }

    func receive(stream: XHTTPH2Stream, completion: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if closedFlag, stream.receiveBuffer.isEmpty, !stream.ended, stream.failure == nil {
            lock.unlock(); completion(nil, XHTTPError.connectionClosed); return
        }
        stream.pendingReceive = completion
        let work = makeDeliveryLocked(stream)
        lock.unlock()
        work?()
    }

    // MARK: Streams

    func makeStream() -> XHTTPH2Stream {
        lock.lock()
        let id = nextStreamId
        nextStreamId += 2
        let stream = XHTTPH2Stream(streamId: id, connection: self, sendWindow: peerInitialWindow)
        streams[id] = stream
        lock.unlock()
        return stream
    }

    func drain(stream: XHTTPH2Stream) {
        lock.lock()
        stream.draining = true
        stream.receiveBuffer = Data()
        lock.unlock()
    }

    func closeStream(_ stream: XHTTPH2Stream) {
        lock.lock()
        let known = streams[stream.streamId] != nil
        streams.removeValue(forKey: stream.streamId)
        let ended = stream.ended
        let closed = closedFlag
        lock.unlock()
        if known, !ended, !closed {
            var code = Data(count: 4); code[3] = 0x08 // CANCEL
            transportSend(frame(type: XHTTPConnection.h2FrameRstStream, flags: 0, streamId: stream.streamId, payload: code)) { _ in }
        }
    }

    func cancel() { failAll(XHTTPError.connectionClosed) }

    private func failAll(_ error: Error) {
        lock.lock()
        if closedFlag { lock.unlock(); return }
        closedFlag = true
        let pendings = streams.values.compactMap { $0.pendingReceive }
        streams.removeAll()
        // Sends parked on flow control; each re-enters `sendData`, sees the closed connection,
        // and completes with `.connectionClosed` rather than hanging forever.
        let resumptions = flowResumptions
        flowResumptions.removeAll()
        lock.unlock()
        frameReader.reset()
        for resume in resumptions { resume() }
        for p in pendings { p(nil, error) }
        transportCancel()
    }

    // MARK: Frame I/O

    private func frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        H2Framing.frame(type: type, flags: flags, streamId: streamId, payload: payload)
    }

    private func applySettings(_ payload: Data) {
        var o = payload.startIndex
        while o + 6 <= payload.endIndex {
            let id = (UInt16(payload[o]) << 8) | UInt16(payload[o + 1])
            let val = (UInt32(payload[o + 2]) << 24) | (UInt32(payload[o + 3]) << 16)
                    | (UInt32(payload[o + 4]) << 8) | UInt32(payload[o + 5])
            lock.lock()
            if id == 0x04 { // INITIAL_WINDOW_SIZE
                let delta = Int(val) - peerInitialWindow
                peerInitialWindow = Int(val)
                for s in streams.values { s.sendWindow += delta }
            } else if id == 0x05 { // MAX_FRAME_SIZE
                maxFrameSize = Int(val)
            }
            lock.unlock()
            o += 6
        }
    }

    /// Conn-level WINDOW_UPDATE once >= 50% of the advertised window is consumed. Lock held.
    private func connWindowUpdateLocked() -> Data? {
        guard connReceiveConsumed >= Int(Self.localConnWindow) / 2 else { return nil }
        let inc = UInt32(connReceiveConsumed)
        connReceiveConsumed = 0
        return frame(type: XHTTPConnection.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: uint32Data(inc))
    }

    /// Conn + stream WINDOW_UPDATEs as thresholds are crossed. Lock held.
    private func windowUpdatesLocked(_ stream: XHTTPH2Stream) -> [Data] {
        var out: [Data] = []
        if let c = connWindowUpdateLocked() { out.append(c) }
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

nonisolated final class XHTTPH1UploadConnection: XMUXPoolable {
    private let underlyingSend: (Data, @escaping (Error?) -> Void) -> Void
    private let underlyingReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let underlyingCancel: () -> Void

    private let lock = UnfairLock()
    private var outstanding = 0       // POSTs written minus responses fully parsed
    private var dirty = false         // unparseable/unexpected response → never reuse
    private var closed = false
    private var retained: [AnyObject] = []

    private enum ParseState { case headers; case body(Int) }
    private var parseState: ParseState = .headers
    private var parseBuffer = Data()

    /// Lease for the current session; refreshed on each pool acquire.
    var lease: XMUXLease?

    init(transport: TransportClosures) {
        underlyingSend = transport.send
        underlyingReceive = transport.receive
        underlyingCancel = transport.cancel
        startDrain()
    }

    /// Keeps a dial-time object (TLS/Reality client) alive for the connection's lifetime.
    func retain(_ object: AnyObject) { lock.lock(); retained.append(object); lock.unlock() }

    var isPoolClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed || dirty }

    func poolClose() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        lock.unlock()
        underlyingCancel()
    }

    /// Closures handed to the XHTTP session: each write is one POST; the session needn't drain
    /// (this connection drains internally); cancel returns the connection to the pool.
    var sessionClosures: TransportClosures {
        TransportClosures(
            send: { [weak self] data, completion in
                guard let self else { completion(XHTTPError.connectionClosed); return }
                self.lock.lock(); self.outstanding += 1; self.lock.unlock()
                self.underlyingSend(data, completion)
            },
            receive: { completion in
                // The internal drain owns the socket; the session doesn't read upload responses.
                completion(nil, true, nil)
            },
            cancel: { [weak self] in self?.releaseToPool() }
        )
    }

    private func releaseToPool() {
        lock.lock()
        // Only a fully-drained, well-framed connection may be reused.
        if dirty || outstanding != 0 || !parseBuffer.isEmpty { dirty = true }
        let lease = self.lease
        self.lease = nil
        lock.unlock()
        lease?.release()
    }

    // MARK: Internal drain + response parser

    private func startDrain() {
        underlyingReceive { [weak self] data, isComplete, error in
            guard let self else { return }
            if error != nil {
                self.lock.lock(); self.closed = true; self.lock.unlock()
                return
            }
            if let data, !data.isEmpty { self.consume(data) }
            if isComplete {
                self.lock.lock(); self.closed = true; self.lock.unlock()
                return
            }
            self.lock.lock(); let stop = self.closed; self.lock.unlock()
            if !stop { self.startDrain() }
        }
    }

    /// Counts completed responses (Content-Length framed). Anything it can't frame marks the
    /// connection unreusable rather than risk mis-framing a reused socket.
    private func consume(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        if dirty || closed { return }
        parseBuffer.append(data)
        while true {
            switch parseState {
            case .headers:
                guard let r = parseBuffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) else { return }
                let headerData = Data(parseBuffer[parseBuffer.startIndex..<r.lowerBound])
                parseBuffer = Data(parseBuffer[r.upperBound...])
                guard let header = String(data: headerData, encoding: .ascii), header.hasPrefix("HTTP/1.") else {
                    dirty = true; return
                }
                let lower = header.lowercased()
                if lower.contains("transfer-encoding:"), lower.contains("chunked") {
                    dirty = true; return
                }
                guard let length = Self.contentLength(in: header) else {
                    // No Content-Length and not chunked → connection-delimited → can't reuse.
                    dirty = true; return
                }
                if length == 0 { completeResponseLocked() } else { parseState = .body(length) }
            case .body(let remaining):
                guard !parseBuffer.isEmpty else { return }
                let take = min(remaining, parseBuffer.count)
                parseBuffer.removeFirst(take)
                parseBuffer = parseBuffer.isEmpty ? Data() : Data(parseBuffer)
                let left = remaining - take
                if left == 0 { parseState = .headers; completeResponseLocked() }
                else { parseState = .body(left); return }
            }
        }
    }

    /// Lock held.
    private func completeResponseLocked() {
        parseState = .headers
        if outstanding <= 0 { dirty = true; return } // unexpected/extra response
        outstanding -= 1
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
