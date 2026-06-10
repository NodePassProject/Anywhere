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
    var h2ReadBuffer = Data()
    var h2DataBuffer = Data()

    /// Caps h2ReadBuffer to bound memory growth.
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

    /// Consecutive synchronous parses in readH2Frame; trampolined every Nth call to avoid stack overflow.
    var h2ReadDepth: Int = 0

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

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
        // Detached: healthy only while both legs are up.
        return v && (uploadChannel?.isConnected ?? true)
    }

    // MARK: - X-Padding (matching Xray-core xpadding.go)

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

    // MARK: - Session/Seq Metadata (matching Xray-core config.go ApplyMetaToRequest)

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

    func buildRequestLine(method: String, path: String, queryParts: [String]) -> String {
        var url = path
        var allQuery = queryParts.filter { !$0.isEmpty }
        // Config-level query (path after "?"), matching Xray-core GetNormalizedQuery.
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
        if useHTTP3 {
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
        h2ReadBuffer.removeAll()
        h2DataBuffer.removeAll()
        h2StreamClosed = true
        h3Closed = true
        let h3Dl = h3Download
        let h3Up = h3Upload
        let h3Sess = h3Session
        let uploadCancelFn = uploadCancel
        uploadSend = nil
        uploadReceive = nil
        uploadCancel = nil
        let pendingPackets = packetUpQueue
        packetUpQueue.removeAll()
        packetUpFlushPending = false
        lock.unlock()

        for (_, completion) in pendingPackets {
            completion(XHTTPError.connectionClosed)
        }

        downloadCancel()
        uploadCancelFn?()
        h3Dl?.close()
        h3Up?.close()
        h3Sess?.close()
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

    /// Schedules a flush respecting `scMinPostsIntervalMs` since the last flush start (matches Xray-core).
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

        if isH3 {
            sendH3PacketUp(data: batchedData, completion: onComplete)
        } else if isH2 {
            sendH2PacketUp(data: batchedData, completion: onComplete)
        } else {
            sendPacketUp(data: batchedData, completion: onComplete)
        }
    }
}
