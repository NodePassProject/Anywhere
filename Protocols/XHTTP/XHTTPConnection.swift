//
//  XHTTPConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "XHTTP")

let defaultUserAgent = ProxyUserAgent.chrome

// MARK: - Transport Closures

/// Type alias for the set of closures that abstract the underlying transport (NWTransport / TLSRecordConnection).
struct TransportClosures {
    let send: (Data, @escaping (Error?) -> Void) -> Void
    let receive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    let cancel: () -> Void
}

// MARK: - XHTTPConnection

/// XHTTP connection implementing packet-up, stream-up, and stream-one modes.
///
/// Uses the same closure-based transport abstraction as ``WebSocketConnection`` and ``HTTPUpgradeConnection``.
class XHTTPConnection {

    let configuration: XHTTPConfiguration
    let mode: XHTTPMode
    let sessionId: String

    // Download / stream-one connection (closure-based, from ProxyClient)
    let downloadSend: (Data, @escaping (Error?) -> Void) -> Void
    let downloadReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    let downloadCancel: () -> Void

    // Upload connection factory (packet-up and stream-up)
    let uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)?

    // Upload connection state (packet-up and stream-up)
    var uploadSend: ((Data, @escaping (Error?) -> Void) -> Void)?
    var uploadReceive: ((@escaping (Data?, Bool, Error?) -> Void) -> Void)?
    var uploadCancel: (() -> Void)?

    // State
    var nextSeq: Int64 = 0
    var chunkedDecoder = ChunkedTransferDecoder()
    var downloadHeadersParsed = false
    var _isConnected = false
    let lock = UnfairLock()

    // Packet-up batching: delay completion to match Xray-core's scMinPostsIntervalMs.
    // This keeps uploadFlushInFlight=true longer, causing LWIPTCPConnection to
    // accumulate data in its coalesce buffer, resulting in fewer, larger POSTs.
    var lastPacketUpSendTime: UInt64 = 0

    /// Leftover data after HTTP response headers.
    var headerBuffer = Data()

    // HTTP/2 state
    let useHTTP2: Bool
    var h2ReadBuffer = Data()
    var h2DataBuffer = Data()

    /// Maximum h2ReadBuffer size (2 MB). Protects against unbounded growth
    static let maxH2ReadBufferSize = 2_097_152
    /// Connection-level send window (RFC 7540 §6.9: stream 0).
    /// Updated by WINDOW_UPDATE on stream 0 only.
    var h2PeerConnectionWindow: Int = 65535
    /// Stream-level send window for the active upload stream (stream-up / stream-one).
    /// Updated by SETTINGS INITIAL_WINDOW_SIZE and stream-level WINDOW_UPDATE.
    var h2PeerStreamSendWindow: Int = 65535
    var h2PeerInitialWindowSize: Int = 65535
    var h2LocalWindowSize: Int = 4_194_304  // Match h2StreamWindowSize (4MB)
    var h2MaxFrameSize: Int = 16384
    var h2ResponseReceived = false
    var h2StreamClosed = false

    /// Continuations stored when sends are blocked by flow control (window == 0).
    /// All are invoked by the WINDOW_UPDATE handler; each re-checks its own window.
    var h2FlowResumptions: [() -> Void] = []
    /// Per-stream send windows for packet-up streams that are blocked on flow control.
    /// Keyed by stream ID; entries are created when a packet-up send blocks, updated by
    /// stream-level WINDOW_UPDATE, and removed when the send resumes.
    var h2PacketStreamWindows: [UInt32: Int] = [:]

    /// Bytes received but not yet acknowledged via WINDOW_UPDATE (connection level).
    var h2ConnectionReceiveConsumed: Int = 0
    /// Bytes received but not yet acknowledged via WINDOW_UPDATE (stream level, download stream).
    var h2StreamReceiveConsumed: Int = 0

    /// Counts consecutive synchronous frame parses in readH2Frame to trampoline
    /// only every Nth call, avoiding both stack overflow and per-frame dispatch overhead.
    var h2ReadDepth: Int = 0

    // HTTP/2 multiplexing state (for stream-up / packet-up over H2)
    var h2UploadStreamId: UInt32 = 3      // Fixed upload stream for stream-up
    var h2NextPacketStreamId: UInt32 = 3   // Next stream ID for packet-up uploads

    var isConnected: Bool {
        lock.lock()
        let v = _isConnected
        lock.unlock()
        return v
    }

    // MARK: - X-Padding (matching Xray-core xpadding.go)

    /// Applies X-Padding to the raw HTTP request string based on configuration.
    ///
    /// Non-obfs mode (default): `Referer: https://{host}{path}?x_padding=XXX...`
    /// Obfs mode: Places padding in header, query, cookie, or queryInHeader based on config.
    func applyPadding(to request: inout String, forPath path: String) {
        let padding = configuration.generatePadding()

        if !configuration.xPaddingObfsMode {
            // Default mode: padding as Referer URL query param
            request += "Referer: https://\(configuration.host)\(path)?\(configuration.xPaddingKey)=\(padding)\r\n"
            return
        }

        // Obfs mode: place based on configured placement
        switch configuration.xPaddingPlacement {
        case .header:
            request += "\(configuration.xPaddingHeader): \(padding)\r\n"
        case .queryInHeader:
            request += "\(configuration.xPaddingHeader): https://\(configuration.host)\(path)?\(configuration.xPaddingKey)=\(padding)\r\n"
        case .cookie:
            request += "Cookie: \(configuration.xPaddingKey)=\(padding)\r\n"
        case .query:
            // Query padding is appended to the URL path in the request line — handled separately
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

    /// Appends a segment to a URL path, ensuring proper "/" handling.
    func appendToPath(_ path: String, _ segment: String) -> String {
        if path.hasSuffix("/") {
            return path + segment
        }
        return path + "/" + segment
    }

    /// Builds the full request URL path with optional query string.
    func buildRequestLine(method: String, path: String, queryParts: [String]) -> String {
        var url = path
        var allQuery = queryParts.filter { !$0.isEmpty }
        // Include config-level query string (from path after "?"), matching Xray-core GetNormalizedQuery
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty {
            allQuery.insert(configQuery, at: 0)
        }
        // Add query-based padding if in obfs+query mode
        if configuration.xPaddingObfsMode && configuration.xPaddingPlacement == .query {
            let padding = configuration.generatePadding()
            allQuery.append("\(configuration.xPaddingKey)=\(padding)")
        }
        if !allQuery.isEmpty {
            url += "?" + allQuery.joined(separator: "&")
        }
        return "\(method) \(url) HTTP/1.1\r\n"
    }

    // MARK: - Initializers (NWTransport)

    /// Creates an XHTTP connection over a plain NWTransport (security=none).
    init(transport: NWTransport, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.useHTTP2 = useHTTP2
        self.uploadConnectionFactory = uploadConnectionFactory
        self.downloadSend = { data, completion in
            transport.send(data: data, completion: completion)
        }
        self.downloadReceive = { completion in
            transport.receive(maximumLength: 65536, completion: completion)
        }
        self.downloadCancel = {
            transport.forceCancel()
        }
        self._isConnected = true
    }

    // MARK: - Initializers (Proxy Tunnel)

    /// Creates an XHTTP connection over a proxy tunnel (for proxy chaining).
    init(tunnel: ProxyConnection, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.useHTTP2 = useHTTP2
        self.uploadConnectionFactory = uploadConnectionFactory
        self.downloadSend = { data, completion in
            tunnel.sendRaw(data: data, completion: completion)
        }
        self.downloadReceive = { completion in
            tunnel.receiveRaw { data, error in
                if let error {
                    completion(nil, true, error)
                } else if let data, !data.isEmpty {
                    completion(data, false, nil)
                } else {
                    completion(nil, true, nil)
                }
            }
        }
        self.downloadCancel = {
            tunnel.cancel()
        }
        self._isConnected = true
    }

    // MARK: - Initializers (TLSRecordConnection)

    /// Creates an XHTTP connection over a TLS record connection (security=tls or reality).
    init(tlsConnection: TLSRecordConnection, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.useHTTP2 = useHTTP2
        self.uploadConnectionFactory = uploadConnectionFactory
        self.downloadSend = { data, completion in
            tlsConnection.send(data: data, completion: completion)
        }
        self.downloadReceive = { completion in
            tlsConnection.receive { data, error in
                completion(data, false, error)
            }
        }
        self.downloadCancel = {
            tlsConnection.cancel()
        }
        self._isConnected = true
    }

    // MARK: - Setup

    /// Performs the initial HTTP handshake (sends the initial request and reads the response headers).
    ///
    /// - For stream-one mode: sends a POST with `Transfer-Encoding: chunked` and reads the response headers.
    /// - For stream-up mode: sends a GET for download stream, establishes upload connection,
    ///   and sends a streaming POST with `Transfer-Encoding: chunked` (no sequence numbers).
    /// - For packet-up mode: sends a GET request for the download stream, reads response headers,
    ///   and establishes the upload connection via the factory.
    func performSetup(completion: @escaping (Error?) -> Void) {
        if useHTTP2 {
            // HTTP/2: all modes go through H2 setup with mode-specific stream handling
            performH2Setup(completion: completion)
        } else if mode == .streamOne {
            performStreamOneSetup(completion: completion)
        } else if mode == .streamUp {
            performStreamUpSetup(completion: completion)
        } else {
            performPacketUpSetup(completion: completion)
        }
    }

    // MARK: - Send

    /// Sends data through the XHTTP connection.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        if useHTTP2 {
            if mode == .packetUp {
                sendH2PacketUp(data: data, completion: completion)
            } else if mode == .streamUp {
                sendH2Data(data: data, streamId: h2UploadStreamId, completion: completion)
            } else {
                // stream-one: upload and download share stream 1
                sendH2Data(data: data, streamId: 1, completion: completion)
            }
        } else if mode == .streamOne {
            sendStreamOne(data: data, completion: completion)
        } else if mode == .streamUp {
            sendStreamUp(data: data, completion: completion)
        } else {
            sendPacketUp(data: data, completion: completion)
        }
    }

    /// Sends data without tracking completion.
    func send(data: Data) {
        send(data: data) { _ in }
    }

    // MARK: - Receive

    /// Receives data from the download stream.
    func receive(completion: @escaping (Data?, Error?) -> Void) {
        if useHTTP2 {
            receiveH2Data(completion: completion)
            return
        }

        lock.lock()
        // Try to get data from chunked decoder buffer first
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

        // Need more data from download connection
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
                // Not enough data for a full chunk, keep reading
                self.receive(completion: completion)
            }
        }
    }

    // MARK: - Cancel

    /// Cancels the connection and releases resources.
    func cancel() {
        lock.lock()
        _isConnected = false
        chunkedDecoder = ChunkedTransferDecoder()
        headerBuffer.removeAll()
        h2ReadBuffer.removeAll()
        h2DataBuffer.removeAll()
        h2StreamClosed = true
        let uploadCancelFn = uploadCancel
        uploadSend = nil
        uploadReceive = nil
        uploadCancel = nil
        lock.unlock()

        downloadCancel()
        uploadCancelFn?()
    }

    // MARK: - Packet-Up Delay

    /// Delays the packet-up send completion to enforce `scMinPostsIntervalMs` spacing
    /// between POSTs, matching Xray-core's behavior. This keeps the caller's send-in-flight
    /// flag set, causing data to accumulate and batch into larger POSTs.
    func completePacketUpWithDelay(completion: @escaping (Error?) -> Void) {
        let delayMs = configuration.scMinPostsIntervalMs
        guard delayMs > 0 else {
            completion(nil)
            return
        }
        lock.lock()
        let now = DispatchTime.now().uptimeNanoseconds
        let elapsed = lastPacketUpSendTime == 0 ? UInt64(delayMs) * 1_000_000 : now - lastPacketUpSendTime
        lastPacketUpSendTime = now
        lock.unlock()

        let delayNs = UInt64(delayMs) * 1_000_000
        if elapsed >= delayNs {
            // Enough time has passed since last POST — complete immediately
            completion(nil)
        } else {
            // Defer completion for the remaining interval
            let remaining = delayNs - elapsed
            DispatchQueue.global().asyncAfter(deadline: .now() + .nanoseconds(Int(remaining))) {
                completion(nil)
            }
        }
    }
}
