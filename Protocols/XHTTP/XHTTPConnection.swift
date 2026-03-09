//
//  XHTTPConnection.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation

/// Default User-Agent matching Xray-core's `utils.ChromeUA` (config.go:51-53).
private let defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

// MARK: - Transport Closures

/// Type alias for the set of closures that abstract the underlying transport (BSDSocket / TLSRecordConnection).
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
    private let downloadSend: (Data, @escaping (Error?) -> Void) -> Void
    private let downloadReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let downloadCancel: () -> Void

    // Upload connection factory (packet-up and stream-up)
    private let uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)?

    // Upload connection state (packet-up and stream-up)
    private var uploadSend: ((Data, @escaping (Error?) -> Void) -> Void)?
    private var uploadReceive: ((@escaping (Data?, Bool, Error?) -> Void) -> Void)?
    private var uploadCancel: (() -> Void)?

    // State
    private var nextSeq: Int64 = 0
    private var chunkedDecoder = ChunkedTransferDecoder()
    private var downloadHeadersParsed = false
    private var _isConnected = false
    private let lock = UnfairLock()

    /// Leftover data after HTTP response headers.
    private var headerBuffer = Data()

    // HTTP/2 state (for Reality + stream-one)
    private let useHTTP2: Bool
    private var h2ReadBuffer = Data()
    private var h2DataBuffer = Data()

    /// Maximum h2ReadBuffer size (2 MB). Protects against unbounded growth
    private static let maxH2ReadBufferSize = 2_097_152
    private var h2PeerWindowSize: Int = 65535
    private var h2PeerInitialWindowSize: Int = 65535
    private var h2LocalWindowSize: Int = 65535
    private var h2MaxFrameSize: Int = 16384
    private var h2ResponseReceived = false
    private var h2StreamClosed = false

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
    private func applyPadding(to request: inout String, forPath path: String) {
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
    private func pathWithQueryPadding(_ basePath: String) -> String {
        if configuration.xPaddingObfsMode && configuration.xPaddingPlacement == .query {
            let padding = configuration.generatePadding()
            return "\(basePath)?\(configuration.xPaddingKey)=\(padding)"
        }
        return basePath
    }

    // MARK: - Session/Seq Metadata (matching Xray-core config.go ApplyMetaToRequest)

    /// Applies session ID to the request path, headers, query, or cookie based on configuration.
    private func applySessionId(to request: inout String, path: inout String) {
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
    private func queryParamsForMeta(seq: Int64? = nil) -> String {
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
    private func applySeq(to request: inout String, path: inout String, seq: Int64) {
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
    private func appendToPath(_ path: String, _ segment: String) -> String {
        if path.hasSuffix("/") {
            return path + segment
        }
        return path + "/" + segment
    }

    /// Builds the full request URL path with optional query string.
    private func buildRequestLine(method: String, path: String, queryParts: [String]) -> String {
        var url = path
        var allQuery = queryParts.filter { !$0.isEmpty }
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

    // MARK: - Initializers (BSDSocket)

    /// Creates an XHTTP connection over a plain BSD socket (security=none).
    init(socket: BSDSocket, configuration: XHTTPConfiguration, mode: XHTTPMode, sessionId: String, useHTTP2: Bool = false, uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)? = nil) {
        self.configuration = configuration
        self.mode = mode
        self.sessionId = sessionId
        self.useHTTP2 = useHTTP2
        self.uploadConnectionFactory = uploadConnectionFactory
        self.downloadSend = { data, completion in
            socket.send(data: data, completion: completion)
        }
        self.downloadReceive = { completion in
            socket.receive(maximumLength: 65536, completion: completion)
        }
        self.downloadCancel = {
            socket.forceCancel()
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
            performH2Setup(completion: completion)
        } else if mode == .streamOne {
            performStreamOneSetup(completion: completion)
        } else if mode == .streamUp {
            performStreamUpSetup(completion: completion)
        } else {
            performPacketUpSetup(completion: completion)
        }
    }

    // MARK: stream-one Setup

    private func performStreamOneSetup(completion: @escaping (Error?) -> Void) {
        let method = configuration.uplinkHTTPMethod
        let path = configuration.normalizedPath
        var request = ""

        // stream-one: no session ID in path (matching Xray-core: sessionId="" for stream-one)
        let metaQuery = queryParamsForMeta()
        request += buildRequestLine(method: method, path: path, queryParts: [metaQuery])
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        applyPadding(to: &request, forPath: path)
        request += "Transfer-Encoding: chunked\r\n"
        if !configuration.noGRPCHeader {
            request += "Content-Type: application/grpc\r\n"
        }
        for (key, value) in configuration.headers where key != "User-Agent" {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"

        guard let requestData = request.data(using: .utf8) else {
            completion(XHTTPError.setupFailed("Failed to encode stream-one request"))
            return
        }

        downloadSend(requestData) { [weak self] error in
            if let error {
                completion(XHTTPError.setupFailed(error.localizedDescription))
                return
            }
            self?.receiveResponseHeaders(completion: completion)
        }
    }

    // MARK: packet-up Setup

    private func performPacketUpSetup(completion: @escaping (Error?) -> Void) {
        // Send GET request on the download connection
        let request = buildDownloadGETRequest()

        guard let requestData = request.data(using: .utf8) else {
            completion(XHTTPError.setupFailed("Failed to encode GET request"))
            return
        }

        downloadSend(requestData) { [weak self] error in
            if let error {
                completion(XHTTPError.setupFailed(error.localizedDescription))
                return
            }

            // Read GET response headers
            self?.receiveResponseHeaders { [weak self] headerError in
                if let headerError {
                    completion(headerError)
                    return
                }

                // Establish the upload connection
                guard let self, let factory = self.uploadConnectionFactory else {
                    completion(XHTTPError.setupFailed("No upload connection factory"))
                    return
                }

                factory { [weak self] result in
                    switch result {
                    case .success(let closures):
                        self?.lock.lock()
                        self?.uploadSend = closures.send
                        self?.uploadReceive = closures.receive
                        self?.uploadCancel = closures.cancel
                        self?.lock.unlock()
                        completion(nil)
                    case .failure(let error):
                        completion(XHTTPError.setupFailed("Upload connection failed: \(error.localizedDescription)"))
                    }
                }
            }
        }
    }

    // MARK: stream-up Setup

    private func performStreamUpSetup(completion: @escaping (Error?) -> Void) {
        // 1. Send GET request on the download connection (same as packet-up)
        let request = buildDownloadGETRequest()

        guard let requestData = request.data(using: .utf8) else {
            completion(XHTTPError.setupFailed("Failed to encode GET request"))
            return
        }

        downloadSend(requestData) { [weak self] error in
            if let error {
                completion(XHTTPError.setupFailed(error.localizedDescription))
                return
            }

            // 2. Read GET response headers
            self?.receiveResponseHeaders { [weak self] headerError in
                if let headerError {
                    completion(headerError)
                    return
                }

                // 3. Establish the upload connection and send streaming POST headers
                guard let self, let factory = self.uploadConnectionFactory else {
                    completion(XHTTPError.setupFailed("No upload connection factory"))
                    return
                }

                factory { [weak self] result in
                    switch result {
                    case .success(let closures):
                        guard let self else {
                            completion(XHTTPError.setupFailed("Connection deallocated"))
                            return
                        }
                        self.lock.lock()
                        self.uploadSend = closures.send
                        self.uploadReceive = closures.receive
                        self.uploadCancel = closures.cancel
                        self.lock.unlock()

                        // 4. Send streaming POST request headers on upload connection
                        let postRequest = self.buildStreamUpPOSTRequest()

                        guard let postData = postRequest.data(using: .utf8) else {
                            completion(XHTTPError.setupFailed("Failed to encode stream-up POST request"))
                            return
                        }

                        closures.send(postData) { error in
                            if let error {
                                completion(XHTTPError.setupFailed("Stream-up POST send failed: \(error.localizedDescription)"))
                            } else {
                                completion(nil)
                            }
                        }

                    case .failure(let error):
                        completion(XHTTPError.setupFailed("Upload connection failed: \(error.localizedDescription)"))
                    }
                }
            }
        }
    }

    // MARK: - Request Builders

    /// Builds a GET request for the download stream (used by packet-up and stream-up).
    /// Session ID is placed according to sessionPlacement config.
    private func buildDownloadGETRequest() -> String {
        var path = configuration.normalizedPath
        var request = ""
        applySessionId(to: &request, path: &path)
        if path.last != "/" { path += "/" }
        let metaQuery = queryParamsForMeta()
        request = buildRequestLine(method: "GET", path: path, queryParts: [metaQuery]) + request
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        applyPadding(to: &request, forPath: path)
        for (key, value) in configuration.headers where key != "User-Agent" {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"
        return request
    }

    /// Builds a streaming POST request for stream-up upload.
    /// Session ID placed according to config, no sequence number, chunked transfer.
    private func buildStreamUpPOSTRequest() -> String {
        let method = configuration.uplinkHTTPMethod
        var path = configuration.normalizedPath
        var request = ""
        applySessionId(to: &request, path: &path)
        if path.last != "/" { path += "/" }
        let metaQuery = queryParamsForMeta()
        request = buildRequestLine(method: method, path: path, queryParts: [metaQuery]) + request
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        applyPadding(to: &request, forPath: path)
        request += "Transfer-Encoding: chunked\r\n"
        if !configuration.noGRPCHeader {
            request += "Content-Type: application/grpc\r\n"
        }
        for (key, value) in configuration.headers where key != "User-Agent" {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"
        return request
    }

    // MARK: - HTTP Response Header Parsing

    /// Reads bytes from the download connection until `\r\n\r\n` is found.
    /// Validates the status line contains "200".
    private func receiveResponseHeaders(completion: @escaping (Error?) -> Void) {
        downloadReceive { [weak self] data, _, error in
            guard let self else {
                completion(XHTTPError.setupFailed("Connection deallocated"))
                return
            }

            if let error {
                completion(XHTTPError.setupFailed(error.localizedDescription))
                return
            }

            guard let data, !data.isEmpty else {
                completion(XHTTPError.setupFailed("Empty response from server"))
                return
            }

            self.lock.lock()
            self.headerBuffer.append(data)

            let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
            guard let range = self.headerBuffer.range(of: headerEnd) else {
                self.lock.unlock()
                // Haven't received the full header yet, keep reading
                self.receiveResponseHeaders(completion: completion)
                return
            }

            let headerData = self.headerBuffer[self.headerBuffer.startIndex..<range.lowerBound]
            let leftover = Data(self.headerBuffer[range.upperBound...])
            self.headerBuffer.removeAll()
            self.downloadHeadersParsed = true

            // Feed leftover data into chunked decoder
            if !leftover.isEmpty {
                self.chunkedDecoder.feed(leftover)
            }
            self.lock.unlock()

            // Validate HTTP 200 response
            guard let headerString = String(data: Data(headerData), encoding: .utf8) else {
                completion(XHTTPError.httpError("Cannot decode response headers"))
                return
            }

            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("200") else {
                completion(XHTTPError.httpError("Expected HTTP 200, got: \(firstLine)"))
                return
            }

            completion(nil)
        }
    }

    // MARK: - Send

    /// Sends data through the XHTTP connection.
    func send(data: Data, completion: @escaping (Error?) -> Void) {
        if useHTTP2 {
            sendH2Data(data: data, completion: completion)
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

    // MARK: stream-one Send

    /// Sends data as a chunked-encoded chunk on the stream-one POST.
    private func sendStreamOne(data: Data, completion: @escaping (Error?) -> Void) {
        let chunk = ChunkedTransferEncoder.encode(data)
        downloadSend(chunk, completion)
    }

    // MARK: stream-up Send

    /// Sends data as a chunked-encoded chunk on the stream-up upload POST.
    private func sendStreamUp(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        guard let uploadSend = self.uploadSend else {
            lock.unlock()
            completion(XHTTPError.setupFailed("Upload connection not established"))
            return
        }
        lock.unlock()

        let chunk = ChunkedTransferEncoder.encode(data)
        uploadSend(chunk, completion)
    }

    // MARK: packet-up Send

    /// Sends data as a POST request with sequence number on the upload connection.
    private func sendPacketUp(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        guard let uploadSend = self.uploadSend, let uploadReceive = self.uploadReceive else {
            lock.unlock()
            completion(XHTTPError.setupFailed("Upload connection not established"))
            return
        }

        let seq = nextSeq
        nextSeq += 1
        lock.unlock()

        // Split data into chunks of scMaxEachPostBytes
        let maxSize = configuration.scMaxEachPostBytes
        if data.count <= maxSize {
            sendSinglePost(data: data, seq: seq, uploadSend: uploadSend, uploadReceive: uploadReceive, completion: completion)
        } else {
            // Send first chunk with current seq, remaining chunks will use subsequent seqs
            let firstChunk = data.prefix(maxSize)
            let remaining = data.suffix(from: maxSize)
            sendSinglePost(data: Data(firstChunk), seq: seq, uploadSend: uploadSend, uploadReceive: uploadReceive) { [weak self] error in
                if let error {
                    completion(error)
                    return
                }
                // Recurse for remaining data
                self?.sendPacketUp(data: Data(remaining), completion: completion)
            }
        }
    }

    /// Sends a single POST request and reads the 200 OK response.
    private func sendSinglePost(
        data: Data,
        seq: Int64,
        uploadSend: @escaping (Data, @escaping (Error?) -> Void) -> Void,
        uploadReceive: @escaping (@escaping (Data?, Bool, Error?) -> Void) -> Void,
        completion: @escaping (Error?) -> Void
    ) {
        let method = configuration.uplinkHTTPMethod
        var path = configuration.normalizedPath
        var headerBlock = ""

        // Apply session ID and sequence number metadata
        applySessionId(to: &headerBlock, path: &path)
        applySeq(to: &headerBlock, path: &path, seq: seq)

        // Determine body vs non-body data placement
        let bodyData: Data
        if configuration.uplinkDataPlacement != .body {
            // Encode data in headers or cookies instead of body
            let encoded = data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            let chunkSize = configuration.uplinkChunkSize > 0 ? configuration.uplinkChunkSize : encoded.count
            let key = configuration.uplinkDataKey

            switch configuration.uplinkDataPlacement {
            case .header:
                var i = 0
                var chunkIndex = 0
                while i < encoded.count {
                    let end = min(i + chunkSize, encoded.count)
                    let chunk = String(encoded[encoded.index(encoded.startIndex, offsetBy: i)..<encoded.index(encoded.startIndex, offsetBy: end)])
                    headerBlock += "\(key)-\(chunkIndex): \(chunk)\r\n"
                    i = end
                    chunkIndex += 1
                }
                headerBlock += "\(key)-Length: \(encoded.count)\r\n"
                headerBlock += "\(key)-Upstream: 1\r\n"
            case .cookie:
                headerBlock += "Cookie: \(key)=\(encoded)\r\n"
            default:
                break
            }
            bodyData = Data()
        } else {
            bodyData = data
        }

        let metaQuery = queryParamsForMeta(seq: seq)
        var request = buildRequestLine(method: method, path: path, queryParts: [metaQuery])
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        request += headerBlock
        applyPadding(to: &request, forPath: path)
        request += "Content-Length: \(bodyData.count)\r\n"
        if !configuration.noGRPCHeader {
            request += "Content-Type: application/grpc\r\n"
        }
        request += "Connection: keep-alive\r\n"
        for (key, value) in configuration.headers where key != "User-Agent" {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"

        guard var requestData = request.data(using: .utf8) else {
            completion(XHTTPError.setupFailed("Failed to encode POST request"))
            return
        }
        requestData.append(bodyData)

        uploadSend(requestData) { [weak self] error in
            if let error {
                completion(error)
                return
            }

            // Read the 200 OK response
            self?.readPostResponse(uploadReceive: uploadReceive, buffer: Data(), completion: completion)
        }
    }

    /// Reads the HTTP response to a POST request, looking for the end of headers.
    private func readPostResponse(
        uploadReceive: @escaping (@escaping (Data?, Bool, Error?) -> Void) -> Void,
        buffer: Data,
        completion: @escaping (Error?) -> Void
    ) {
        uploadReceive { [weak self] data, _, error in
            if let error {
                completion(error)
                return
            }

            guard let data, !data.isEmpty else {
                completion(XHTTPError.httpError("Empty POST response"))
                return
            }

            var buf = buffer
            buf.append(data)

            let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A])
            guard let range = buf.range(of: headerEnd) else {
                // Haven't received the full header yet, keep reading
                self?.readPostResponse(uploadReceive: uploadReceive, buffer: buf, completion: completion)
                return
            }

            let headerData = buf[buf.startIndex..<range.lowerBound]
            guard let headerString = String(data: Data(headerData), encoding: .utf8) else {
                completion(XHTTPError.httpError("Cannot decode POST response headers"))
                return
            }

            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("200") else {
                completion(XHTTPError.httpError("POST response error: \(firstLine)"))
                return
            }

            completion(nil)
        }
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
}

// MARK: - HTTP/2 Support (RFC 7540)

extension XHTTPConnection {

    // MARK: HTTP/2 Constants

    /// HTTP/2 connection preface (RFC 7540 §3.5).
    private static let h2Preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)

    /// HTTP/2 frame header size.
    private static let h2FrameHeaderSize = 9

    // Frame types
    private static let h2FrameData: UInt8 = 0x00
    private static let h2FrameHeaders: UInt8 = 0x01
    private static let h2FrameSettings: UInt8 = 0x04
    private static let h2FramePing: UInt8 = 0x06
    private static let h2FrameGoaway: UInt8 = 0x07
    private static let h2FrameWindowUpdate: UInt8 = 0x08
    private static let h2FrameRstStream: UInt8 = 0x03

    // Flags
    private static let h2FlagEndStream: UInt8 = 0x01
    private static let h2FlagEndHeaders: UInt8 = 0x04
    private static let h2FlagAck: UInt8 = 0x01

    // Settings IDs
    private static let h2SettingsEnablePush: UInt16 = 0x02
    private static let h2SettingsInitialWindowSize: UInt16 = 0x04

    // Go http2 transport defaults
    private static let h2StreamWindowSize: UInt32 = 4_194_304  // 4MB
    private static let h2ConnWindowSize: UInt32 = 1_073_741_824  // 1GB

    // MARK: HTTP/2 Frame I/O

    /// Builds an HTTP/2 frame.
    private func buildH2Frame(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data) -> Data {
        var frame = Data(capacity: Self.h2FrameHeaderSize + payload.count)
        // Length (24-bit)
        let len = UInt32(payload.count)
        frame.append(UInt8((len >> 16) & 0xFF))
        frame.append(UInt8((len >> 8) & 0xFF))
        frame.append(UInt8(len & 0xFF))
        // Type
        frame.append(type)
        // Flags
        frame.append(flags)
        // Stream ID (31-bit, R=0)
        let sid = streamId & 0x7FFFFFFF
        frame.append(UInt8((sid >> 24) & 0xFF))
        frame.append(UInt8((sid >> 16) & 0xFF))
        frame.append(UInt8((sid >> 8) & 0xFF))
        frame.append(UInt8(sid & 0xFF))
        // Payload
        frame.append(payload)
        return frame
    }

    /// Attempts to parse one complete frame from h2ReadBuffer.
    /// Returns (type, flags, streamId, payload) or nil if not enough data.
    private func parseH2Frame() -> (type: UInt8, flags: UInt8, streamId: UInt32, payload: Data)? {
        guard h2ReadBuffer.count >= Self.h2FrameHeaderSize else { return nil }

        let b = h2ReadBuffer
        let length = (UInt32(b[b.startIndex]) << 16) | (UInt32(b[b.startIndex + 1]) << 8) | UInt32(b[b.startIndex + 2])
        let type = b[b.startIndex + 3]
        let flags = b[b.startIndex + 4]
        let streamId = (UInt32(b[b.startIndex + 5]) << 24) | (UInt32(b[b.startIndex + 6]) << 16) | (UInt32(b[b.startIndex + 7]) << 8) | UInt32(b[b.startIndex + 8])
        let sid = streamId & 0x7FFFFFFF

        let totalSize = Self.h2FrameHeaderSize + Int(length)
        guard h2ReadBuffer.count >= totalSize else { return nil }

        let payload = Data(h2ReadBuffer[h2ReadBuffer.startIndex + Self.h2FrameHeaderSize ..< h2ReadBuffer.startIndex + totalSize])
        h2ReadBuffer.removeFirst(totalSize)
        // Release backing store when buffer is fully consumed
        if h2ReadBuffer.isEmpty {
            h2ReadBuffer = Data()
        }

        return (type, flags, sid, payload)
    }

    /// Reads from transport into h2ReadBuffer until at least one full frame is available,
    /// then parses and returns it.
    private func readH2Frame(completion: @escaping (Result<(type: UInt8, flags: UInt8, streamId: UInt32, payload: Data), Error>) -> Void) {
        lock.lock()
        if let frame = parseH2Frame() {
            lock.unlock()
            completion(.success(frame))
            return
        }
        lock.unlock()

        downloadReceive { [weak self] data, _, error in
            guard let self else {
                completion(.failure(XHTTPError.connectionClosed))
                return
            }
            if let error {
                completion(.failure(error))
                return
            }
            guard let data, !data.isEmpty else {
                completion(.failure(XHTTPError.connectionClosed))
                return
            }

            self.lock.lock()
            self.h2ReadBuffer.append(data)
            if self.h2ReadBuffer.count > Self.maxH2ReadBufferSize {
                self.h2ReadBuffer.removeAll()
                self.lock.unlock()
                completion(.failure(XHTTPError.connectionClosed))
                return
            }
            self.lock.unlock()

            // Recurse to try parsing again
            self.readH2Frame(completion: completion)
        }
    }

    // MARK: HTTP/2 HPACK Encoder (simplified, no Huffman)

    /// Encodes an integer with the given prefix bit width (RFC 7541 §5.1).
    private static func hpackEncodeInteger(_ value: Int, prefixBits: Int) -> [UInt8] {
        let maxPrefix = (1 << prefixBits) - 1
        if value < maxPrefix {
            return [UInt8(value)]
        }
        var bytes: [UInt8] = [UInt8(maxPrefix)]
        var remaining = value - maxPrefix
        while remaining >= 128 {
            bytes.append(UInt8(remaining & 0x7F) | 0x80)
            remaining >>= 7
        }
        bytes.append(UInt8(remaining))
        return bytes
    }

    /// Encodes a plain (non-Huffman) string (RFC 7541 §5.2).
    private static func hpackEncodeString(_ string: String) -> [UInt8] {
        let bytes = Array(string.utf8)
        // H=0 (no Huffman), length with 7-bit prefix
        var result = hpackEncodeInteger(bytes.count, prefixBits: 7)
        // Clear the H bit (it's already 0 since we're setting it explicitly)
        result[0] &= 0x7F
        result.append(contentsOf: bytes)
        return result
    }

    /// Encodes a request header block for stream-one POST.
    private func encodeH2RequestHeaders() -> Data {
        var block = Data()

        // :method POST — static table index 3 (exact match)
        block.append(0x83)
        // :scheme https — static table index 7 (exact match)
        block.append(0x87)

        // :path — literal without indexing, name index 4
        let path = configuration.normalizedPath
        if path == "/" {
            block.append(0x84) // Indexed: :path / (index 4)
        } else {
            // 0000 NNNN format: name index in 4-bit prefix
            var pathBytes = Self.hpackEncodeInteger(4, prefixBits: 4)
            pathBytes[0] &= 0x0F // Ensure top 4 bits are 0000 (literal without indexing)
            block.append(contentsOf: pathBytes)
            block.append(contentsOf: Self.hpackEncodeString(path))
        }

        // :authority — literal without indexing, name index 1
        var authBytes = Self.hpackEncodeInteger(1, prefixBits: 4)
        authBytes[0] &= 0x0F
        block.append(contentsOf: authBytes)
        block.append(contentsOf: Self.hpackEncodeString(configuration.host))

        // content-type: application/grpc (if enabled)
        if !configuration.noGRPCHeader {
            // name index 31
            var ctBytes = Self.hpackEncodeInteger(31, prefixBits: 4)
            ctBytes[0] &= 0x0F
            block.append(contentsOf: ctBytes)
            block.append(contentsOf: Self.hpackEncodeString("application/grpc"))
        }

        // user-agent — name index 58
        let ua = configuration.headers["User-Agent"] ?? defaultUserAgent
        var uaBytes = Self.hpackEncodeInteger(58, prefixBits: 4)
        uaBytes[0] &= 0x0F
        block.append(contentsOf: uaBytes)
        block.append(contentsOf: Self.hpackEncodeString(ua))

        // X-Padding — applied based on configuration
        // Default (non-obfs): Referer header with x_padding query param
        // Obfs mode: Uses configured placement (header, queryInHeader, cookie, query)
        let padding = configuration.generatePadding()
        if !configuration.xPaddingObfsMode {
            // Default: Referer (name index 51) with padding in URL query
            let referer = "https://\(configuration.host)\(configuration.normalizedPath)?\(configuration.xPaddingKey)=\(padding)"
            var refBytes = Self.hpackEncodeInteger(51, prefixBits: 4)
            refBytes[0] &= 0x0F
            block.append(contentsOf: refBytes)
            block.append(contentsOf: Self.hpackEncodeString(referer))
        } else {
            switch configuration.xPaddingPlacement {
            case .header:
                // Custom header with padding value
                block.append(0x00)
                block.append(contentsOf: Self.hpackEncodeString(configuration.xPaddingHeader.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(padding))
            case .queryInHeader:
                // Custom header with padding in URL query
                let headerValue = "https://\(configuration.host)\(configuration.normalizedPath)?\(configuration.xPaddingKey)=\(padding)"
                block.append(0x00)
                block.append(contentsOf: Self.hpackEncodeString(configuration.xPaddingHeader.lowercased()))
                block.append(contentsOf: Self.hpackEncodeString(headerValue))
            case .cookie:
                // Cookie header (name index 32)
                var cookieBytes = Self.hpackEncodeInteger(32, prefixBits: 4)
                cookieBytes[0] &= 0x0F
                block.append(contentsOf: cookieBytes)
                block.append(contentsOf: Self.hpackEncodeString("\(configuration.xPaddingKey)=\(padding)"))
            default:
                break
            }
        }

        // Custom headers (literal, new names)
        for (key, value) in configuration.headers where key != "User-Agent" {
            // 0x00 = literal without indexing, new name
            block.append(0x00)
            block.append(contentsOf: Self.hpackEncodeString(key.lowercased()))
            block.append(contentsOf: Self.hpackEncodeString(value))
        }

        return block
    }

    /// Checks if the HEADERS response block starts with :status 200.
    /// Returns nil if status is 200 OK, or an error description string otherwise.
    private func checkH2ResponseStatus(_ headerBlock: Data) -> String? {
        guard !headerBlock.isEmpty else { return "empty header block" }

        // Skip HPACK dynamic table size updates (prefix 001xxxxx, RFC 7541 §6.3).
        // Servers may send these at the start of a header block after a SETTINGS change.
        var offset = headerBlock.startIndex
        while offset < headerBlock.endIndex, headerBlock[offset] & 0xE0 == 0x20 {
            // Decode the 5-bit prefixed integer to find the entry's length
            let initial = headerBlock[offset] & 0x1F
            offset += 1
            if initial == 0x1F {
                // Multi-byte integer: skip continuation bytes (high bit set)
                while offset < headerBlock.endIndex, headerBlock[offset] & 0x80 != 0 {
                    offset += 1
                }
                offset += 1  // final byte (high bit clear)
            }
        }
        guard offset < headerBlock.endIndex else { return "empty header block (only table size updates)" }

        let first = headerBlock[offset]
        let remaining = headerBlock[offset...]

        // 1. Indexed representation (top bit set): static table index
        //    0x88=200, 0x89=204, 0x8a=206, 0x8b=304, 0x8c=400, 0x8d=404, 0x8e=500
        if first & 0x80 != 0 {
            if first == 0x88 { return nil } // 200 OK
            let indexedStatus: [UInt8: String] = [0x89: "204", 0x8a: "206", 0x8b: "304", 0x8c: "400", 0x8d: "404", 0x8e: "500"]
            if let status = indexedStatus[first] { return "status \(status)" }
            return "status (indexed \(first & 0x7F))"
        }

        // 2. Literal representations with name index 8 (:status)
        //    0x08 = without indexing, 0x18 = never indexed, 0x48 = incremental indexing
        let nameIndex: UInt8
        if first & 0xF0 == 0x00 {       // Literal without indexing (0000 NNNN)
            nameIndex = first & 0x0F
        } else if first & 0xF0 == 0x10 { // Literal never indexed (0001 NNNN)
            nameIndex = first & 0x0F
        } else if first & 0xC0 == 0x40 { // Literal with incremental indexing (01NN NNNN)
            nameIndex = first & 0x3F
        } else {
            let hex = remaining.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            return "unknown status (HPACK: \(hex))"
        }

        guard nameIndex == 8, remaining.count >= 2 else {
            let hex = remaining.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            return "unknown status (HPACK: \(hex))"
        }

        let valueMeta = remaining[remaining.startIndex + 1]
        let isHuffman = (valueMeta & 0x80) != 0
        let valueLen = Int(valueMeta & 0x7F)
        let valueStart = remaining.startIndex + 2

        guard remaining.count >= 2 + valueLen, valueLen > 0 else {
            return "status (?)"
        }

        let valueData = Data(remaining[valueStart..<(valueStart + valueLen)])

        if !isHuffman {
            let status = String(data: valueData, encoding: .ascii) ?? "?"
            return status == "200" ? nil : "status \(status)"
        }

        // Huffman-decode digits for status code (RFC 7541 Appendix B)
        // '0'=00000(5), '1'=00001(5), '2'=00010(5),
        // '3'=011000(6), '4'=011001(6), '5'=011010(6), '6'=011011(6),
        // '7'=011100(6), '8'=011101(6), '9'=011110(6)
        let status = Self.huffmanDecodeDigits(valueData)
        if status.isEmpty {
            let hex = valueData.map { String(format: "%02x", $0) }.joined(separator: " ")
            return "status (huffman: \(hex))"
        }
        return status == "200" ? nil : "status \(status)"
    }

    /// Huffman-decodes a byte sequence containing only ASCII digits (for HTTP status codes).
    private static func huffmanDecodeDigits(_ data: Data) -> String {
        var result = ""
        var bits: UInt32 = 0
        var numBits = 0

        for byte in data {
            bits = (bits << 8) | UInt32(byte)
            numBits += 8
        }

        while numBits >= 5 {
            let top5 = Int((bits >> (numBits - 5)) & 0x1F)
            // 5-bit codes: '0'=0x00, '1'=0x01, '2'=0x02
            if top5 <= 0x02 {
                result.append(Character(UnicodeScalar(48 + top5)!))
                numBits -= 5
                continue
            }
            // 6-bit codes: '3'=0x18...'9'=0x1e
            guard numBits >= 6 else { break }
            let top6 = Int((bits >> (numBits - 6)) & 0x3F)
            if top6 >= 0x18 && top6 <= 0x1E {
                let digit = top6 - 0x18 + 3 // '3'..'9'
                result.append(Character(UnicodeScalar(48 + digit)!))
                numBits -= 6
                continue
            }
            break // Unknown code or EOS padding
        }
        return result
    }

    // MARK: HTTP/2 Setup

    /// Performs HTTP/2 connection setup matching Go's http2.Transport behavior:
    /// 1. Send preface + SETTINGS + WINDOW_UPDATE
    /// 2. Wait for server's SETTINGS (exchange settings)
    /// 3. Send HEADERS for the stream-one POST
    /// 4. Wait for server's HEADERS response (200 OK)
    func performH2Setup(completion: @escaping (Error?) -> Void) {
        // Phase 1: Send connection preface + SETTINGS + WINDOW_UPDATE
        var initData = Data()

        // 1. Connection preface
        initData.append(Self.h2Preface)

        // 2. Client SETTINGS frame (matching Go http2.Transport defaults)
        var settingsPayload = Data()
        // HEADER_TABLE_SIZE = 4096 (Go default: initialHeaderTableSize)
        settingsPayload.append(contentsOf: [0x00, 0x01, 0x00, 0x00, 0x10, 0x00])
        // ENABLE_PUSH = 0
        settingsPayload.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        // INITIAL_WINDOW_SIZE = 4MB (matches Go http2.Transport)
        let winSize = Self.h2StreamWindowSize
        settingsPayload.append(contentsOf: [
            0x00, 0x04,
            UInt8((winSize >> 24) & 0xFF), UInt8((winSize >> 16) & 0xFF),
            UInt8((winSize >> 8) & 0xFF), UInt8(winSize & 0xFF)
        ])
        // MAX_HEADER_LIST_SIZE = 10MB (Go default)
        settingsPayload.append(contentsOf: [0x00, 0x06, 0x00, 0xA0, 0x00, 0x00])
        initData.append(buildH2Frame(type: Self.h2FrameSettings, flags: 0, streamId: 0, payload: settingsPayload))

        // 3. Connection-level WINDOW_UPDATE (increase from default 65535 to 1GB)
        let windowIncrement = Self.h2ConnWindowSize - 65535
        var wuPayload = Data(count: 4)
        wuPayload[0] = UInt8((windowIncrement >> 24) & 0xFF)
        wuPayload[1] = UInt8((windowIncrement >> 16) & 0xFF)
        wuPayload[2] = UInt8((windowIncrement >> 8) & 0xFF)
        wuPayload[3] = UInt8(windowIncrement & 0xFF)
        initData.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: wuPayload))

        // Send preface + settings + window_update (NO HEADERS yet — wait for server settings first)
        downloadSend(initData) { [weak self] error in
            if let error {
                completion(XHTTPError.setupFailed("H2 preface send failed: \(error.localizedDescription)"))
                return
            }

            // Phase 2: Read server SETTINGS, then send HEADERS
            self?.waitForServerSettings(completion: completion)
        }
    }

    /// Reads frames until we receive the server's SETTINGS frame, sends ACK,
    /// then sends the HEADERS frame for the POST request.
    private func waitForServerSettings(completion: @escaping (Error?) -> Void) {
        readH2Frame { [weak self] result in
            guard let self else {
                completion(XHTTPError.connectionClosed)
                return
            }

            switch result {
            case .failure(let error):
                completion(XHTTPError.setupFailed("H2 settings exchange failed: \(error.localizedDescription)"))

            case .success(let frame):
                switch frame.type {
                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck != 0 {
                        // SETTINGS ACK for our settings — keep waiting for server's own SETTINGS
                        self.waitForServerSettings(completion: completion)
                    } else {
                        // Server's SETTINGS — parse and send ACK
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }

                        // Phase 3: Now send HEADERS for stream 1
                        self.sendH2Headers(completion: completion)
                    }

                case Self.h2FrameWindowUpdate:
                    self.lock.lock()
                    if frame.payload.count >= 4 {
                        let increment = (UInt32(frame.payload[0]) << 24) | (UInt32(frame.payload[1]) << 16) | (UInt32(frame.payload[2]) << 8) | UInt32(frame.payload[3])
                        self.h2PeerWindowSize += Int(increment & 0x7FFFFFFF)
                    }
                    self.lock.unlock()
                    self.waitForServerSettings(completion: completion)

                case Self.h2FramePing:
                    let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                    self.downloadSend(pong) { _ in }
                    self.waitForServerSettings(completion: completion)

                case Self.h2FrameGoaway:
                    completion(XHTTPError.setupFailed("Server sent GOAWAY during settings exchange"))

                default:
                    self.waitForServerSettings(completion: completion)
                }
            }
        }
    }

    /// Sends the HEADERS frame for the stream-one POST, then waits for the response.
    private func sendH2Headers(completion: @escaping (Error?) -> Void) {
        let headerBlock = encodeH2RequestHeaders()
        // END_HEADERS (0x04), but NOT END_STREAM (body follows)
        let headersFrame = buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: 1, payload: headerBlock)

        downloadSend(headersFrame) { [weak self] error in
            if let error {
                completion(XHTTPError.setupFailed("H2 HEADERS send failed: \(error.localizedDescription)"))
                return
            }

            // Phase 4: Wait for server's HEADERS response (200 OK)
            self?.readH2ResponseHeaders(completion: completion)
        }
    }

    /// Reads server frames after sending HEADERS, waiting for the response HEADERS.
    private func readH2ResponseHeaders(completion: @escaping (Error?) -> Void) {
        readH2Frame { [weak self] result in
            guard let self else {
                completion(XHTTPError.connectionClosed)
                return
            }

            switch result {
            case .failure(let error):
                completion(XHTTPError.setupFailed("H2 frame read failed: \(error.localizedDescription)"))

            case .success(let frame):
                switch frame.type {
                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck == 0 {
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }
                    }
                    self.readH2ResponseHeaders(completion: completion)

                case Self.h2FrameHeaders:
                    // Response headers for stream 1
                    if let statusError = self.checkH2ResponseStatus(frame.payload) {
                        completion(XHTTPError.httpError("H2 response \(statusError)"))
                    } else {
                        self.lock.lock()
                        self.h2ResponseReceived = true
                        self.lock.unlock()
                        completion(nil)
                    }

                case Self.h2FrameWindowUpdate:
                    self.lock.lock()
                    if frame.payload.count >= 4 {
                        let increment = (UInt32(frame.payload[0]) << 24) | (UInt32(frame.payload[1]) << 16) | (UInt32(frame.payload[2]) << 8) | UInt32(frame.payload[3])
                        self.h2PeerWindowSize += Int(increment & 0x7FFFFFFF)
                    }
                    self.lock.unlock()
                    self.readH2ResponseHeaders(completion: completion)

                case Self.h2FramePing:
                    let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                    self.downloadSend(pong) { _ in }
                    self.readH2ResponseHeaders(completion: completion)

                case Self.h2FrameGoaway:
                    completion(XHTTPError.setupFailed("Server sent GOAWAY during setup"))

                case Self.h2FrameRstStream:
                    completion(XHTTPError.setupFailed("Server sent RST_STREAM during setup"))

                case Self.h2FrameData:
                    // Early DATA before we saw HEADERS — buffer it
                    self.lock.lock()
                    self.h2DataBuffer.append(frame.payload)
                    self.lock.unlock()
                    self.readH2ResponseHeaders(completion: completion)

                default:
                    self.readH2ResponseHeaders(completion: completion)
                }
            }
        }
    }

    /// Parses server SETTINGS payload to extract initial window size and max frame size.
    private func parseH2Settings(_ payload: Data) {
        // Each setting is 6 bytes: 2-byte ID + 4-byte value
        var offset = payload.startIndex
        while offset + 6 <= payload.endIndex {
            let id = (UInt16(payload[offset]) << 8) | UInt16(payload[offset + 1])
            let value = (UInt32(payload[offset + 2]) << 24) | (UInt32(payload[offset + 3]) << 16) | (UInt32(payload[offset + 4]) << 8) | UInt32(payload[offset + 5])
            offset += 6

            switch id {
            case 0x04: // INITIAL_WINDOW_SIZE (RFC 7540 §6.9.2: adjust by delta)
                lock.lock()
                let delta = Int(value) - h2PeerInitialWindowSize
                h2PeerInitialWindowSize = Int(value)
                h2PeerWindowSize += delta
                lock.unlock()
            case 0x05: // MAX_FRAME_SIZE
                lock.lock()
                h2MaxFrameSize = Int(value)
                lock.unlock()
            default:
                break
            }
        }
    }

    // MARK: HTTP/2 Send

    /// Sends data as HTTP/2 DATA frame(s) on stream 1.
    private func sendH2Data(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        let maxSize = h2MaxFrameSize
        lock.unlock()

        if data.count <= maxSize {
            let frame = buildH2Frame(type: Self.h2FrameData, flags: 0, streamId: 1, payload: data)
            downloadSend(frame, completion)
        } else {
            // Split into multiple DATA frames
            let firstChunk = data.prefix(maxSize)
            let remaining = data.suffix(from: data.startIndex + maxSize)
            let frame = buildH2Frame(type: Self.h2FrameData, flags: 0, streamId: 1, payload: Data(firstChunk))
            downloadSend(frame) { [weak self] error in
                if let error {
                    completion(error)
                    return
                }
                self?.sendH2Data(data: Data(remaining), completion: completion)
            }
        }
    }

    // MARK: HTTP/2 Receive

    /// Receives data from HTTP/2 DATA frames on stream 1.
    private func receiveH2Data(completion: @escaping (Data?, Error?) -> Void) {
        // Check buffered data first
        lock.lock()
        if !h2DataBuffer.isEmpty {
            let data = h2DataBuffer
            h2DataBuffer.removeAll()
            lock.unlock()
            completion(data, nil)
            return
        }
        if h2StreamClosed {
            lock.unlock()
            completion(nil, nil)
            return
        }
        lock.unlock()

        // Read next frame
        readH2Frame { [weak self] result in
            guard let self else {
                completion(nil, XHTTPError.connectionClosed)
                return
            }

            switch result {
            case .failure:
                completion(nil, nil) // EOF

            case .success(let frame):
                switch frame.type {
                case Self.h2FrameData:
                    // Send WINDOW_UPDATE to keep flow control open
                    if !frame.payload.isEmpty {
                        let increment = UInt32(frame.payload.count)
                        var wuPayload = Data(count: 4)
                        wuPayload[0] = UInt8((increment >> 24) & 0xFF)
                        wuPayload[1] = UInt8((increment >> 16) & 0xFF)
                        wuPayload[2] = UInt8((increment >> 8) & 0xFF)
                        wuPayload[3] = UInt8(increment & 0xFF)
                        // Stream-level + connection-level WINDOW_UPDATE
                        var updates = self.buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 1, payload: wuPayload)
                        updates.append(self.buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: wuPayload))
                        self.downloadSend(updates) { _ in }
                    }

                    if frame.flags & Self.h2FlagEndStream != 0 {
                        self.lock.lock()
                        self.h2StreamClosed = true
                        self.lock.unlock()
                    }

                    if frame.payload.isEmpty {
                        // Empty DATA frame (possibly END_STREAM)
                        if frame.flags & Self.h2FlagEndStream != 0 {
                            completion(nil, nil)
                        } else {
                            self.receiveH2Data(completion: completion)
                        }
                    } else {
                        completion(frame.payload, nil)
                    }

                case Self.h2FrameHeaders:
                    // Could be trailing headers (END_STREAM)
                    if frame.flags & Self.h2FlagEndStream != 0 {
                        self.lock.lock()
                        self.h2StreamClosed = true
                        self.lock.unlock()
                        completion(nil, nil)
                    } else if !self.h2ResponseReceived {
                        // Late response headers
                        if self.checkH2ResponseStatus(frame.payload) == nil {
                            self.lock.lock()
                            self.h2ResponseReceived = true
                            self.lock.unlock()
                        }
                        self.receiveH2Data(completion: completion)
                    } else {
                        self.receiveH2Data(completion: completion)
                    }

                case Self.h2FrameSettings:
                    if frame.flags & Self.h2FlagAck == 0 {
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }
                    }
                    self.receiveH2Data(completion: completion)

                case Self.h2FrameWindowUpdate:
                    self.lock.lock()
                    if frame.payload.count >= 4 {
                        let increment = (UInt32(frame.payload[0]) << 24) | (UInt32(frame.payload[1]) << 16) | (UInt32(frame.payload[2]) << 8) | UInt32(frame.payload[3])
                        self.h2PeerWindowSize += Int(increment & 0x7FFFFFFF)
                    }
                    self.lock.unlock()
                    self.receiveH2Data(completion: completion)

                case Self.h2FramePing:
                    let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                    self.downloadSend(pong) { _ in }
                    self.receiveH2Data(completion: completion)

                case Self.h2FrameGoaway:
                    self.lock.lock()
                    self.h2StreamClosed = true
                    self.lock.unlock()
                    completion(nil, nil)

                case Self.h2FrameRstStream:
                    self.lock.lock()
                    self.h2StreamClosed = true
                    self.lock.unlock()
                    completion(nil, nil)

                default:
                    self.receiveH2Data(completion: completion)
                }
            }
        }
    }
}

// MARK: - ChunkedTransferDecoder

/// Stateful chunked transfer encoding decoder (HTTP/1.1 RFC 7230 §4.1).
///
/// Handles partial reads: data can be fed incrementally and chunks extracted as they become complete.
struct ChunkedTransferDecoder {
    private var buffer = Data()
    private var _isFinished = false

    var isFinished: Bool { _isFinished }

    /// Feed raw data from the transport into the decoder.
    mutating func feed(_ data: Data) {
        buffer.append(data)
    }

    /// Try to extract the next complete chunk from the buffer.
    ///
    /// Returns the chunk payload (without framing), or `nil` if not enough data is available yet.
    /// Returns empty `Data()` if a zero-length terminator chunk is found (EOF).
    mutating func nextChunk() -> Data? {
        guard !_isFinished else { return nil }

        // Look for the chunk-size line ending with \r\n
        let crlf = Data([0x0D, 0x0A])
        guard let crlfRange = buffer.range(of: crlf) else {
            return nil
        }

        let sizeLineData = buffer[buffer.startIndex..<crlfRange.lowerBound]
        guard let sizeLine = String(data: Data(sizeLineData), encoding: .ascii) else {
            return nil
        }

        // Parse hex chunk size (ignoring chunk extensions after ";")
        let sizeStr = sizeLine.split(separator: ";", maxSplits: 1).first.map(String.init) ?? sizeLine
        guard let chunkSize = UInt64(sizeStr.trimmingCharacters(in: .whitespaces), radix: 16) else {
            return nil
        }

        if chunkSize == 0 {
            // Terminal chunk
            _isFinished = true
            // Consume "0\r\n\r\n" (the trailing CRLF after the zero chunk)
            let termEnd = crlfRange.upperBound
            if buffer.endIndex >= termEnd + 2 {
                buffer.removeFirst(termEnd + 2 - buffer.startIndex)
            }
            buffer = Data()
            return nil
        }

        // Check if we have the full chunk data + trailing \r\n
        let dataStart = crlfRange.upperBound
        let needed = dataStart + Int(chunkSize) + 2 // chunk data + \r\n
        guard buffer.endIndex >= needed else {
            return nil // Need more data
        }

        let chunkData = Data(buffer[dataStart..<dataStart + Int(chunkSize)])

        // Consume the chunk from the buffer (size line + \r\n + data + \r\n)
        buffer.removeFirst(needed - buffer.startIndex)
        if buffer.isEmpty { buffer = Data() }

        return chunkData
    }
}

// MARK: - ChunkedTransferEncoder

/// Chunked transfer encoding encoder (HTTP/1.1 RFC 7230 §4.1).
enum ChunkedTransferEncoder {
    /// Encodes data as a single chunked-encoded chunk: `{hex-size}\r\n{data}\r\n`.
    static func encode(_ data: Data) -> Data {
        let sizeStr = String(data.count, radix: 16)
        var encoded = Data()
        encoded.append(contentsOf: sizeStr.utf8)
        encoded.append(contentsOf: [0x0D, 0x0A]) // \r\n
        encoded.append(data)
        encoded.append(contentsOf: [0x0D, 0x0A]) // \r\n
        return encoded
    }

    /// Encodes the terminal zero-length chunk: `0\r\n\r\n`.
    static func encodeTerminator() -> Data {
        return Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A]) // "0\r\n\r\n"
    }
}
