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

/// XHTTP connection implementing both packet-up and stream-one modes.
///
/// Uses the same closure-based transport abstraction as ``WebSocketConnection`` and ``HTTPUpgradeConnection``.
class XHTTPConnection {

    let configuration: XHTTPConfiguration
    let mode: XHTTPMode
    let sessionId: String

    // Download / stream-one connection (closure-based, from VLESSClient)
    private let downloadSend: (Data, @escaping (Error?) -> Void) -> Void
    private let downloadReceive: (@escaping (Data?, Bool, Error?) -> Void) -> Void
    private let downloadCancel: () -> Void

    // Upload connection factory (packet-up only)
    private let uploadConnectionFactory: ((@escaping (Result<TransportClosures, Error>) -> Void) -> Void)?

    // Upload connection state (packet-up only)
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
    private var h2PeerWindowSize: Int = 65535
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

    /// Generates the `Referer` header value containing X-Padding.
    ///
    /// Default non-obfs mode: `Referer: https://{host}{path}?x_padding=XXX...`
    /// Server validates padding length is within 100-1000 bytes (default range).
    /// Matches Xray-core `ApplyXPaddingToRequest` with `PlacementQueryInHeader`.
    private func generatePaddingReferer(forPath path: String) -> String {
        let length = Int.random(in: 100...1000)
        let padding = String(repeating: "X", count: length)
        return "https://\(configuration.host)\(path)?x_padding=\(padding)"
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
    /// - For packet-up mode: sends a GET request for the download stream, reads response headers,
    ///   and establishes the upload connection via the factory.
    func performSetup(completion: @escaping (Error?) -> Void) {
        if useHTTP2 {
            performH2Setup(completion: completion)
        } else if mode == .streamOne {
            performStreamOneSetup(completion: completion)
        } else {
            performPacketUpSetup(completion: completion)
        }
    }

    // MARK: stream-one Setup

    private func performStreamOneSetup(completion: @escaping (Error?) -> Void) {
        var request = "POST \(configuration.normalizedPath) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        request += "Referer: \(generatePaddingReferer(forPath: configuration.normalizedPath))\r\n"
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
        let getPath = "\(configuration.normalizedPath)\(sessionId)/"
        var request = "GET \(getPath) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        request += "Referer: \(generatePaddingReferer(forPath: getPath))\r\n"
        for (key, value) in configuration.headers where key != "User-Agent" {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"

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
        let postPath = "\(configuration.normalizedPath)\(sessionId)/\(seq)"
        var request = "POST \(postPath) HTTP/1.1\r\n"
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? defaultUserAgent)\r\n"
        request += "Referer: \(generatePaddingReferer(forPath: postPath))\r\n"
        request += "Content-Length: \(data.count)\r\n"
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
        requestData.append(data)

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

        // referer (X-Padding) — name index 51
        // Xray-core sends padding as Referer URL with x_padding query param (xpadding.go)
        let referer = generatePaddingReferer(forPath: configuration.normalizedPath)
        var refBytes = Self.hpackEncodeInteger(51, prefixBits: 4)
        refBytes[0] &= 0x0F
        block.append(contentsOf: refBytes)
        block.append(contentsOf: Self.hpackEncodeString(referer))

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
    private func checkH2ResponseStatus(_ headerBlock: Data) -> Bool {
        guard !headerBlock.isEmpty else { return false }
        // 0x88 = indexed representation of :status 200 (static table index 8)
        if headerBlock[headerBlock.startIndex] == 0x88 {
            return true
        }
        // Also accept literal with name index 8, value "200"
        // 0x48 = literal with incremental indexing, name index 8
        if headerBlock.count >= 5 && headerBlock[headerBlock.startIndex] == 0x48 {
            let valueStart = headerBlock.startIndex + 2 // skip 0x48 and length byte
            if headerBlock[headerBlock.startIndex + 1] == 0x03, // length=3
               headerBlock.count >= valueStart + 3 {
                let value = String(data: headerBlock[valueStart..<valueStart + 3], encoding: .ascii)
                return value == "200"
            }
        }
        return false
    }

    // MARK: HTTP/2 Setup

    /// Performs HTTP/2 connection setup: sends preface + SETTINGS + WINDOW_UPDATE,
    /// exchanges settings with server, sends HEADERS for the stream-one POST.
    func performH2Setup(completion: @escaping (Error?) -> Void) {
        // Build initial data: preface + SETTINGS + WINDOW_UPDATE
        var initData = Data()

        // 1. Connection preface
        initData.append(Self.h2Preface)

        // 2. Client SETTINGS frame
        var settingsPayload = Data()
        // ENABLE_PUSH = 0
        settingsPayload.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        // INITIAL_WINDOW_SIZE = 4MB (matches Go http2.Transport)
        let winSize = Self.h2StreamWindowSize
        settingsPayload.append(contentsOf: [
            0x00, 0x04,
            UInt8((winSize >> 24) & 0xFF), UInt8((winSize >> 16) & 0xFF),
            UInt8((winSize >> 8) & 0xFF), UInt8(winSize & 0xFF)
        ])
        initData.append(buildH2Frame(type: Self.h2FrameSettings, flags: 0, streamId: 0, payload: settingsPayload))

        // 3. Connection-level WINDOW_UPDATE (increase from default 65535 to 1GB)
        let windowIncrement = Self.h2ConnWindowSize - 65535
        var wuPayload = Data(count: 4)
        wuPayload[0] = UInt8((windowIncrement >> 24) & 0xFF)
        wuPayload[1] = UInt8((windowIncrement >> 16) & 0xFF)
        wuPayload[2] = UInt8((windowIncrement >> 8) & 0xFF)
        wuPayload[3] = UInt8(windowIncrement & 0xFF)
        initData.append(buildH2Frame(type: Self.h2FrameWindowUpdate, flags: 0, streamId: 0, payload: wuPayload))

        // 4. HEADERS frame for stream 1 (the stream-one POST request)
        let headerBlock = encodeH2RequestHeaders()
        // END_HEADERS (0x04), but NOT END_STREAM (body follows)
        initData.append(buildH2Frame(type: Self.h2FrameHeaders, flags: Self.h2FlagEndHeaders, streamId: 1, payload: headerBlock))

        // Send all at once
        downloadSend(initData) { [weak self] error in
            if let error {
                completion(XHTTPError.setupFailed("H2 preface send failed: \(error.localizedDescription)"))
                return
            }

            // Read server frames until we get SETTINGS and HEADERS response
            self?.readH2SetupFrames(completion: completion)
        }
    }

    /// Reads server frames during setup: process SETTINGS, wait for HEADERS response.
    private func readH2SetupFrames(completion: @escaping (Error?) -> Void) {
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
                    if frame.flags & Self.h2FlagAck != 0 {
                        // SETTINGS ACK
                    } else {
                        // Server's SETTINGS — parse and send ACK
                        self.parseH2Settings(frame.payload)
                        let ack = self.buildH2Frame(type: Self.h2FrameSettings, flags: Self.h2FlagAck, streamId: 0, payload: Data())
                        self.downloadSend(ack) { _ in }
                    }
                    // Keep reading until we get HEADERS response
                    self.readH2SetupFrames(completion: completion)

                case Self.h2FrameHeaders:
                    // Response headers for stream 1
                    if self.checkH2ResponseStatus(frame.payload) {
                        self.lock.lock()
                        self.h2ResponseReceived = true
                        self.lock.unlock()
                        completion(nil)
                    } else {
                        completion(XHTTPError.httpError("H2 response status is not 200"))
                    }

                case Self.h2FrameWindowUpdate:
                    self.lock.lock()
                    if frame.payload.count >= 4 {
                        let increment = (UInt32(frame.payload[0]) << 24) | (UInt32(frame.payload[1]) << 16) | (UInt32(frame.payload[2]) << 8) | UInt32(frame.payload[3])
                        self.h2PeerWindowSize += Int(increment & 0x7FFFFFFF)
                    }
                    self.lock.unlock()
                    self.readH2SetupFrames(completion: completion)

                case Self.h2FramePing:
                    // Send PONG
                    let pong = self.buildH2Frame(type: Self.h2FramePing, flags: Self.h2FlagAck, streamId: 0, payload: frame.payload)
                    self.downloadSend(pong) { _ in }
                    self.readH2SetupFrames(completion: completion)

                case Self.h2FrameGoaway:
                    completion(XHTTPError.setupFailed("Server sent GOAWAY during setup"))

                case Self.h2FrameData:
                    // Early DATA before we saw HEADERS — buffer it
                    self.lock.lock()
                    self.h2DataBuffer.append(frame.payload)
                    self.lock.unlock()
                    self.readH2SetupFrames(completion: completion)

                default:
                    // Ignore unknown frames
                    self.readH2SetupFrames(completion: completion)
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
            case 0x04: // INITIAL_WINDOW_SIZE
                lock.lock()
                h2PeerWindowSize = Int(value)
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
                        if self.checkH2ResponseStatus(frame.payload) {
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
            } else {
                buffer.removeAll()
            }
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
