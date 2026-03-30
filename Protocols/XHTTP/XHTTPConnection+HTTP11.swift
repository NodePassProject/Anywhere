//
//  XHTTPConfiguration.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/30/26.
//

import Foundation

// MARK: - HTTP/1.1 Setup & Transport

extension XHTTPConnection {

    // MARK: stream-one Setup

    func performStreamOneSetup(completion: @escaping (Error?) -> Void) {
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

    func performPacketUpSetup(completion: @escaping (Error?) -> Void) {
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
            self?.receiveResponseHeaders { [weak self] headerError in
                if let headerError {
                    completion(headerError)
                    return
                }
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
                        // Drain HTTP/1.1 POST responses in background to prevent
                        // TCP receive-buffer saturation (see startUploadResponseDrain).
                        self?.startUploadResponseDrain()
                        completion(nil)
                    case .failure(let error):
                        completion(XHTTPError.setupFailed("Upload connection failed: \(error.localizedDescription)"))
                    }
                }
            }
        }
    }

    // MARK: Upload Response Drain

    /// Starts a background loop that continuously reads from the upload connection
    /// and discards all data (HTTP/1.1 responses to POST requests).
    ///
    /// In HTTP/1.1 packet-up mode each POST request receives an HTTP response
    /// (e.g. `HTTP/1.1 200 OK …`).  If these responses are never consumed they
    /// accumulate in the TCP receive buffer.  Once the buffer fills the server's
    /// response writes block, preventing it from processing further requests on
    /// this connection and causing intermittent stalls.
    ///
    /// HTTP/2 does not need this because upload-stream responses are consumed
    /// inline by the shared H2 frame reader (`receiveH2Data`).
    func startUploadResponseDrain() {
        drainNextUploadResponse()
    }

    private func drainNextUploadResponse() {
        lock.lock()
        guard let uploadReceive = self.uploadReceive, _isConnected else {
            lock.unlock()
            return
        }
        lock.unlock()

        uploadReceive { [weak self] data, isComplete, error in
            guard let self else { return }
            if error != nil || isComplete {
                return // Upload connection closed — stop draining.
            }
            // Discard the received data (HTTP response bytes) and keep draining.
            self.drainNextUploadResponse()
        }
    }

    // MARK: stream-up Setup

    func performStreamUpSetup(completion: @escaping (Error?) -> Void) {
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
    func buildDownloadGETRequest() -> String {
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
    func buildStreamUpPOSTRequest() -> String {
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
    func receiveResponseHeaders(completion: @escaping (Error?) -> Void) {
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

    // MARK: - HTTP/1.1 Send

    /// Sends data as a chunked-encoded chunk on the stream-one POST.
    func sendStreamOne(data: Data, completion: @escaping (Error?) -> Void) {
        let chunk = ChunkedTransferEncoder.encode(data)
        downloadSend(chunk, completion)
    }

    /// Sends data as a chunked-encoded chunk on the stream-up upload POST.
    func sendStreamUp(data: Data, completion: @escaping (Error?) -> Void) {
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

    /// Sends data as a POST request with sequence number on the upload connection.
    func sendPacketUp(data: Data, completion: @escaping (Error?) -> Void) {
        lock.lock()
        guard let uploadSend = self.uploadSend else {
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
            sendSinglePost(data: data, seq: seq, uploadSend: uploadSend, completion: completion)
        } else {
            // Send first chunk with current seq, remaining chunks will use subsequent seqs
            let firstChunk = data.prefix(maxSize)
            let remaining = data.suffix(from: maxSize)
            sendSinglePost(data: Data(firstChunk), seq: seq, uploadSend: uploadSend) { [weak self] error in
                if let error {
                    completion(error)
                    return
                }
                // Recurse for remaining data
                self?.sendPacketUp(data: Data(remaining), completion: completion)
            }
        }
    }

    /// Sends a single POST request on the upload connection.
    private func sendSinglePost(
        data: Data,
        seq: Int64,
        uploadSend: @escaping (Data, @escaping (Error?) -> Void) -> Void,
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
            } else {
                self?.completePacketUpWithDelay(completion: completion)
            }
        }
    }
}
