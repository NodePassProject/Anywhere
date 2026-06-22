//
//  XHTTPConnection+HTTP11.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation

// MARK: - HTTP/1.1 Setup & Transport

extension XHTTPConnection {

    // MARK: stream-one Setup

    func performStreamOneSetup(completion: @escaping (Error?) -> Void) {
        let method = configuration.uplinkHTTPMethod
        let path = configuration.normalizedPath
        var request = ""

        // stream-one carries no session ID in the path.
        let metaQuery = queryParamsForMeta()
        request += buildRequestLine(method: method, path: path, queryParts: [metaQuery])
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? ProxyUserAgent.default)\r\n"
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

    /// Discards POST responses in a loop; otherwise they fill the TCP receive buffer and stall the server.
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
                return
            }
            self.drainNextUploadResponse()
        }
    }

    // MARK: stream-up Setup

    func performStreamUpSetup(completion: @escaping (Error?) -> Void) {
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
                        guard let self else {
                            completion(XHTTPError.setupFailed("Connection deallocated"))
                            return
                        }
                        self.lock.lock()
                        self.uploadSend = closures.send
                        self.uploadReceive = closures.receive
                        self.uploadCancel = closures.cancel
                        self.lock.unlock()

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

    // MARK: Detached leg Setup (up/download detach)

    func performDownloadOnlyHTTP11Setup(completion: @escaping (Error?) -> Void) {
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
            self?.receiveResponseHeaders(completion: completion)
        }
    }

    /// Its own transport *is* the upload connection, so `uploadSend`/`uploadReceive` alias it.
    /// `uploadCancel` stays nil — `downloadCancel` already tears down this transport, avoiding a double cancel.
    func performUploadOnlyHTTP11Setup(completion: @escaping (Error?) -> Void) {
        lock.lock()
        uploadSend = downloadSend
        uploadReceive = downloadReceive
        lock.unlock()

        if mode == .streamUp {
            let postRequest = buildStreamUpPOSTRequest()
            guard let postData = postRequest.data(using: .utf8) else {
                completion(XHTTPError.setupFailed("Failed to encode stream-up POST request"))
                return
            }
            downloadSend(postData) { error in
                if let error {
                    completion(XHTTPError.setupFailed("Stream-up POST send failed: \(error.localizedDescription)"))
                } else {
                    completion(nil)
                }
            }
        } else {
            // packet-up: each send() is its own POST.
            startUploadResponseDrain()
            completion(nil)
        }
    }

    // MARK: - Request Builders

    func buildDownloadGETRequest() -> String {
        var path = configuration.normalizedPath
        var request = ""
        applySessionId(to: &request, path: &path)
        let metaQuery = queryParamsForMeta()
        request = buildRequestLine(method: "GET", path: path, queryParts: [metaQuery]) + request
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? ProxyUserAgent.default)\r\n"
        applyPadding(to: &request, forPath: path)
        for (key, value) in configuration.headers where key != "User-Agent" {
            request += "\(key): \(value)\r\n"
        }
        request += "\r\n"
        return request
    }

    func buildStreamUpPOSTRequest() -> String {
        let method = configuration.uplinkHTTPMethod
        var path = configuration.normalizedPath
        var request = ""
        applySessionId(to: &request, path: &path)
        let metaQuery = queryParamsForMeta()
        request = buildRequestLine(method: method, path: path, queryParts: [metaQuery]) + request
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? ProxyUserAgent.default)\r\n"
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
                self.receiveResponseHeaders(completion: completion)
                return
            }

            let headerData = self.headerBuffer[self.headerBuffer.startIndex..<range.lowerBound]
            let leftover = Data(self.headerBuffer[range.upperBound...])
            self.headerBuffer.removeAll()
            self.downloadHeadersParsed = true

            if !leftover.isEmpty {
                self.chunkedDecoder.feed(leftover)
            }
            self.lock.unlock()

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

    func sendStreamOne(data: Data, completion: @escaping (Error?) -> Void) {
        let chunk = ChunkedTransferEncoder.encode(data)
        downloadSend(chunk, completion)
    }

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

        let maxSize = configuration.scMaxEachPostBytes
        if data.count <= maxSize {
            sendSinglePost(data: data, seq: seq, uploadSend: uploadSend, completion: completion)
        } else {
            let firstChunk = data.prefix(maxSize)
            let remaining = data.suffix(from: maxSize)
            sendSinglePost(data: Data(firstChunk), seq: seq, uploadSend: uploadSend) { [weak self] error in
                if let error {
                    completion(error)
                    return
                }
                self?.sendPacketUp(data: Data(remaining), completion: completion)
            }
        }
    }

    private func sendSinglePost(
        data: Data,
        seq: Int64,
        uploadSend: @escaping (Data, @escaping (Error?) -> Void) -> Void,
        completion: @escaping (Error?) -> Void
    ) {
        let method = configuration.uplinkHTTPMethod
        var path = configuration.normalizedPath
        var headerBlock = ""

        applySessionId(to: &headerBlock, path: &path)
        applySeq(to: &headerBlock, path: &path, seq: seq)

        // Header/cookie placement carries the payload outside the body.
        let bodyData: Data
        let dataFields = uplinkDataFields(for: data)
        if dataFields.isEmpty {
            bodyData = data
        } else {
            for field in dataFields {
                switch field {
                case .header(let name, let value): headerBlock += "\(name): \(value)\r\n"
                case .cookie(let pair):            headerBlock += "Cookie: \(pair)\r\n"
                }
            }
            bodyData = Data()
        }

        let metaQuery = queryParamsForMeta(seq: seq)
        var request = buildRequestLine(method: method, path: path, queryParts: [metaQuery])
        request += "Host: \(configuration.host)\r\n"
        request += "User-Agent: \(configuration.headers["User-Agent"] ?? ProxyUserAgent.default)\r\n"
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

        // Rate limiting between POSTs is enforced upstream by flushPacketUpBatch.
        uploadSend(requestData, completion)
    }
}
