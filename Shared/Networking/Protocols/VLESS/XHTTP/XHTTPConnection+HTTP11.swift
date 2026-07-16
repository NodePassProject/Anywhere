//
//  XHTTPConnection+HTTP11.swift
//  Anywhere
//
//  Created by NodePassProject on 3/30/26.
//

import Foundation
import Synchronization

extension XHTTPConnection {

    // MARK: stream-one Setup

    func performStreamOneSetup() async throws {
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
            throw XHTTPError.setupFailed("Failed to encode stream-one request")
        }

        do {
            try await download.send(requestData)
        } catch {
            throw XHTTPError.setupFailed(error.localizedDescription)
        }
        try await receiveResponseHeaders()
    }

    // MARK: packet-up Setup

    func performPacketUpSetup() async throws {
        let request = buildDownloadGETRequest()

        guard let requestData = request.data(using: .utf8) else {
            throw XHTTPError.setupFailed("Failed to encode GET request")
        }

        do {
            try await download.send(requestData)
        } catch {
            throw XHTTPError.setupFailed(error.localizedDescription)
        }
        try await receiveResponseHeaders()

        guard let factory = uploadConnectionFactory else {
            throw XHTTPError.setupFailed("No upload connection factory")
        }
        let closures: AsyncTransportClosures
        do {
            closures = try await factory()
        } catch {
            throw XHTTPError.setupFailed("Upload connection failed: \(error.localizedDescription)")
        }
        state.withLock { $0.uploadTransport = closures }
        startUploadResponseDrain()
    }

    // MARK: Upload Response Drain

    /// Discards POST responses in a loop; otherwise they fill the TCP receive buffer and stall the server.
    func startUploadResponseDrain() {
        guard let upload = state.withLock({ $0.uploadTransport }) else { return }
        Task { [weak self] in
            while true {
                guard let self, self.state.withLock({ $0._isConnected }) else { return }
                let chunk: TransportChunk
                do {
                    chunk = try await upload.receive()
                } catch {
                    return
                }
                if case .end = chunk { return }
                // .bytes → discard and keep draining.
            }
        }
    }

    // MARK: stream-up Setup

    func performStreamUpSetup() async throws {
        let request = buildDownloadGETRequest()

        guard let requestData = request.data(using: .utf8) else {
            throw XHTTPError.setupFailed("Failed to encode GET request")
        }

        do {
            try await download.send(requestData)
        } catch {
            throw XHTTPError.setupFailed(error.localizedDescription)
        }
        try await receiveResponseHeaders()

        guard let factory = uploadConnectionFactory else {
            throw XHTTPError.setupFailed("No upload connection factory")
        }
        let closures: AsyncTransportClosures
        do {
            closures = try await factory()
        } catch {
            throw XHTTPError.setupFailed("Upload connection failed: \(error.localizedDescription)")
        }
        state.withLock { $0.uploadTransport = closures }

        let postRequest = buildStreamUpPOSTRequest()
        guard let postData = postRequest.data(using: .utf8) else {
            throw XHTTPError.setupFailed("Failed to encode stream-up POST request")
        }
        do {
            try await closures.send(postData)
        } catch {
            throw XHTTPError.setupFailed("Stream-up POST send failed: \(error.localizedDescription)")
        }
    }

    // MARK: Detached leg Setup (up/download detach)

    func performDownloadOnlyHTTP11Setup() async throws {
        let request = buildDownloadGETRequest()
        guard let requestData = request.data(using: .utf8) else {
            throw XHTTPError.setupFailed("Failed to encode GET request")
        }
        do {
            try await download.send(requestData)
        } catch {
            throw XHTTPError.setupFailed(error.localizedDescription)
        }
        try await receiveResponseHeaders()
    }

    /// Its own transport *is* the upload connection, so `uploadTransport` aliases it with a no-op
    /// cancel — the download transport's own cancel already tears it down, avoiding a double cancel.
    func performUploadOnlyHTTP11Setup() async throws {
        let upload = AsyncTransportClosures(
            send: download.send, finishSend: download.finishSend, receive: download.receive, cancel: {}
        )
        state.withLock { $0.uploadTransport = upload }

        if mode == .streamUp {
            let postRequest = buildStreamUpPOSTRequest()
            guard let postData = postRequest.data(using: .utf8) else {
                throw XHTTPError.setupFailed("Failed to encode stream-up POST request")
            }
            do {
                try await download.send(postData)
            } catch {
                throw XHTTPError.setupFailed("Stream-up POST send failed: \(error.localizedDescription)")
            }
        } else {
            // packet-up: each send() is its own POST.
            startUploadResponseDrain()
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

    func receiveResponseHeaders() async throws {
        let headerEnd = Data([0x0D, 0x0A, 0x0D, 0x0A]) // \r\n\r\n
        while true {
            let chunk: TransportChunk
            do {
                chunk = try await download.receive()
            } catch {
                throw XHTTPError.setupFailed(error.localizedDescription)
            }
            guard case .bytes(let data) = chunk, !data.isEmpty else {
                throw XHTTPError.setupFailed("Empty response from server")
            }

            let headerData: Data? = state.withLock { state in
                state.headerBuffer.append(data)
                guard let range = state.headerBuffer.range(of: headerEnd) else { return nil }
                let headerData = Data(state.headerBuffer[state.headerBuffer.startIndex..<range.lowerBound])
                let leftover = Data(state.headerBuffer[range.upperBound...])
                state.headerBuffer.removeAll()
                state.downloadHeadersParsed = true
                if !leftover.isEmpty { state.chunkedDecoder.feed(leftover) }
                return headerData
            }
            guard let headerData else { continue } // headers not yet complete; read more

            guard let headerString = String(data: headerData, encoding: .utf8) else {
                throw XHTTPError.httpError("Cannot decode response headers")
            }
            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("200") else {
                throw XHTTPError.httpError("Expected HTTP 200, got: \(firstLine)")
            }
            return
        }
    }

    // MARK: - HTTP/1.1 Send

    func sendStreamOne(data: Data) async throws {
        try await download.send(ChunkedTransferEncoder.encode(data))
    }

    func sendStreamUp(data: Data) async throws {
        guard let upload = state.withLock({ $0.uploadTransport }) else {
            throw XHTTPError.setupFailed("Upload connection not established")
        }
        try await upload.send(ChunkedTransferEncoder.encode(data))
    }

    /// Sends the packet-up payload as one POST, re-splitting an oversized payload into
    /// back-to-back POSTs (each with its own seq). Called under `packetUpMutex`.
    func sendPacketUpHTTP11(data: Data) async throws {
        guard let upload = state.withLock({ $0.uploadTransport }) else {
            throw XHTTPError.setupFailed("Upload connection not established")
        }
        let maxSize = max(1, configuration.scMaxEachPostBytes)
        var remaining = data
        repeat {
            let piece = Data(remaining.prefix(maxSize))
            remaining = Data(remaining.dropFirst(maxSize))
            let seq = state.withLock { state -> Int64 in let s = state.nextSeq; state.nextSeq += 1; return s }
            try await sendSinglePost(data: piece, seq: seq, upload: upload)
        } while !remaining.isEmpty
    }

    private func sendSinglePost(data: Data, seq: Int64, upload: AsyncTransportClosures) async throws {
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
            throw XHTTPError.setupFailed("Failed to encode POST request")
        }
        requestData.append(bodyData)

        // Rate limiting between POSTs is enforced upstream by `rateLimitPacketUp`.
        try await upload.send(requestData)
    }
}
