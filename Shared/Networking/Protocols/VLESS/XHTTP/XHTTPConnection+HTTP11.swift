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
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Failed to encode stream-one request"))
        }

        do {
            try await download.send(requestData)
        } catch {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: error.localizedDescription))
        }
        try await receiveResponseHeaders()
    }

    // MARK: packet-up Setup

    func performPacketUpSetup() async throws {
        try await openDownloadWithConcurrentUpload()
        startUploadResponseDrain()
    }

    @discardableResult
    private func openDownloadWithConcurrentUpload() async throws -> any ByteTransport {
        guard let factory = uploadConnectionFactory else {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "No upload connection factory"))
        }
        let request = buildDownloadGETRequest()

        guard let requestData = request.data(using: .utf8) else {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Failed to encode GET request"))
        }

        async let pendingUpload = factory()
        do {
            do {
                try await download.send(requestData)
            } catch {
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: error.localizedDescription))
            }
            try await receiveResponseHeaders()
        } catch {
            (try? await pendingUpload)?.cancel()
            throw error
        }

        let upload: any ByteTransport
        do {
            upload = try await pendingUpload
        } catch {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Upload connection failed: \(error.localizedDescription)"))
        }
        let adopted = state.withLock { state -> Bool in
            guard state.phase != .cancelled else { return false }
            state.uploadTransport = upload
            return true
        }
        guard adopted else {
            upload.cancel()
            throw AnywhereError.transport(.terminated)
        }
        return upload
    }

    // MARK: Upload Response Drain

    func startUploadResponseDrain() {
        guard let upload = state.withLock({ $0.uploadTransport }) else { return }
        let task = Task { [weak self] in
            while true {
                guard let self, self.state.withLock({ $0.phase != .cancelled }) else { return }
                let chunk: TransportChunk
                do {
                    chunk = try await upload.receive()
                } catch {
                    return
                }
                if case .end = chunk { return }
            }
        }
        let stored: Bool = state.withLock { state in
            guard state.uploadTransport != nil else { return false }
            state.uploadDrainTask = task
            return true
        }
        if !stored { task.cancel() }
    }

    // MARK: stream-up Setup

    func performStreamUpSetup() async throws {
        let closures = try await openDownloadWithConcurrentUpload()

        let postRequest = buildStreamUpPOSTRequest()
        guard let postData = postRequest.data(using: .utf8) else {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Failed to encode stream-up POST request"))
        }
        do {
            try await closures.send(postData)
        } catch {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Stream-up POST send failed: \(error.localizedDescription)"))
        }
    }

    // MARK: Detached leg Setup

    func performDownloadOnlyHTTP11Setup() async throws {
        let request = buildDownloadGETRequest()
        guard let requestData = request.data(using: .utf8) else {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Failed to encode GET request"))
        }
        do {
            try await download.send(requestData)
        } catch {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: error.localizedDescription))
        }
        try await receiveResponseHeaders()
    }

    func performUploadOnlyHTTP11Setup() async throws {
        let upload = NonCancelingByteTransport(download)
        state.withLock { $0.uploadTransport = upload }

        if mode == .streamUp {
            let postRequest = buildStreamUpPOSTRequest()
            guard let postData = postRequest.data(using: .utf8) else {
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Failed to encode stream-up POST request"))
            }
            do {
                try await download.send(postData)
            } catch {
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Stream-up POST send failed: \(error.localizedDescription)"))
            }
        } else {
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
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: error.localizedDescription))
            }
            guard case .bytes(let data) = chunk, !data.isEmpty else {
                throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Empty response from server"))
            }

            let headerData: Data? = try state.withLock { state in
                state.headerBuffer.append(data)
                guard let range = state.headerBuffer.range(of: headerEnd) else {
                    if state.headerBuffer.count > Self.maxResponseHeaderSize {
                        throw AnywhereError.proxy(.xhttp, .protocolViolation(detail: "response headers too large"))
                    }
                    return nil
                }
                let headerData = Data(state.headerBuffer[state.headerBuffer.startIndex..<range.lowerBound])
                let leftover = Data(state.headerBuffer[range.upperBound...])
                state.headerBuffer.removeAll()
                if !leftover.isEmpty { state.chunkedDecoder.feed(leftover) }
                return headerData
            }
            guard let headerData else { continue }

            guard let headerString = String(data: headerData, encoding: .utf8) else {
                throw AnywhereError.proxy(.xhttp, .protocolViolation(detail: "Cannot decode response headers"))
            }
            let firstLine = headerString.split(separator: "\r\n", maxSplits: 1).first ?? ""
            guard firstLine.contains("200") else {
                throw AnywhereError.proxy(.xhttp, .protocolViolation(detail: "Expected HTTP 200, got: \(firstLine)"))
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
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Upload connection not established"))
        }
        try await upload.send(ChunkedTransferEncoder.encode(data))
    }

    func sendPacketUpHTTP11(data: Data) async throws {
        guard let upload = state.withLock({ $0.uploadTransport }) else {
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Upload connection not established"))
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

    private func sendSinglePost(data: Data, seq: Int64, upload: any ByteTransport) async throws {
        let method = configuration.uplinkHTTPMethod
        var path = configuration.normalizedPath
        var headerBlock = ""

        applySessionId(to: &headerBlock, path: &path)
        applySeq(to: &headerBlock, path: &path, seq: seq)

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
            throw AnywhereError.proxy(.xhttp, .handshakeFailed(detail: "Failed to encode POST request"))
        }
        requestData.append(bodyData)

        try await upload.send(requestData)
    }
}
