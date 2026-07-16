//
//  XHTTPConnection+H3.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation
import Synchronization

extension XHTTPConnection {

    // MARK: Setup

    func performH3Setup() async throws {
        guard let multiplexer = h3Multiplexer else {
            throw XHTTPError.setupFailed("H3 setup without a multiplexer")
        }

        switch role {
        case .downloadOnly:
            // Download leg of a detached multiplexer; the upload POST lives on a separate QUIC multiplexer.
            try await setupH3Download(multiplexer: multiplexer)

        case .uploadOnly:
            // packet-up opens streams per batch, so only stream-up opens anything at setup.
            if mode == .streamUp {
                try await openH3UploadStream(multiplexer: multiplexer)
            }

        case .combined:
            switch mode {
            case .streamOne:
                // Can't wait for the response: the server only replies after seeing upload body.
                let stream = XHTTPH3RequestStream(multiplexer: multiplexer)
                state.withLock { $0.h3Download = stream }
                let headers = h3RequestHeaderBlock(method: "POST", includeMeta: false)
                do {
                    try await stream.sendRequest(headerBlock: headers, endStream: false)
                } catch {
                    throw XHTTPError.setupFailed("H3 stream-one request failed: \(error.localizedDescription)")
                }

            case .streamUp:
                try await setupH3Download(multiplexer: multiplexer)
                try await openH3UploadStream(multiplexer: multiplexer)

            default:
                // packet-up (and .auto, already resolved to packet-up for TLS upstream).
                try await setupH3Download(multiplexer: multiplexer)
            }
        }
    }

    /// Opens the persistent stream-up upload POST; no seq or content length since the body streams indefinitely.
    private func openH3UploadStream(multiplexer: HTTP3Multiplexer) async throws {
        let upload = XHTTPH3RequestStream(multiplexer: multiplexer)
        state.withLock { $0.h3Upload = upload }
        xmuxLease?.noteRequest()
        let headers = h3UploadHeaderBlock(seq: nil, contentLength: nil)
        do {
            try await upload.sendRequest(headerBlock: headers, endStream: false)
        } catch {
            throw XHTTPError.setupFailed("H3 upload stream open failed: \(error.localizedDescription)")
        }
    }

    /// Opens the download GET and returns on a 2xx response; waiting is safe
    /// because the GET has no request body (the stream-one POST would deadlock).
    private func setupH3Download(multiplexer: HTTP3Multiplexer) async throws {
        let stream = XHTTPH3RequestStream(multiplexer: multiplexer)
        state.withLock { $0.h3Download = stream }
        xmuxLease?.noteRequest()
        let headers = h3RequestHeaderBlock(method: "GET", includeMeta: true)

        // Send the GET (endStream), then wait for the response status. Splitting the write and the
        // response awaits is safe: a write failure throws before we await the status, and a response
        // that arrives first is recorded on the stream and surfaced by `awaitResponseStatus`.
        do {
            try await stream.sendRequest(headerBlock: headers, endStream: true)
        } catch {
            throw XHTTPError.setupFailed("H3 download request failed: \(error.localizedDescription)")
        }
        let status: Int
        do {
            status = try await stream.awaitResponseStatus()
        } catch {
            throw XHTTPError.setupFailed("H3 download failed: \(error.localizedDescription)")
        }
        guard (200...299).contains(status) else {
            throw XHTTPError.setupFailed("H3 download rejected: status \(status)")
        }
    }

    // MARK: Send (packet-up)

    /// Sends one packet-up batch as its own POST stream; the response only acks receipt and is
    /// discarded. Called under `packetUpMutex`.
    func sendH3PacketUp(data: Data) async throws {
        guard let multiplexer = h3Multiplexer, !state.withLock({ $0.h3Closed }) else {
            throw XHTTPError.connectionClosed
        }
        let seq = state.withLock { state -> Int64 in let s = state.nextSeq; state.nextSeq += 1; return s }
        xmuxLease?.noteRequest()

        // Header/cookie placement carries the payload in the header block; the body stays empty.
        let dataFields = uplinkDataFields(for: data)
        let bodyInHeaders = !dataFields.isEmpty
        let bodyLength = bodyInHeaders ? 0 : data.count
        let stream = XHTTPH3RequestStream(multiplexer: multiplexer)
        let headers = h3UploadHeaderBlock(seq: seq, contentLength: bodyLength, uplinkData: dataFields)

        if !bodyInHeaders, !data.isEmpty {
            do {
                try await stream.sendRequest(headerBlock: headers, endStream: false)
                try await stream.sendBody(data, fin: true)
            } catch {
                stream.close()
                throw error
            }
            stream.drainResponse()
        } else {
            do {
                try await stream.sendRequest(headerBlock: headers, endStream: true)
            } catch {
                stream.close()
                throw error
            }
            stream.drainResponse()
        }
    }

    // MARK: Receive

    func receiveH3Data() async throws -> Data? {
        guard let stream = state.withLock({ $0.h3Download }) else {
            return nil
        }
        return try await stream.receive()
    }

    // MARK: Header construction (QPACK)

    /// Builds the QPACK header block for the download GET or the stream-one POST.
    func h3RequestHeaderBlock(method: String, includeMeta: Bool) -> Data {
        var path = configuration.normalizedPath
        if includeMeta, !sessionId.isEmpty, configuration.sessionPlacement == .path {
            path = appendToPath(path, sessionId)
        }
        var queryParts: [String] = []
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty { queryParts.append(configQuery) }
        if includeMeta, !sessionId.isEmpty, configuration.sessionPlacement == .query {
            queryParts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
        }
        if configuration.xPaddingObfsMode, configuration.xPaddingPlacement == .query {
            queryParts.append("\(configuration.xPaddingKey)=\(configuration.generatePadding())")
        }
        if !queryParts.isEmpty { path += "?" + queryParts.joined(separator: "&") }

        var headers = h3CommonHeaders()
        if method != "GET", !configuration.noGRPCHeader {
            headers.append((name: "content-type", value: "application/grpc"))
        }
        if includeMeta { h3AppendSessionMeta(to: &headers) }

        return QPACKEncoder.encodeRequestHeaders(
            method: method, authority: configuration.host, path: path, extraHeaders: headers
        )
    }

    /// QPACK header block for an upload POST; `seq` is nil for stream-up, set per batch for packet-up.
    /// `uplinkData` carries a packet-up payload in headers/cookies under non-body placement.
    func h3UploadHeaderBlock(seq: Int64?, contentLength: Int?, uplinkData: [UplinkDataField] = []) -> Data {
        var path = configuration.normalizedPath
        if !sessionId.isEmpty, configuration.sessionPlacement == .path {
            path = appendToPath(path, sessionId)
        }
        if let seq, configuration.seqPlacement == .path {
            path = appendToPath(path, "\(seq)")
        }
        var queryParts: [String] = []
        let configQuery = configuration.normalizedQuery
        if !configQuery.isEmpty { queryParts.append(configQuery) }
        if !sessionId.isEmpty, configuration.sessionPlacement == .query {
            queryParts.append("\(configuration.normalizedSessionKey)=\(sessionId)")
        }
        if let seq, configuration.seqPlacement == .query {
            queryParts.append("\(configuration.normalizedSeqKey)=\(seq)")
        }
        if configuration.xPaddingObfsMode, configuration.xPaddingPlacement == .query {
            queryParts.append("\(configuration.xPaddingKey)=\(configuration.generatePadding())")
        }
        if !queryParts.isEmpty { path += "?" + queryParts.joined(separator: "&") }

        var headers = h3CommonHeaders()
        // Only the streaming upload (seq == nil) declares a content type.
        if seq == nil, !configuration.noGRPCHeader {
            headers.append((name: "content-type", value: "application/grpc"))
        }
        if let contentLength {
            headers.append((name: "content-length", value: "\(contentLength)"))
        }
        h3AppendSessionMeta(to: &headers)
        if let seq { h3AppendSeqMeta(to: &headers, seq: seq) }

        for field in uplinkData {
            switch field {
            case .header(let name, let value): headers.append((name: name.lowercased(), value: value))
            case .cookie(let pair):            headers.append((name: "cookie", value: pair))
            }
        }

        return QPACKEncoder.encodeRequestHeaders(
            method: configuration.uplinkHTTPMethod, authority: configuration.host, path: path, extraHeaders: headers
        )
    }

    /// Headers shared by every request: user-agent, X-Padding, and custom headers.
    private func h3CommonHeaders() -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = []

        let userAgent = configuration.headers["User-Agent"] ?? ProxyUserAgent.default
        headers.append((name: "user-agent", value: userAgent))

        let padding = configuration.generatePadding()
        let paddingPath = configuration.normalizedPath
        if !configuration.xPaddingObfsMode {
            headers.append((name: "referer",
                            value: "https://\(configuration.host)\(paddingPath)?x_padding=\(padding)"))
        } else {
            switch configuration.xPaddingPlacement {
            case .header:
                headers.append((name: configuration.xPaddingHeader.lowercased(), value: padding))
            case .queryInHeader:
                headers.append((name: configuration.xPaddingHeader.lowercased(),
                                value: "https://\(configuration.host)\(paddingPath)?\(configuration.xPaddingKey)=\(padding)"))
            case .cookie:
                headers.append((name: "cookie", value: "\(configuration.xPaddingKey)=\(padding)"))
            default:
                break // .query is appended to the path
            }
        }

        // Skip connection-specific headers (illegal in HTTP/2+) and ones already emitted.
        let forbidden: Set<String> = [
            "host", "connection", "proxy-connection", "transfer-encoding",
            "upgrade", "keep-alive", "content-length", "user-agent"
        ]
        for (key, value) in configuration.headers {
            let lowercasedKey = key.lowercased()
            if forbidden.contains(lowercasedKey) { continue }
            headers.append((name: lowercasedKey, value: value))
        }
        return headers
    }

    private func h3AppendSessionMeta(to headers: inout [(name: String, value: String)]) {
        guard !sessionId.isEmpty else { return }
        switch configuration.sessionPlacement {
        case .header:
            headers.append((name: configuration.normalizedSessionKey.lowercased(), value: sessionId))
        case .cookie:
            headers.append((name: "cookie", value: "\(configuration.normalizedSessionKey)=\(sessionId)"))
        default:
            break // path / query handled in the request path
        }
    }

    private func h3AppendSeqMeta(to headers: inout [(name: String, value: String)], seq: Int64) {
        switch configuration.seqPlacement {
        case .header:
            headers.append((name: configuration.normalizedSeqKey.lowercased(), value: "\(seq)"))
        case .cookie:
            headers.append((name: "cookie", value: "\(configuration.normalizedSeqKey)=\(seq)"))
        default:
            break // path / query handled in the request path
        }
    }
}
