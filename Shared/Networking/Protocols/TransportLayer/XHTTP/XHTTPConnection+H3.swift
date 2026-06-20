//
//  XHTTPConnection+H3.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation

// MARK: - HTTP/3 Transport (XHTTP over QUIC)

/// Maps each split-HTTP request onto bidirectional QUIC streams of a shared multiplexer:
/// stream-one uses a single full-duplex POST; stream-up a GET download plus a
/// persistent POST upload; packet-up a GET plus one short POST per upload batch.
extension XHTTPConnection {

    // MARK: Setup

    func performH3Setup(completion: @escaping (Error?) -> Void) {
        guard let multiplexer = h3Multiplexer else {
            completion(XHTTPError.setupFailed("H3 setup without a multiplexer"))
            return
        }

        switch role {
        case .downloadOnly:
            // Download leg of a detached multiplexer; the upload POST lives on a separate QUIC multiplexer.
            setupH3Download(multiplexer: multiplexer, completion: completion)

        case .uploadOnly:
            // packet-up opens streams per batch, so only stream-up opens anything at setup.
            if mode == .streamUp {
                openH3UploadStream(multiplexer: multiplexer, completion: completion)
            } else {
                completion(nil)
            }

        case .combined:
            switch mode {
            case .streamOne:
                // Can't wait for the response: the server only replies after seeing upload body.
                let stream = XHTTPH3RequestStream(multiplexer: multiplexer)
                lock.lock(); h3Download = stream; lock.unlock()
                let headers = h3RequestHeaderBlock(method: "POST", includeMeta: false)
                stream.sendRequest(headerBlock: headers, endStream: false) { error in
                    if let error {
                        completion(XHTTPError.setupFailed("H3 stream-one request failed: \(error.localizedDescription)"))
                    } else {
                        completion(nil)
                    }
                }

            case .streamUp:
                setupH3Download(multiplexer: multiplexer) { [weak self] error in
                    if let error { completion(error); return }
                    guard let self else { completion(XHTTPError.connectionClosed); return }
                    self.openH3UploadStream(multiplexer: multiplexer, completion: completion)
                }

            default:
                // packet-up (and .auto, already resolved to packet-up for TLS upstream).
                setupH3Download(multiplexer: multiplexer, completion: completion)
            }
        }
    }

    /// Opens the persistent stream-up upload POST; no seq or content length since the body streams indefinitely.
    private func openH3UploadStream(multiplexer: HTTP3Multiplexer, completion: @escaping (Error?) -> Void) {
        let upload = XHTTPH3RequestStream(multiplexer: multiplexer)
        lock.lock(); h3Upload = upload; lock.unlock()
        xmuxLease?.noteRequest()
        let headers = h3UploadHeaderBlock(seq: nil, contentLength: nil)
        upload.sendRequest(headerBlock: headers, endStream: false) { upErr in
            if let upErr {
                completion(XHTTPError.setupFailed("H3 upload stream open failed: \(upErr.localizedDescription)"))
            } else {
                completion(nil)
            }
        }
    }

    /// Opens the download GET and completes on a 2xx response; waiting is safe
    /// because the GET has no request body (the stream-one POST would deadlock).
    private func setupH3Download(multiplexer: HTTP3Multiplexer, completion: @escaping (Error?) -> Void) {
        let stream = XHTTPH3RequestStream(multiplexer: multiplexer)
        lock.lock(); h3Download = stream; lock.unlock()
        xmuxLease?.noteRequest()
        let headers = h3RequestHeaderBlock(method: "GET", includeMeta: true)

        // Both callbacks run on the multiplexer queue, so `settled` is race-free.
        var settled = false
        stream.sendRequest(
            headerBlock: headers,
            endStream: true,
            onResponse: { result in
                guard !settled else { return }
                settled = true
                switch result {
                case .success(let status):
                    if (200...299).contains(status) {
                        completion(nil)
                    } else {
                        completion(XHTTPError.setupFailed("H3 download rejected: status \(status)"))
                    }
                case .failure(let error):
                    completion(XHTTPError.setupFailed("H3 download failed: \(error.localizedDescription)"))
                }
            },
            completion: { error in
                // Only surface send-side failures here; success is reported via onResponse.
                if let error, !settled {
                    settled = true
                    completion(XHTTPError.setupFailed("H3 download request failed: \(error.localizedDescription)"))
                }
            }
        )
    }

    // MARK: Send (packet-up)

    /// Sends one packet-up batch as its own POST stream; the response only acks receipt and is discarded.
    func sendH3PacketUp(data: Data, completion: @escaping (Error?) -> Void) {
        guard let multiplexer = h3Multiplexer, !h3Closed else {
            completion(XHTTPError.connectionClosed)
            return
        }
        lock.lock()
        let seq = nextSeq
        nextSeq += 1
        lock.unlock()
        xmuxLease?.noteRequest()

        // Header/cookie placement carries the payload in the header block; the body stays empty.
        let dataFields = uplinkDataFields(for: data)
        let bodyInHeaders = !dataFields.isEmpty
        let bodyLength = bodyInHeaders ? 0 : data.count
        let stream = XHTTPH3RequestStream(multiplexer: multiplexer)
        let headers = h3UploadHeaderBlock(seq: seq, contentLength: bodyLength, uplinkData: dataFields)

        guard !bodyInHeaders, !data.isEmpty else {
            stream.sendRequest(headerBlock: headers, endStream: true) { error in
                if let error {
                    stream.close()
                    completion(error)
                    return
                }
                stream.drainResponse()
                completion(nil)
            }
            return
        }

        stream.sendRequest(headerBlock: headers, endStream: false) { error in
            if let error {
                stream.close()
                completion(error)
                return
            }
            stream.sendBody(data, fin: true) { sendErr in
                if let sendErr {
                    stream.close()
                    completion(sendErr)
                    return
                }
                stream.drainResponse()
                completion(nil)
            }
        }
    }

    // MARK: Receive

    func receiveH3Data(completion: @escaping (Data?, Error?) -> Void) {
        guard let stream = h3Download else {
            completion(nil, nil)
            return
        }
        stream.receive(completion: completion)
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
