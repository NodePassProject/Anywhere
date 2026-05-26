//
//  XHTTPConnection+H3.swift
//  Anywhere
//
//  Created by NodePassProject on 5/26/26.
//

import Foundation

// MARK: - HTTP/3 Transport (XHTTP over QUIC)

/// XHTTP-over-HTTP/3 maps each split-HTTP "request" onto a bidirectional QUIC
/// stream of a shared ``HTTP3Session``:
///
/// - **stream-one**: one bidi stream carrying a POST whose request body is the
///   upload and whose response body is the download.
/// - **stream-up**: a body-less GET stream for the download plus a persistent
///   POST stream for the upload.
/// - **packet-up**: a body-less GET stream for the download plus one short POST
///   stream per upload batch (`/{session}/{seq}`).
///
/// Unlike H1/H2, QUIC provides framing, flow control, and multiplexing
/// natively, so there is no chunked encoding or manual frame parsing here —
/// request and response bodies are plain HTTP/3 DATA frames handled by
/// ``HTTP3RequestStream``. Request paths, session/seq metadata, and X-Padding
/// are built the same way on every HTTP version, so a server sees identical
/// split-HTTP requests whichever transport negotiated.
extension XHTTPConnection {

    // MARK: Setup

    func performH3Setup(completion: @escaping (Error?) -> Void) {
        guard let session = h3Session else {
            completion(XHTTPError.setupFailed("H3 setup without a session"))
            return
        }

        switch mode {
        case .streamOne:
            // Single full-duplex POST: request body is the upload, response body
            // the download. Setup can't wait for the response — the server only
            // replies once it sees upload body, which the caller sends afterwards.
            let stream = HTTP3RequestStream(session: session)
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
            setupH3Download(session: session) { [weak self] error in
                if let error { completion(error); return }
                guard let self else { completion(XHTTPError.connectionClosed); return }
                // Persistent upload POST stream (no seq; body streams over its lifetime).
                let upload = HTTP3RequestStream(session: session)
                self.lock.lock(); self.h3Upload = upload; self.lock.unlock()
                let headers = self.h3UploadHeaderBlock(seq: nil, contentLength: nil)
                upload.sendRequest(headerBlock: headers, endStream: false) { upErr in
                    if let upErr {
                        completion(XHTTPError.setupFailed("H3 upload stream open failed: \(upErr.localizedDescription)"))
                    } else {
                        completion(nil)
                    }
                }
            }

        default:
            // packet-up (and .auto, already resolved to packet-up for TLS upstream).
            setupH3Download(session: session, completion: completion)
        }
    }

    /// Opens the download GET stream and completes once the server returns a
    /// 2xx status. The GET carries no request body, so waiting for the response
    /// can't deadlock (unlike the stream-one POST).
    private func setupH3Download(session: HTTP3Session, completion: @escaping (Error?) -> Void) {
        let stream = HTTP3RequestStream(session: session)
        lock.lock(); h3Download = stream; lock.unlock()
        let headers = h3RequestHeaderBlock(method: "GET", includeMeta: true)

        // `settled` is only touched on the session queue (both callbacks run
        // there), so the shared capture is race-free.
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

    /// Sends one packet-up batch as its own POST stream (HEADERS + DATA + FIN).
    /// Each batch is an independent request, so it gets a fresh stream; the
    /// response only acks receipt and is irrelevant to the data plane, so it is
    /// drained and released.
    func sendH3PacketUp(data: Data, completion: @escaping (Error?) -> Void) {
        guard let session = h3Session, !h3Closed else {
            completion(XHTTPError.connectionClosed)
            return
        }
        lock.lock()
        let seq = nextSeq
        nextSeq += 1
        lock.unlock()

        let stream = HTTP3RequestStream(session: session)
        let headers = h3UploadHeaderBlock(seq: seq, contentLength: data.count)
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
                // Request (HEADERS + DATA + FIN) delivered; discard the response
                // and let the stream close cleanly on EOF.
                stream.drainResponse()
                completion(nil)
            }
        }
    }

    // MARK: Receive

    func receiveH3Data(completion: @escaping (Data?, Error?) -> Void) {
        guard let stream = h3Download else {
            completion(nil, nil) // No download stream → EOF.
            return
        }
        stream.receive(completion: completion)
    }

    // MARK: Header construction (QPACK)

    /// Builds the QPACK header block for the download GET (stream-up / packet-up)
    /// or the stream-one POST.
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

    /// Builds the QPACK header block for an upload POST. `seq` is nil for the
    /// stream-up persistent upload and set per batch for packet-up.
    func h3UploadHeaderBlock(seq: Int64?, contentLength: Int?) -> Data {
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
        // Only the streaming upload (seq == nil) declares a media type; discrete
        // per-packet POSTs omit it.
        if seq == nil, !configuration.noGRPCHeader {
            headers.append((name: "content-type", value: "application/grpc"))
        }
        if let contentLength {
            headers.append((name: "content-length", value: "\(contentLength)"))
        }
        h3AppendSessionMeta(to: &headers)
        if let seq { h3AppendSeqMeta(to: &headers, seq: seq) }

        return QPACKEncoder.encodeRequestHeaders(
            method: configuration.uplinkHTTPMethod, authority: configuration.host, path: path, extraHeaders: headers
        )
    }

    /// Common headers shared by every XHTTP-over-h3 request: user-agent,
    /// X-Padding (Referer or obfs placement), and custom headers.
    private func h3CommonHeaders() -> [(name: String, value: String)] {
        var headers: [(name: String, value: String)] = []

        let ua = configuration.headers["User-Agent"] ?? ProxyUserAgent.default
        headers.append((name: "user-agent", value: ua))

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

        // Skip connection-specific headers (illegal as literal fields in HTTP/2+)
        // and ones already emitted above (user-agent, content-length).
        let forbidden: Set<String> = [
            "host", "connection", "proxy-connection", "transfer-encoding",
            "upgrade", "keep-alive", "content-length", "user-agent"
        ]
        for (key, value) in configuration.headers {
            let lk = key.lowercased()
            if forbidden.contains(lk) { continue }
            headers.append((name: lk, value: value))
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
