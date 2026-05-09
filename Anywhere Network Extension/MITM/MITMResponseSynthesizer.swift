//
//  MITMResponseSynthesizer.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/9/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// Inner-leg responder used when a rule set's action synthesizes the
/// reply itself (``MITMRewriteAction/redirect302``,
/// ``MITMRewriteAction/reject200``). Owns the post-handshake
/// ``TLSRecordConnection``: parses the client's request enough to build
/// a coherent response, writes the response, and reports completion.
///
/// HTTP/1.1: parses the request line for the target path, then writes
/// `HTTP/1.1 302 Found` (with `Location:`) or `HTTP/1.1 200 OK` (with
/// the configured body and Content-Type), terminating with
/// `Connection: close`.
///
/// HTTP/2: consumes the connection preface, handshakes initial SETTINGS,
/// decodes the first HEADERS frame to extract `:path` and the stream id,
/// then emits HEADERS (+ optional DATA) carrying the synthesized
/// response with END_STREAM, followed by GOAWAY.
///
/// One-shot: after the response is written, ``onComplete`` is called and
/// no further bytes are processed. ``MITMSession`` tears the surrounding
/// session down in response.
final class MITMResponseSynthesizer {

    enum HTTPVersion {
        case http11
        case http2
    }

    private let record: TLSRecordConnection
    private let httpVersion: HTTPVersion
    private let target: MITMRewriteTarget
    private let queue: DispatchQueue
    private let onComplete: (Error?) -> Void

    private var rxBuffer = Data()
    private var responded = false
    private var torn = false

    // HTTP/2 state.
    private var prefaceConsumed = false
    private let hpackDecoder = HPACKDecoder()
    private var sentInitialSettings = false

    init(
        record: TLSRecordConnection,
        httpVersion: HTTPVersion,
        target: MITMRewriteTarget,
        queue: DispatchQueue,
        onComplete: @escaping (Error?) -> Void
    ) {
        self.record = record
        self.httpVersion = httpVersion
        self.target = target
        self.queue = queue
        self.onComplete = onComplete
    }

    func start() {
        if httpVersion == .http2, !sentInitialSettings {
            sentInitialSettings = true
            // Empty SETTINGS frame: keep all defaults. The peer will ACK
            // it; we ACK theirs in ``handleH2Frame``.
            record.send(data: encodeH2Frame(typeCode: 0x4, flags: 0, streamID: 0, payload: Data()))
        }
        receiveLoop()
    }

    func cancel() {
        guard !torn else { return }
        torn = true
    }

    // MARK: - Receive Loop

    private func receiveLoop() {
        record.receive { [weak self] data, error in
            guard let self else { return }
            self.queue.async {
                guard !self.torn else { return }
                if let error {
                    self.finish(error: error)
                    return
                }
                guard let data, !data.isEmpty else {
                    // Client closed before we had what we needed.
                    self.finish(error: nil)
                    return
                }
                self.rxBuffer.append(data)
                self.process()
                if !self.responded, !self.torn {
                    self.receiveLoop()
                }
            }
        }
    }

    private func process() {
        switch httpVersion {
        case .http11: processHTTP11()
        case .http2:  processHTTP2()
        }
    }

    private func finish(error: Error?) {
        guard !torn else { return }
        torn = true
        onComplete(error)
    }

    // MARK: - HTTP/1.1

    private func processHTTP11() {
        guard !responded else { return }
        guard let crlf = rxBuffer.range(of: Data([0x0D, 0x0A])) else {
            return
        }
        let lineData = rxBuffer.subdata(in: rxBuffer.startIndex..<crlf.lowerBound)
        let path: String
        if let str = String(data: lineData, encoding: .ascii) {
            // Request line: "METHOD SP request-target SP HTTP/1.x"
            let parts = str.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            path = parts.count >= 2 ? String(parts[1]) : "/"
        } else {
            path = "/"
        }
        sendResponseHTTP11(path: path)
    }

    private func sendResponseHTTP11(path: String) {
        let response: Data
        switch target.action {
        case .transparent:
            // Synthesizer should never run in transparent mode.
            finish(error: nil)
            return
        case .redirect302:
            response = build302HTTP11(path: path)
        case .reject200:
            response = build200HTTP11()
        }
        responded = true
        record.send(data: response) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.finish(error: error)
            }
        }
    }

    private func build302HTTP11(path: String) -> Data {
        let location = locationURL(path: path)
        var s = "HTTP/1.1 302 Found\r\n"
        s += "Location: \(location)\r\n"
        s += "Content-Length: 0\r\n"
        s += "Connection: close\r\n"
        s += "\r\n"
        return Data(s.utf8)
    }

    private func build200HTTP11() -> Data {
        let body = bodyBytes()
        let contentType = effectiveContentType()
        var s = "HTTP/1.1 200 OK\r\n"
        s += "Content-Type: \(contentType)\r\n"
        s += "Content-Length: \(body.count)\r\n"
        s += "Connection: close\r\n"
        s += "\r\n"
        var out = Data(s.utf8)
        out.append(body)
        return out
    }

    // MARK: - HTTP/2

    private func processHTTP2() {
        guard !responded else { return }
        if !prefaceConsumed {
            // RFC 9113 §3.4: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24 bytes.
            guard rxBuffer.count >= 24 else { return }
            rxBuffer.removeFirst(24)
            prefaceConsumed = true
        }
        while !responded, let frame = parseH2Frame() {
            handleH2Frame(frame)
        }
    }

    private struct H2Frame {
        var typeCode: UInt8
        var flags: UInt8
        var streamID: UInt32
        var payload: Data
    }

    private func parseH2Frame() -> H2Frame? {
        guard rxBuffer.count >= 9 else { return nil }
        let s = rxBuffer.startIndex
        let length = (Int(rxBuffer[s]) << 16)
            | (Int(rxBuffer[s + 1]) << 8)
            | Int(rxBuffer[s + 2])
        let total = 9 + length
        guard rxBuffer.count >= total else { return nil }
        let typeCode = rxBuffer[s + 3]
        let flags = rxBuffer[s + 4]
        let streamID = (UInt32(rxBuffer[s + 5]) << 24
                      | UInt32(rxBuffer[s + 6]) << 16
                      | UInt32(rxBuffer[s + 7]) << 8
                      | UInt32(rxBuffer[s + 8])) & 0x7FFFFFFF
        let payload = rxBuffer.subdata(in: (s + 9)..<(s + total))
        rxBuffer.removeFirst(total)
        return H2Frame(typeCode: typeCode, flags: flags, streamID: streamID, payload: payload)
    }

    private func handleH2Frame(_ frame: H2Frame) {
        switch frame.typeCode {
        case 0x4: // SETTINGS
            // ACK the client's SETTINGS once. Our own ACK frame is
            // ignored on the way back since ``responded`` short-circuits
            // further processing.
            if frame.flags & 0x1 == 0 {
                record.send(data: encodeH2Frame(typeCode: 0x4, flags: 0x1, streamID: 0, payload: Data()))
            }
        case 0x1: // HEADERS
            handleH2Headers(frame)
        default:
            // Ignore everything else (PRIORITY, WINDOW_UPDATE, PING,
            // RST_STREAM, etc.) — none of them can carry the request
            // we need to parse.
            break
        }
    }

    private func handleH2Headers(_ frame: H2Frame) {
        var payload = frame.payload
        // PADDED: leading pad-length byte + trailing padding.
        if frame.flags & 0x8 != 0 {
            guard !payload.isEmpty else { return }
            let padLen = Int(payload[payload.startIndex])
            guard payload.count >= 1 + padLen else { return }
            payload = payload.subdata(in: (payload.startIndex + 1)..<(payload.endIndex - padLen))
        }
        // PRIORITY: 5-byte priority block.
        if frame.flags & 0x20 != 0 {
            guard payload.count >= 5 else { return }
            payload = payload.subdata(in: (payload.startIndex + 5)..<payload.endIndex)
        }
        // CONTINUATION is not handled — origin clients don't fragment
        // a tiny request HEADERS block in practice. If END_HEADERS is
        // not set, we still try to decode the prefix; HPACK will simply
        // return what it can.
        guard let headers = hpackDecoder.decodeHeaders(from: payload) else {
            // Decoder desynced; nothing safe to do. Tear down.
            finish(error: nil)
            return
        }
        var path = "/"
        for (n, v) in headers where n == ":path" {
            path = v
            break
        }
        sendResponseH2(streamID: frame.streamID, path: path)
    }

    private func sendResponseH2(streamID: UInt32, path: String) {
        var responseHeaders: [(name: String, value: String)] = []
        var bodyData = Data()
        switch target.action {
        case .transparent:
            finish(error: nil)
            return
        case .redirect302:
            let location = locationURL(path: path)
            responseHeaders.append((":status", "302"))
            responseHeaders.append(("location", location))
            responseHeaders.append(("content-length", "0"))
        case .reject200:
            bodyData = bodyBytes()
            responseHeaders.append((":status", "200"))
            responseHeaders.append(("content-type", effectiveContentType()))
            responseHeaders.append(("content-length", "\(bodyData.count)"))
        }
        let block = HPACKEncoder.encodeHeaderBlock(responseHeaders)
        var output = Data()
        let endStreamOnHeaders = bodyData.isEmpty
        var headersFlags: UInt8 = 0x4 // END_HEADERS
        if endStreamOnHeaders { headersFlags |= 0x1 } // END_STREAM
        output.append(encodeH2Frame(typeCode: 0x1, flags: headersFlags, streamID: streamID, payload: block))
        if !bodyData.isEmpty {
            output.append(encodeH2Frame(typeCode: 0x0, flags: 0x1, streamID: streamID, payload: bodyData))
        }
        // GOAWAY(last_stream_id=streamID, error=NO_ERROR), so the client
        // knows the connection won't accept new streams.
        var goaway = Data(capacity: 8)
        let s = streamID & 0x7FFFFFFF
        goaway.append(UInt8((s >> 24) & 0xFF))
        goaway.append(UInt8((s >> 16) & 0xFF))
        goaway.append(UInt8((s >> 8) & 0xFF))
        goaway.append(UInt8(s & 0xFF))
        goaway.append(0); goaway.append(0); goaway.append(0); goaway.append(0)
        output.append(encodeH2Frame(typeCode: 0x7, flags: 0, streamID: 0, payload: goaway))

        responded = true
        record.send(data: output) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.finish(error: error)
            }
        }
    }

    private func encodeH2Frame(typeCode: UInt8, flags: UInt8, streamID: UInt32, payload: Data) -> Data {
        var out = Data(capacity: 9 + payload.count)
        let len = payload.count
        out.append(UInt8((len >> 16) & 0xFF))
        out.append(UInt8((len >> 8) & 0xFF))
        out.append(UInt8(len & 0xFF))
        out.append(typeCode)
        out.append(flags)
        let sid = streamID & 0x7FFFFFFF
        out.append(UInt8((sid >> 24) & 0xFF))
        out.append(UInt8((sid >> 16) & 0xFF))
        out.append(UInt8((sid >> 8) & 0xFF))
        out.append(UInt8(sid & 0xFF))
        out.append(payload)
        return out
    }

    // MARK: - Shared Helpers

    private func locationURL(path: String) -> String {
        let host = target.host
        let authority: String
        if let port = target.port, port != 443 {
            authority = "\(host):\(port)"
        } else {
            authority = host
        }
        return "https://\(authority)\(path)"
    }

    private func bodyBytes() -> Data {
        let body = target.rejectBody ?? MITMRejectBody()
        switch body.kind {
        case .text:
            let text = body.contents.isEmpty ? MITMRejectBody.Kind.text.defaultContents : body.contents
            return Data(text.utf8)
        case .gif:
            return MITMResponseSynthesizer.tinyGIF
        case .data:
            let source = body.contents.isEmpty ? MITMRejectBody.Kind.data.defaultContents : body.contents
            return Data(base64Encoded: source) ?? Data()
        }
    }

    private func effectiveContentType() -> String {
        let body = target.rejectBody
        if let override = body?.contentType, !override.isEmpty {
            return override
        }
        switch body?.kind ?? .text {
        case .text: return "text/plain; charset=utf-8"
        case .gif:  return "image/gif"
        case .data: return "application/octet-stream"
        }
    }

    /// 43-byte 1×1 transparent GIF89a — the canonical "tracking pixel"
    /// payload used to satisfy image requests with no visible content.
    private static let tinyGIF: Data = Data([
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02,
        0x4C, 0x01, 0x00, 0x3B
    ])
}
