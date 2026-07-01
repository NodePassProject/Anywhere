//
//  TunneledHTTP1Exchange.swift
//  Anywhere
//
//  Created by NodePassProject on 7/1/26.
//

import Foundation

final class TunneledHTTP1Exchange {

    // MARK: Active-exchange registry (keeps the exchange alive across async I/O)

    private static let registryLock = UnfairLock()
    private static var active: [ObjectIdentifier: TunneledHTTP1Exchange] = [:]

    // MARK: Inputs

    private let connection: ProxyConnection
    private let teardown: () -> Void
    private let request: URLRequest
    private let hostHeader: String
    private let maxBytes: Int
    private let resourceTimeout: TimeInterval
    private let queue: DispatchQueue
    private let completion: (Result<MITMScriptHTTPClient.Response, Error>) -> Void

    // MARK: State (touched only on `queue`)

    private var inbound = Data()
    private var headParsed = false
    private var status = 0
    private var headers: [(name: String, value: String)] = []
    private var body = Data()
    private var reservedBytes = 0
    private var bodyMode: BodyMode = .undetermined
    private var chunked = ChunkedDecoder()
    private var finished = false

    private var deadlineTimer: DispatchSourceTimer?
    private var idleTimer: DispatchSourceTimer?

    /// The response head cannot exceed this; guards against an unbounded header stream.
    private static let maxHeadBytes = 64 * 1024

    private enum BodyMode {
        case undetermined
        case contentLength(Int)
        case chunked
        case untilClose
    }

    init(
        connection: ProxyConnection,
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        queue: DispatchQueue,
        teardown: @escaping () -> Void,
        completion: @escaping (Result<MITMScriptHTTPClient.Response, Error>) -> Void
    ) {
        self.connection = connection
        self.teardown = teardown
        self.request = request
        self.hostHeader = hostHeader
        self.maxBytes = maxBytes
        self.resourceTimeout = resourceTimeout
        self.queue = queue
        self.completion = completion
    }

    // MARK: - Lifecycle

    func start() {
        queue.async { [self] in
            Self.registryLock.withLock { Self.active[ObjectIdentifier(self)] = self }
            armTimers()
            sendRequest()
        }
    }

    private func armTimers() {
        let timeout = resourceTimeout
        let deadline = DispatchSource.makeTimerSource(queue: queue)
        deadline.schedule(deadline: .now() + timeout)
        deadline.setEventHandler { [weak self] in
            self?.fail(TransportError.connectionFailed("request exceeded \(Int(timeout))s deadline"))
        }
        deadline.resume()
        deadlineTimer = deadline
        rearmIdleTimer()
    }

    /// Inactivity backstop; reset whenever inbound bytes arrive.
    private func rearmIdleTimer() {
        let interval = request.timeoutInterval
        guard interval > 0 else { return }
        idleTimer?.cancel()
        let idle = DispatchSource.makeTimerSource(queue: queue)
        idle.schedule(deadline: .now() + interval)
        idle.setEventHandler { [weak self] in
            self?.fail(TransportError.connectionFailed("request idle for \(Int(interval))s"))
        }
        idle.resume()
        idleTimer = idle
    }

    // MARK: - Request

    private func sendRequest() {
        guard let head = serializeRequest() else {
            fail(TransportError.connectionFailed("could not serialize request"))
            return
        }
        connection.send(data: head) { [weak self] error in
            self?.queue.async {
                guard let self, !self.finished else { return }
                if let error { self.fail(error); return }
                self.receiveMore()
            }
        }
    }

    private func serializeRequest() -> Data? {
        guard let url = request.url,
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        var target = comps.percentEncodedPath
        if target.isEmpty { target = "/" }
        if let query = comps.percentEncodedQuery, !query.isEmpty { target += "?" + query }

        let method = (request.httpMethod ?? "GET").uppercased()
        guard HTTPHeader.isValidName(method) else { return nil }

        var lines = "\(method) \(target) HTTP/1.1\r\n"

        // Headers we set ourselves are stripped from the user set to avoid duplicates / smuggling.
        let managed: Set<String> = ["connection", "accept-encoding", "content-length", "transfer-encoding", "host"]
        var hasHost = false
        let requestBody = request.httpBody
        if let userHeaders = request.allHTTPHeaderFields {
            for (name, value) in userHeaders {
                let lower = name.lowercased()
                guard HTTPHeader.isValidName(name), HTTPHeader.isValidValue(value) else { continue }
                if lower == "host" {
                    lines += "Host: \(value)\r\n"
                    hasHost = true
                } else if !managed.contains(lower) {
                    lines += "\(name): \(value)\r\n"
                }
            }
        }
        if !hasHost { lines += "Host: \(hostHeader)\r\n" }
        // Advertise only codings MITMBodyCodec can reverse; the response is decoded before return.
        lines += "Accept-Encoding: gzip, deflate, br\r\n"
        lines += "Connection: close\r\n"
        if let requestBody, !requestBody.isEmpty {
            lines += "Content-Length: \(requestBody.count)\r\n"
        } else if method == "POST" || method == "PUT" || method == "PATCH" {
            lines += "Content-Length: 0\r\n"
        }
        lines += "\r\n"

        var data = Data(lines.utf8)
        if let requestBody, !requestBody.isEmpty { data.append(requestBody) }
        return data
    }

    // MARK: - Receive

    private func receiveMore() {
        connection.receive { [weak self] data, error in
            self?.queue.async {
                guard let self, !self.finished else { return }
                if let error { self.fail(error); return }
                guard let data, !data.isEmpty else { self.handleEOF(); return }
                self.rearmIdleTimer()
                self.inbound.append(data)
                self.process()
            }
        }
    }

    private func process() {
        guard !finished else { return }
        if !headParsed {
            let ready = parseHeadIfReady()
            guard !finished else { return }
            if !ready {
                if inbound.count > Self.maxHeadBytes {
                    fail(TransportError.connectionFailed("response head exceeds \(Self.maxHeadBytes) bytes"))
                } else {
                    receiveMore()
                }
                return
            }
        }
        processBody()
    }

    /// Skips 1xx interim heads; on the final head, records status/headers and body framing.
    private func parseHeadIfReady() -> Bool {
        let terminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
        while true {
            guard let range = inbound.range(of: terminator) else { return false }
            guard let (code, hdrs) = Self.parseHead(inbound.subdata(in: inbound.startIndex..<range.lowerBound)) else {
                fail(TransportError.connectionFailed("malformed response head"))
                return false
            }
            inbound = inbound.subdata(in: range.upperBound..<inbound.endIndex)
            if (100..<200).contains(code) { continue }   // interim response: keep reading for the final head
            status = code
            headers = hdrs
            headParsed = true
            determineBodyMode()
            return true
        }
    }

    private func determineBodyMode() {
        if let te = header("Transfer-Encoding"), te.lowercased().contains("chunked") {
            bodyMode = .chunked
            return
        }
        if let clString = header("Content-Length"),
           let contentLength = Int(clString.trimmingCharacters(in: .whitespaces)), contentLength >= 0 {
            if contentLength > maxBytes {
                fail(MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes))
                return
            }
            bodyMode = .contentLength(contentLength)
            return
        }
        // No framing headers: the body runs until the server closes the connection.
        bodyMode = .untilClose
    }

    private func processBody() {
        guard !finished else { return }
        if responseHasNoBody { finishSuccess(); return }

        switch bodyMode {
        case .undetermined:
            finishSuccess()

        case .contentLength(let total):
            if total == 0 { finishSuccess(); return }
            if !inbound.isEmpty {
                let take = min(total - body.count, inbound.count)
                if take > 0 {
                    let slice = inbound.subdata(in: inbound.startIndex..<(inbound.startIndex + take))
                    inbound = inbound.subdata(in: (inbound.startIndex + take)..<inbound.endIndex)
                    if !appendBody(slice) { return }
                }
            }
            if body.count >= total { finishSuccess() } else { receiveMore() }

        case .chunked:
            var decoded = Data()
            switch chunked.feed(&inbound, into: &decoded) {
            case .needMore:
                if !appendBody(decoded) { return }
                receiveMore()
            case .done:
                if !appendBody(decoded) { return }
                finishSuccess()
            case .error(let message):
                fail(TransportError.connectionFailed("chunked decode failed: \(message)"))
            }

        case .untilClose:
            if !inbound.isEmpty {
                let slice = inbound
                inbound = Data()
                if !appendBody(slice) { return }
            }
            receiveMore()
        }
    }

    private func handleEOF() {
        guard !finished else { return }
        guard headParsed else {
            fail(TransportError.connectionFailed("connection closed before response head"))
            return
        }
        switch bodyMode {
        case .untilClose, .undetermined:
            finishSuccess()
        case .contentLength(let total):
            if body.count >= total { finishSuccess() }
            else { fail(TransportError.connectionFailed("connection closed; body truncated (\(body.count)/\(total))")) }
        case .chunked:
            fail(TransportError.connectionFailed("connection closed before final chunk"))
        }
    }

    // MARK: - Body accounting

    /// Returns false (and fails the exchange) when the per-response or global byte cap is hit.
    private func appendBody(_ data: Data) -> Bool {
        guard !data.isEmpty else { return true }
        if body.count + data.count > maxBytes {
            fail(MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes))
            return false
        }
        guard MITMScriptHTTPClient.reserveInFlight(data.count) else {
            fail(MITMScriptHTTPClient.ClientError.globalBudgetExceeded(MITMScriptHTTPClient.maxGlobalInFlightBytes))
            return false
        }
        reservedBytes += data.count
        body.append(data)
        return true
    }

    // MARK: - Completion

    private func finishSuccess() {
        var responseBody = body
        // Drop `Transfer-Encoding`: the body is fully buffered and de-chunked (and it's hop-by-hop anyway).
        var dropHeaders: Set<String> = ["transfer-encoding"]

        // Decode the origin's Content-Encoding so the script sees plaintext, dropping the stale
        // encoding/length headers. An unsupported/failed coding is left as-is for the script to handle.
        let plan = MITMBodyCodec.plan(for: header("Content-Encoding"))
        if plan.requiresDecompression,
           let decoded = MITMBodyCodec.decompress(body, plan: plan, host: request.url?.host ?? "") {
            if decoded.count > maxBytes {
                fail(MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes))
                return
            }
            responseBody = decoded
            dropHeaders.insert("content-encoding")
            dropHeaders.insert("content-length")
        }

        let responseHeaders = headers.filter { !dropHeaders.contains($0.name.lowercased()) }

        finish(.success(MITMScriptHTTPClient.Response(
            status: status,
            headers: responseHeaders,
            body: responseBody,
            finalURL: request.url?.absoluteString
        )))
    }

    private func fail(_ error: Error) {
        finish(.failure(error))
    }

    private func finish(_ result: Result<MITMScriptHTTPClient.Response, Error>) {
        guard !finished else { return }
        finished = true
        deadlineTimer?.cancel(); deadlineTimer = nil
        idleTimer?.cancel(); idleTimer = nil
        MITMScriptHTTPClient.releaseInFlight(reservedBytes)
        reservedBytes = 0
        teardown()
        Self.registryLock.withLock { Self.active[ObjectIdentifier(self)] = nil }
        completion(result)
    }

    // MARK: - Helpers

    private var responseHasNoBody: Bool {
        let method = (request.httpMethod ?? "GET").uppercased()
        if method == "HEAD" { return true }
        return status == 204 || status == 304
    }

    private func header(_ name: String) -> String? {
        for (n, value) in headers where n.caseInsensitiveCompare(name) == .orderedSame { return value }
        return nil
    }

    private static func parseHead(_ headData: Data) -> (Int, [(name: String, value: String)])? {
        let text = String(decoding: headData, as: UTF8.self)
        let lines = text.components(separatedBy: "\r\n")
        guard let statusLine = lines.first else { return nil }
        let parts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let code = Int(parts[1]) else { return nil }

        var headers: [(name: String, value: String)] = []
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers.append((name: name, value: value))
        }
        return (code, headers)
    }
}

// MARK: - Chunked transfer decoder

/// Incremental `Transfer-Encoding: chunked` decoder (RFC 9112 §7.1); trailers are dropped.
private struct ChunkedDecoder {
    enum FeedResult {
        case needMore
        case done
        case error(String)
    }

    private enum State {
        case size
        case body(Int)      // bytes still to read in the current chunk
        case afterBodyCRLF
        case trailer
        case done
    }

    private var state: State = .size

    mutating func feed(_ inbound: inout Data, into out: inout Data) -> FeedResult {
        var idx = inbound.startIndex
        let end = inbound.endIndex

        while true {
            switch state {
            case .done:
                inbound = inbound.subdata(in: idx..<end)
                return .done

            case .size:
                guard let crlf = Self.indexOfCRLF(inbound, from: idx, end: end) else {
                    inbound = inbound.subdata(in: idx..<end)
                    return .needMore
                }
                guard let size = Self.parseChunkSize(inbound[idx..<crlf]) else {
                    return .error("bad chunk size")
                }
                idx = crlf + 2
                state = size == 0 ? .trailer : .body(size)

            case .body(let remaining):
                let take = min(remaining, end - idx)
                if take > 0 {
                    out.append(contentsOf: inbound[idx..<(idx + take)])
                    idx += take
                }
                let left = remaining - take
                if left > 0 {
                    state = .body(left)
                    inbound = inbound.subdata(in: idx..<end)
                    return .needMore
                }
                state = .afterBodyCRLF

            case .afterBodyCRLF:
                if end - idx < 2 {
                    inbound = inbound.subdata(in: idx..<end)
                    return .needMore
                }
                guard inbound[idx] == 0x0D, inbound[idx + 1] == 0x0A else {
                    return .error("missing CRLF after chunk data")
                }
                idx += 2
                state = .size

            case .trailer:
                guard let crlf = Self.indexOfCRLF(inbound, from: idx, end: end) else {
                    inbound = inbound.subdata(in: idx..<end)
                    return .needMore
                }
                if crlf == idx {
                    idx += 2                 // empty line terminates the trailer section
                    state = .done
                    inbound = inbound.subdata(in: idx..<end)
                    return .done
                }
                idx = crlf + 2               // skip a trailer header line
            }
        }
    }

    /// Index of the CR in the first CRLF at or after `from`, or nil.
    private static func indexOfCRLF(_ data: Data, from: Int, end: Int) -> Int? {
        guard from < end else { return nil }
        var i = from
        while i + 1 < end {
            if data[i] == 0x0D, data[i + 1] == 0x0A { return i }
            i += 1
        }
        return nil
    }

    private static func parseChunkSize<C: Collection>(_ bytes: C) -> Int? where C.Element == UInt8 {
        let line = String(decoding: bytes, as: UTF8.self)
        let sizeToken = line.split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? line
        let trimmed = sizeToken.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, let size = Int(trimmed, radix: 16), size >= 0 else { return nil }
        return size
    }
}
