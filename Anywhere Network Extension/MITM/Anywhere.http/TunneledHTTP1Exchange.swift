//
//  TunneledHTTP1Exchange.swift
//  Anywhere
//
//  Created by NodePassProject on 7/1/26.
//

import Foundation
import Synchronization

nonisolated final class TunneledHTTP1Exchange: @unchecked Sendable {

    // MARK: Active-exchange registry (keeps the exchange alive across async I/O)

    private static let active = Mutex<[ObjectIdentifier: TunneledHTTP1Exchange]>([:])

    // MARK: Inputs

    private let connection: ProxyConnection
    private let request: URLRequest
    private let hostHeader: String
    private let maxBytes: Int
    private let resourceTimeout: TimeInterval

    // MARK: State (touched only inside the single `runExchange` task)

    private var inbound = Data()
    private var headParsed = false
    private var status = 0
    private var headers: [(name: String, value: String)] = []
    private var body = Data()
    private var reservedBytes = 0
    private var bodyMode: BodyMode = .undetermined
    private var chunked = ChunkedDecoder()

    /// The inactivity deadline, refreshed as inbound bytes arrive; read by the idle-watchdog task.
    private let idleDeadline = Mutex<ContinuousClock.Instant>(ContinuousClock().now)

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
        resourceTimeout: TimeInterval
    ) {
        self.connection = connection
        self.request = request
        self.hostHeader = hostHeader
        self.maxBytes = maxBytes
        self.resourceTimeout = resourceTimeout
    }

    // MARK: - Lifecycle

    /// Runs the whole request/response exchange, racing it against the resource deadline and an
    /// inactivity idle timeout. Transport teardown is the caller's responsibility (see the callers
    /// in `MITMScriptHTTPClient`); on a deadline/idle expiry we cancel the connection to unblock
    /// the pending I/O so the exchange task unwinds promptly.
    func run() async throws -> MITMScriptHTTPClient.Response {
        Self.active.withLock { $0[ObjectIdentifier(self)] = self }
        defer {
            Self.active.withLock { $0[ObjectIdentifier(self)] = nil }
            MITMScriptHTTPClient.releaseInFlight(reservedBytes)
            reservedBytes = 0
        }

        resetIdle()
        let timeout = resourceTimeout

        return try await withThrowingTaskGroup(of: MITMScriptHTTPClient.Response.self) { group in
            group.addTask { try await self.runExchange() }
            group.addTask {
                try await Task.sleep(for: .seconds(timeout))
                throw TransportError.connectionFailed("request exceeded \(Int(timeout))s deadline")
            }
            if request.timeoutInterval > 0 {
                group.addTask { try await self.idleWatchdog() }
            }
            defer { group.cancelAll() }
            do {
                guard let result = try await group.next() else {
                    throw TransportError.connectionFailed("request produced no result")
                }
                return result
            } catch {
                // Unblock the exchange task's pending send/receive so the group can drain.
                connection.cancel()
                throw error
            }
        }
    }

    /// Refreshes the inactivity deadline; called before the exchange starts and on every inbound chunk.
    private func resetIdle() {
        let interval = request.timeoutInterval
        guard interval > 0 else { return }
        idleDeadline.withLock { $0 = ContinuousClock().now.advanced(by: .seconds(interval)) }
    }

    /// Fails the exchange after `request.timeoutInterval` of no inbound progress. Never returns
    /// normally — it either throws on idle expiry or is cancelled when the exchange finishes.
    private func idleWatchdog() async throws -> MITMScriptHTTPClient.Response {
        let interval = request.timeoutInterval
        while true {
            let deadline = idleDeadline.withLock { $0 }
            if ContinuousClock().now >= deadline {
                throw TransportError.connectionFailed("request idle for \(Int(interval))s")
            }
            try await Task.sleep(until: deadline, clock: .continuous)
        }
    }

    // MARK: - Exchange

    private func runExchange() async throws -> MITMScriptHTTPClient.Response {
        guard let head = serializeRequest() else {
            throw TransportError.connectionFailed("could not serialize request")
        }
        try await connection.send(head)

        // Phase 1: read until the final response head is parsed.
        while !headParsed {
            guard let chunk = try await receiveChunk() else {
                throw TransportError.connectionFailed("connection closed before response head")
            }
            inbound.append(chunk)
            if try parseHeadIfReady() { break }
            if inbound.count > Self.maxHeadBytes {
                throw TransportError.connectionFailed("response head exceeds \(Self.maxHeadBytes) bytes")
            }
        }

        // Phase 2: body.
        return try await readBody()
    }

    /// One inbound read; `nil` on EOF. Refreshes the idle deadline whenever bytes arrive.
    private func receiveChunk() async throws -> Data? {
        let data = try await connection.receive()
        guard let data, !data.isEmpty else { return nil }
        resetIdle()
        return data
    }

    private func readBody() async throws -> MITMScriptHTTPClient.Response {
        guard !responseHasNoBody else { return try finishSuccess() }

        switch bodyMode {
        case .undetermined:
            return try finishSuccess()

        case .contentLength(let total):
            if total == 0 { return try finishSuccess() }
            while true {
                if !inbound.isEmpty {
                    let take = min(total - body.count, inbound.count)
                    if take > 0 {
                        let slice = inbound.subdata(in: inbound.startIndex..<(inbound.startIndex + take))
                        inbound = inbound.subdata(in: (inbound.startIndex + take)..<inbound.endIndex)
                        try appendBody(slice)
                    }
                }
                if body.count >= total { return try finishSuccess() }
                guard let chunk = try await receiveChunk() else {
                    throw TransportError.connectionFailed("connection closed; body truncated (\(body.count)/\(total))")
                }
                inbound.append(chunk)
            }

        case .chunked:
            while true {
                var decoded = Data()
                switch chunked.feed(&inbound, into: &decoded) {
                case .needMore:
                    try appendBody(decoded)
                    guard let chunk = try await receiveChunk() else {
                        throw TransportError.connectionFailed("connection closed before final chunk")
                    }
                    inbound.append(chunk)
                case .done:
                    try appendBody(decoded)
                    return try finishSuccess()
                case .error(let message):
                    throw TransportError.connectionFailed("chunked decode failed: \(message)")
                }
            }

        case .untilClose:
            while true {
                if !inbound.isEmpty {
                    let slice = inbound
                    inbound = Data()
                    try appendBody(slice)
                }
                // The body runs until the server closes the connection.
                guard let chunk = try await receiveChunk() else { return try finishSuccess() }
                inbound.append(chunk)
            }
        }
    }

    // MARK: - Request serialization

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

    // MARK: - Head parsing

    /// Skips 1xx interim heads; on the final head, records status/headers and body framing.
    /// Returns `true` once the final head is parsed, `false` when more bytes are needed.
    private func parseHeadIfReady() throws -> Bool {
        let terminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
        while true {
            guard let range = inbound.range(of: terminator) else { return false }
            guard let (code, hdrs) = Self.parseHead(inbound.subdata(in: inbound.startIndex..<range.lowerBound)) else {
                throw TransportError.connectionFailed("malformed response head")
            }
            inbound = inbound.subdata(in: range.upperBound..<inbound.endIndex)
            if (100..<200).contains(code) { continue }   // interim response: keep reading for the final head
            status = code
            headers = hdrs
            headParsed = true
            try determineBodyMode()
            return true
        }
    }

    private func determineBodyMode() throws {
        if let te = header("Transfer-Encoding"), te.lowercased().contains("chunked") {
            bodyMode = .chunked
            return
        }
        if let clString = header("Content-Length"),
           let contentLength = Int(clString.trimmingCharacters(in: .whitespaces)), contentLength >= 0 {
            if contentLength > maxBytes {
                throw MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes)
            }
            bodyMode = .contentLength(contentLength)
            return
        }
        // No framing headers: the body runs until the server closes the connection.
        bodyMode = .untilClose
    }

    // MARK: - Body accounting

    /// Throws when the per-response or global byte cap is hit.
    private func appendBody(_ data: Data) throws {
        guard !data.isEmpty else { return }
        if body.count + data.count > maxBytes {
            throw MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes)
        }
        guard MITMScriptHTTPClient.reserveInFlight(data.count) else {
            throw MITMScriptHTTPClient.ClientError.globalBudgetExceeded(MITMScriptHTTPClient.maxGlobalInFlightBytes)
        }
        reservedBytes += data.count
        body.append(data)
    }

    // MARK: - Completion

    private func finishSuccess() throws -> MITMScriptHTTPClient.Response {
        var responseBody = body
        // Drop `Transfer-Encoding`: the body is fully buffered and de-chunked (and it's hop-by-hop anyway).
        var dropHeaders: Set<String> = ["transfer-encoding"]

        // Decode the origin's Content-Encoding so the script sees plaintext, dropping the stale
        // encoding/length headers. An unsupported/failed coding is left as-is for the script to handle.
        let plan = MITMBodyCodec.plan(for: header("Content-Encoding"))
        if plan.requiresDecompression,
           let decoded = MITMBodyCodec.decompress(body, plan: plan, host: request.url?.host ?? "") {
            if decoded.count > maxBytes {
                throw MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes)
            }
            responseBody = decoded
            dropHeaders.insert("content-encoding")
            dropHeaders.insert("content-length")
        }

        let responseHeaders = headers.filter { !dropHeaders.contains($0.name.lowercased()) }

        return MITMScriptHTTPClient.Response(
            status: status,
            headers: responseHeaders,
            body: responseBody,
            finalURL: request.url?.absoluteString
        )
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
nonisolated private struct ChunkedDecoder {
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
