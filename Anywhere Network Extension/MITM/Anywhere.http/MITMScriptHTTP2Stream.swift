//
//  MITMScriptHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation

/// One HTTP/2 request/response exchange on a single stream of a `MITMScriptHTTP2Connection`.
/// All state is confined to the owning connection's `queue`.
nonisolated final class MITMScriptHTTP2Stream {

    /// Advertised per-stream receive window; must match the connection's SETTINGS_INITIAL_WINDOW_SIZE.
    private static let recvWindow = 4 * 1024 * 1024

    // MARK: Inputs

    let streamID: UInt32
    private weak var connection: MITMScriptHTTP2Connection?
    private let request: URLRequest
    private let hostHeader: String
    private let maxBytes: Int
    private let resourceTimeout: TimeInterval
    private let completion: (Result<MITMScriptHTTPClient.Response, Error>) -> Void

    // MARK: State (touched only on the connection's queue)

    /// Send-side flow-control window; seeded from the peer's INITIAL_WINDOW_SIZE in `start`.
    private(set) var sendWindow = 65_535
    private var streamRecvConsumed = 0

    private var haveFinalHead = false
    private var status = 0
    private var headers: [(name: String, value: String)] = []
    private var body = Data()
    private var reservedBytes = 0
    private var endStreamReceived = false

    private var finished = false
    private var deadlineTimer: DispatchSourceTimer?
    private var idleTimer: DispatchSourceTimer?

    var isFinished: Bool { finished }

    // MARK: Init

    init(
        streamID: UInt32,
        connection: MITMScriptHTTP2Connection,
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        completion: @escaping (Result<MITMScriptHTTPClient.Response, Error>) -> Void
    ) {
        self.streamID = streamID
        self.connection = connection
        self.request = request
        self.hostHeader = hostHeader
        self.maxBytes = maxBytes
        self.resourceTimeout = resourceTimeout
        self.completion = completion
    }

    // MARK: - Lifecycle (on the connection's queue)

    func start() {
        guard let connection else { fail(MITMScriptHTTP2Error.notReady); return }
        sendWindow = connection.peerInitialWindowSize
        armTimers()
        sendRequest()
    }

    private func armTimers() {
        guard let queue = connection?.queue else { return }
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

    /// Inactivity backstop; reset whenever the response makes progress.
    private func rearmIdleTimer() {
        guard let queue = connection?.queue else { return }
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
        guard let connection else { fail(MITMScriptHTTP2Error.notReady); return }
        guard let headerBlock = buildHeaderBlock() else {
            fail(MITMScriptHTTP2Error.protocolError("could not serialize request"))
            return
        }
        let requestBody = request.httpBody ?? Data()
        let hasBody = !requestBody.isEmpty

        connection.sendHeaders(streamID: streamID, headerBlock: headerBlock, endStream: !hasBody) { [weak self, weak connection] error in
            connection?.queue.async {
                guard let self, !self.finished else { return }
                if let error { self.fail(error); return }
                guard hasBody, let connection else { return }
                connection.sendData(requestBody, on: self, endStream: true) { [weak self, weak connection] error in
                    connection?.queue.async {
                        guard let self, !self.finished else { return }
                        if let error { self.fail(error) }
                        // Success: the full request is sent; the response arrives via handleHeaders/handleData.
                    }
                }
            }
        }
    }

    /// Pseudo-headers first and in order (RFC 9113 §8.3), then lowercased regular headers with
    /// hop-by-hop / connection-specific / self-managed fields removed. `accept-encoding` is fixed to
    /// what `MITMBodyCodec` can reverse so the response body is delivered decoded.
    private func buildHeaderBlock() -> Data? {
        guard let url = request.url,
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        let method = (request.httpMethod ?? "GET").uppercased()
        guard HTTPHeader.isValidName(method) else { return nil }

        var path = comps.percentEncodedPath
        if path.isEmpty { path = "/" }
        if let query = comps.percentEncodedQuery, !query.isEmpty { path += "?" + query }

        var fields: [(name: String, value: String)] = [
            (":method", method),
            (":scheme", "https"),
            (":authority", hostHeader),
            (":path", path),
        ]

        // `host` is carried by `:authority`; `content-length` is implied by DATA framing.
        let dropped: Set<String> = [
            "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te",
            "host", "content-length", "accept-encoding",
        ]
        if let userHeaders = request.allHTTPHeaderFields {
            for (name, value) in userHeaders {
                guard HTTPHeader.isValidName(name), HTTPHeader.isValidValue(value) else { continue }
                let lower = name.lowercased()
                if dropped.contains(lower) { continue }
                fields.append((lower, value))
            }
        }
        fields.append(("accept-encoding", "gzip, deflate, br"))

        return HPACKEncoder.encodeHeaderBlock(fields)
    }

    // MARK: - Response (called by the connection on its queue)

    func handleHeaders(fields: [(name: String, value: String)], endStream: Bool) {
        guard !finished else { return }
        rearmIdleTimer()

        if !haveFinalHead {
            // Only the response head carries `:status`; require it before we have a final head.
            guard let statusValue = HTTPHeader.firstValue(in: fields, named: ":status"),
                  let code = HTTPHeader.parseStatusCode(statusValue) else {
                fail(MITMScriptHTTP2Error.protocolError("missing or invalid :status"))
                return
            }
            // Skip 1xx interim responses; keep waiting for the final head.
            if (100..<200).contains(code) { return }
            haveFinalHead = true
            status = code
            headers = fields.filter { !$0.name.hasPrefix(":") }
        }
        // A second header block after the final head is trailers (RFC 9113 §8.1); drop the fields.

        if endStream {
            endStreamReceived = true
            finishSuccess()
        }
    }

    func handleData(_ body: Data, fullPayloadCount: Int, endStream: Bool) {
        guard !finished else { return }
        rearmIdleTimer()
        guard haveFinalHead else {
            fail(MITMScriptHTTP2Error.protocolError("DATA before response head"))
            return
        }
        if !appendBody(body) { return }

        // Replenish the stream receive window (full payload, incl. padding); pointless on
        // END_STREAM — the stream is closing.
        streamRecvConsumed += fullPayloadCount
        if !endStream, streamRecvConsumed >= Self.recvWindow / 2 {
            let increment = UInt32(streamRecvConsumed)
            streamRecvConsumed = 0
            connection?.sendControlFrame(NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment))
        }

        if endStream {
            endStreamReceived = true
            finishSuccess()
        }
    }

    func handleReset(errorCode: UInt32) {
        guard !finished else { return }
        // The connection has already removed us from its stream table.
        finish(.failure(MITMScriptHTTP2Error.streamReset(streamID)), removeFromConnection: false, sendRST: false)
    }

    /// The connection is tearing down and has already removed this stream; don't call back into it.
    func failFromSession(_ error: Error) {
        finish(.failure(error), removeFromConnection: false, sendRST: false)
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

    // MARK: - Flow control (called by the connection on its queue)

    func consumeSendWindow(_ bytes: Int) { sendWindow -= bytes }
    func adjustSendWindow(delta: Int) { sendWindow += delta }

    // MARK: - Completion

    private func fail(_ error: Error) {
        finish(.failure(error), removeFromConnection: true, sendRST: true)
    }

    private func finishSuccess() {
        var responseBody = body
        var dropHeaders: Set<String> = ["transfer-encoding"]

        // Decode the origin's Content-Encoding so the script sees plaintext, dropping the stale
        // encoding/length headers. An unsupported/failed coding is left as-is for the script.
        let plan = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: headers, named: "content-encoding"))
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
        )), removeFromConnection: true, sendRST: false)
    }

    private func finish(
        _ result: Result<MITMScriptHTTPClient.Response, Error>,
        removeFromConnection: Bool,
        sendRST: Bool
    ) {
        guard !finished else { return }
        finished = true
        deadlineTimer?.cancel(); deadlineTimer = nil
        idleTimer?.cancel(); idleTimer = nil
        MITMScriptHTTPClient.releaseInFlight(reservedBytes)
        reservedBytes = 0
        if removeFromConnection {
            connection?.removeStream(self, sendRST: sendRST && !endStreamReceived)
        }
        completion(result)
    }
}
