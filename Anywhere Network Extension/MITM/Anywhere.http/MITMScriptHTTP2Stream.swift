//
//  MITMScriptHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation
import Synchronization

nonisolated final class MITMScriptHTTP2Stream {

    /// Advertised per-stream receive window; must match the connection's SETTINGS_INITIAL_WINDOW_SIZE.
    private static let recvWindow = 4 * 1024 * 1024

    // MARK: Inputs (immutable)

    let streamID: UInt32
    private weak var connection: MITMScriptHTTP2Connection?
    private let request: URLRequest
    private let hostHeader: String
    private let maxBytes: Int
    private let resourceTimeout: TimeInterval

    /// Resumed exactly once in `finish`; the async bridge over the connection's read loop.
    private let continuation: CheckedContinuation<MITMScriptHTTPClient.Response, Error>

    // MARK: State (behind `lock`)

    private struct State {
        var haveFinalHead = false
        var status = 0
        var headers: [(name: String, value: String)] = []
        var body = Data()
        var reservedBytes = 0
        var endStreamReceived = false
        var streamRecvConsumed = 0

        var finished = false

        /// Wall-clock resource cap. Fires once; never rearmed.
        var deadlineTask: Task<Void, Never>?
        /// Inactivity backstop, rearmed on every response progress. A generation counter drops a stale
        /// task that already fired just as a rearm superseded it.
        var idleTask: Task<Void, Never>?
        var idleGeneration = 0
        /// Fire-and-forget request send (HEADERS + optional DATA); cancelled in `finish`.
        var sendTask: Task<Void, Never>?
    }
    private let lock = Mutex(State())

    // MARK: Init

    init(
        streamID: UInt32,
        connection: MITMScriptHTTP2Connection,
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        continuation: CheckedContinuation<MITMScriptHTTPClient.Response, Error>
    ) {
        self.streamID = streamID
        self.connection = connection
        self.request = request
        self.hostHeader = hostHeader
        self.maxBytes = maxBytes
        self.resourceTimeout = resourceTimeout
        self.continuation = continuation
    }

    // MARK: - Lifecycle

    /// Called once by the connection right after creating the stream (send window already seeded on
    /// the connection). Arms the timers and fires the request send.
    func start() {
        armTimers()
        let task = Task<Void, Never> { [weak self] in
            guard let self else { return }
            await self.sendRequest()
        }
        let stale = lock.withLock { state -> Bool in
            guard !state.finished else { return true }
            state.sendTask = task
            return false
        }
        if stale { task.cancel() }
    }

    /// Arms the one-shot wall-clock deadline, then the inactivity backstop. `fail` is idempotent, so
    /// an expiry that races completion is harmless.
    private func armTimers() {
        let timeout = resourceTimeout
        lock.withLock { state in
            guard !state.finished else { return }
            state.deadlineTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(timeout))
                self?.fail(TransportError.connectionFailed("request exceeded \(Int(timeout))s deadline"))
            }
        }
        rearmIdleTimer()
    }

    /// Inactivity backstop; reset whenever the response makes progress. The generation guard drops a
    /// task superseded by a later rearm.
    private func rearmIdleTimer() {
        let interval = request.timeoutInterval
        guard interval > 0 else { return }
        lock.withLock { state in
            guard !state.finished else { return }
            state.idleGeneration += 1
            let generation = state.idleGeneration
            state.idleTask?.cancel()
            state.idleTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(interval))
                guard let self else { return }
                let expired = self.lock.withLock { !$0.finished && $0.idleGeneration == generation }
                if expired { self.fail(TransportError.connectionFailed("request idle for \(Int(interval))s")) }
            }
        }
    }

    // MARK: - Request

    /// Sends HEADERS then (if present) the body. The response arrives separately via
    /// `handleHeaders`/`handleData`; here we only surface a send-side failure.
    private func sendRequest() async {
        guard let connection else { fail(MITMScriptHTTP2Error.notReady); return }
        guard let headerBlock = buildHeaderBlock() else {
            fail(MITMScriptHTTP2Error.protocolError("could not serialize request"))
            return
        }
        let requestBody = request.httpBody ?? Data()
        let hasBody = !requestBody.isEmpty
        do {
            try await connection.sendHeaders(streamID: streamID, headerBlock: headerBlock, endStream: !hasBody)
            if hasBody {
                try await connection.sendData(requestBody, on: self, endStream: true)
            }
            // Success: the full request is sent; the response arrives via handleHeaders/handleData.
        } catch {
            fail(error)
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

    // MARK: - Response (called by the connection with no connection lock held)

    func handleHeaders(fields: [(name: String, value: String)], endStream: Bool) {
        rearmIdleTimer()

        enum Outcome { case ignore; case failStatus; case finishOK }
        let outcome: Outcome = lock.withLock { state in
            guard !state.finished else { return .ignore }

            if !state.haveFinalHead {
                // Only the response head carries `:status`; require it before we have a final head.
                guard let statusValue = HTTPHeader.firstValue(in: fields, named: ":status"),
                      let code = HTTPHeader.parseStatusCode(statusValue) else {
                    return .failStatus
                }
                // Skip 1xx interim responses; keep waiting for the final head.
                if (100..<200).contains(code) { return .ignore }
                state.haveFinalHead = true
                state.status = code
                state.headers = fields.filter { !$0.name.hasPrefix(":") }
            }
            // A second header block after the final head is trailers (RFC 9113 §8.1); drop the fields.

            if endStream {
                state.endStreamReceived = true
                return .finishOK
            }
            return .ignore
        }
        switch outcome {
        case .ignore:
            break
        case .failStatus:
            fail(MITMScriptHTTP2Error.protocolError("missing or invalid :status"))
        case .finishOK:
            finishSuccess()
        }
    }

    func handleData(_ body: Data, fullPayloadCount: Int, endStream: Bool) {
        rearmIdleTimer()

        enum Outcome {
            case ignore
            case failNoHead
            case fail(Error)
            case ok(windowUpdate: NaiveHTTP2Frame?, finish: Bool)
        }
        let outcome: Outcome = lock.withLock { state in
            guard !state.finished else { return .ignore }
            guard state.haveFinalHead else { return .failNoHead }

            // Enforce the per-response and global byte caps before buffering.
            if !body.isEmpty {
                if state.body.count + body.count > maxBytes {
                    return .fail(MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes))
                }
                guard MITMScriptHTTPClient.reserveInFlight(body.count) else {
                    return .fail(MITMScriptHTTPClient.ClientError.globalBudgetExceeded(MITMScriptHTTPClient.maxGlobalInFlightBytes))
                }
                state.reservedBytes += body.count
                state.body.append(body)
            }

            // Replenish the stream receive window (full payload, incl. padding); pointless on
            // END_STREAM — the stream is closing.
            var windowUpdate: NaiveHTTP2Frame?
            state.streamRecvConsumed += fullPayloadCount
            if !endStream, state.streamRecvConsumed >= Self.recvWindow / 2 {
                let increment = UInt32(state.streamRecvConsumed)
                state.streamRecvConsumed = 0
                windowUpdate = NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment)
            }

            if endStream { state.endStreamReceived = true }
            return .ok(windowUpdate: windowUpdate, finish: endStream)
        }
        switch outcome {
        case .ignore:
            break
        case .failNoHead:
            fail(MITMScriptHTTP2Error.protocolError("DATA before response head"))
        case .fail(let error):
            fail(error)
        case .ok(let windowUpdate, let finish):
            if let windowUpdate { connection?.sendControlFrame(windowUpdate) }
            if finish { finishSuccess() }
        }
    }

    func handleReset(errorCode: UInt32) {
        // The connection has already removed us from its stream table.
        finish(.failure(MITMScriptHTTP2Error.streamReset(streamID)), removeFromConnection: false, sendRST: false)
    }

    /// The connection is tearing down and has already removed this stream; don't call back into it.
    func failFromSession(_ error: Error) {
        finish(.failure(error), removeFromConnection: false, sendRST: false)
    }

    // MARK: - Completion

    private func fail(_ error: Error) {
        finish(.failure(error), removeFromConnection: true, sendRST: true)
    }

    private func finishSuccess() {
        let snapshot: (body: Data, headers: [(name: String, value: String)], status: Int)? = lock.withLock { state in
            guard !state.finished else { return nil }
            return (state.body, state.headers, state.status)
        }
        guard let snapshot else { return }

        var responseBody = snapshot.body
        var dropHeaders: Set<String> = ["transfer-encoding"]

        // Decode the origin's Content-Encoding so the script sees plaintext, dropping the stale
        // encoding/length headers. An unsupported/failed coding is left as-is for the script.
        let plan = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: snapshot.headers, named: "content-encoding"))
        if plan.requiresDecompression,
           let decoded = MITMBodyCodec.decompress(snapshot.body, plan: plan, host: request.url?.host ?? "") {
            if decoded.count > maxBytes {
                fail(MITMScriptHTTPClient.ClientError.responseTooLarge(maxBytes))
                return
            }
            responseBody = decoded
            dropHeaders.insert("content-encoding")
            dropHeaders.insert("content-length")
        }

        let responseHeaders = snapshot.headers.filter { !dropHeaders.contains($0.name.lowercased()) }

        finish(.success(MITMScriptHTTPClient.Response(
            status: snapshot.status,
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
        struct Captured { let deadline: Task<Void, Never>?; let idle: Task<Void, Never>?; let send: Task<Void, Never>?
                          let reservedBytes: Int; let endStreamReceived: Bool }
        let captured: Captured? = lock.withLock { state in
            guard !state.finished else { return nil }
            state.finished = true
            let c = Captured(deadline: state.deadlineTask, idle: state.idleTask, send: state.sendTask,
                             reservedBytes: state.reservedBytes, endStreamReceived: state.endStreamReceived)
            state.deadlineTask = nil
            state.idleTask = nil
            state.sendTask = nil
            state.reservedBytes = 0
            return c
        }
        guard let captured else { return }

        captured.deadline?.cancel()
        captured.idle?.cancel()
        captured.send?.cancel()
        MITMScriptHTTPClient.releaseInFlight(captured.reservedBytes)
        if removeFromConnection {
            connection?.removeStream(self, sendRST: sendRST && !captured.endStreamReceived)
        }
        // Unblock a request send parked on this stream's flow window so its task unwinds.
        connection?.wakeFlowParks()
        continuation.resume(with: result)
    }
}
