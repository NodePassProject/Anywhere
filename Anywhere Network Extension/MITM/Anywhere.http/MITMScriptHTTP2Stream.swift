//
//  MITMScriptHTTP2Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 7/2/26.
//

import Foundation
import Synchronization

nonisolated final class MITMScriptHTTP2Stream: Sendable {
    
    private static let receiveWindow = 4 * 1024 * 1024

    // MARK: Inputs

    let streamID: UInt32
    
    private struct WeakConnection: Sendable { weak var value: MITMScriptHTTP2Connection? }
    private let connectionBox: WeakConnection
    private var connection: MITMScriptHTTP2Connection? { connectionBox.value }
    private let request: URLRequest
    private let hostHeader: String
    private let maxBytes: Int
    private let resourceTimeout: TimeInterval
    
    private let responseSignal: AsyncThrowingStream<MITMScriptHTTPClient.Response, Error>.Continuation

    // MARK: State

    private struct State {
        var haveFinalHead = false
        var status = 0
        var headers: [(name: String, value: String)] = []
        var body = Data()
        var reservedBytes = 0
        var endStreamReceived = false
        var streamReceiveConsumed = 0

        var finished = false
        
        var idleGeneration = 0
    }
    private let lock = Mutex(State())

    // MARK: Timer pokes
    
    private let finishPoke = AsyncInbox<Void>(capacity: 1)
    private let idleActivity = AsyncInbox<Void>(capacity: 1)

    // MARK: Init

    init(
        streamID: UInt32,
        connection: MITMScriptHTTP2Connection,
        request: URLRequest,
        hostHeader: String,
        maxBytes: Int,
        resourceTimeout: TimeInterval,
        responseSignal: AsyncThrowingStream<MITMScriptHTTPClient.Response, Error>.Continuation
    ) {
        self.streamID = streamID
        self.connectionBox = WeakConnection(value: connection)
        self.request = request
        self.hostHeader = hostHeader
        self.maxBytes = maxBytes
        self.resourceTimeout = resourceTimeout
        self.responseSignal = responseSignal
    }

    // MARK: - Jobs
    
    func runSend() async {
        guard !lock.withLock({ $0.finished }) else { return }
        await sendRequest()
    }
    
    func runDeadline() async {
        let timedOut = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                do { try await Task.sleep(for: .seconds(self.resourceTimeout)); return true }
                catch { return false }   // cancelled with the tree
            }
            group.addTask {
                _ = try? await self.finishPoke.next(); return false   // stream completed
            }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        guard timedOut else { return }
        fail(AnywhereError.transport(.timedOut(.receive, endpoint: nil, detail: "request exceeded \(Int(resourceTimeout))s deadline")))
    }
    
    func runIdleLoop() async {
        let interval = request.timeoutInterval
        guard interval > 0 else { return }
        while true {
            let generation = lock.withLock { $0.idleGeneration }
            enum Wake { case expired, activity, done }
            let wake = await withTaskGroup(of: Wake.self) { group in
                group.addTask {
                    do { try await Task.sleep(for: .seconds(interval)); return .expired }
                    catch { return .done }
                }
                group.addTask {
                    ((try? await self.idleActivity.next()) ?? nil) != nil ? .activity : .done
                }
                let first = await group.next() ?? .done
                group.cancelAll()
                return first
            }
            switch wake {
            case .activity:
                continue
            case .done:
                return
            case .expired:
                let expired = lock.withLock { !$0.finished && $0.idleGeneration == generation }
                guard expired else { continue }
                fail(AnywhereError.transport(.timedOut(.receive, endpoint: nil, detail: "request idle for \(Int(interval))s")))
                return
            }
        }
    }
    
    private func rearmIdleTimer() {
        lock.withLock { $0.idleGeneration += 1 }
        idleActivity.yield(())
    }

    // MARK: - Request
    
    private func sendRequest() async {
        guard let connection else { fail(AnywhereError.proxy(.http2, .notReady)); return }
        guard let headerBlock = buildHeaderBlock() else {
            fail(AnywhereError.mitm(.invalidScriptRequest))
            return
        }
        let requestBody = request.httpBody ?? Data()
        let hasBody = !requestBody.isEmpty
        do {
            try await connection.sendHeaders(streamID: streamID, headerBlock: headerBlock, endStream: !hasBody)
            if hasBody {
                try await connection.sendData(requestBody, on: self, endStream: true)
            }
        } catch {
            fail(error)
        }
    }
    
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

    // MARK: - Response

    func handleHeaders(fields: [(name: String, value: String)], endStream: Bool) {
        rearmIdleTimer()

        enum Outcome { case ignore; case failStatus; case finishOK }
        let outcome: Outcome = lock.withLock { state in
            guard !state.finished else { return .ignore }

            if !state.haveFinalHead {
                guard let statusValue = HTTPHeader.firstValue(in: fields, named: ":status"),
                      let code = HTTPHeader.parseStatusCode(statusValue) else {
                    return .failStatus
                }
                if (100..<200).contains(code) { return .ignore }
                state.haveFinalHead = true
                state.status = code
                state.headers = fields.filter { !$0.name.hasPrefix(":") }
            }

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
            fail(AnywhereError.proxy(.http2, .protocolViolation(detail: "missing or invalid :status")))
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
            
            if !body.isEmpty {
                if state.body.count + body.count > maxBytes {
                    return .fail(AnywhereError.mitm(.responseTooLarge(limit: maxBytes)))
                }
                guard MITMScriptHTTPClient.reserveInFlight(body.count) else {
                    return .fail(AnywhereError.mitm(.scriptBudgetExceeded(limit: MITMScriptHTTPClient.maxGlobalInFlightBytes)))
                }
                state.reservedBytes += body.count
                state.body.append(body)
            }
            
            var windowUpdate: NaiveHTTP2Frame?
            state.streamReceiveConsumed += fullPayloadCount
            if !endStream, state.streamReceiveConsumed >= Self.receiveWindow / 2 {
                let increment = UInt32(state.streamReceiveConsumed)
                state.streamReceiveConsumed = 0
                windowUpdate = NaiveHTTP2Framer.windowUpdateFrame(streamID: streamID, increment: increment)
            }

            if endStream { state.endStreamReceived = true }
            return .ok(windowUpdate: windowUpdate, finish: endStream)
        }
        switch outcome {
        case .ignore:
            break
        case .failNoHead:
            fail(AnywhereError.proxy(.http2, .protocolViolation(detail: "DATA before response head")))
        case .fail(let error):
            fail(error)
        case .ok(let windowUpdate, let finish):
            if let windowUpdate { connection?.sendControlFrame(windowUpdate) }
            if finish { finishSuccess() }
        }
    }

    func handleReset(errorCode: UInt32) {
        finish(.failure(AnywhereError.proxy(.http2, .streamReset(code: errorCode))), removeFromConnection: false, sendRST: false)
    }
    
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
        
        let plan = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: snapshot.headers, named: "content-encoding"))
        if plan.requiresDecompression,
           let decoded = MITMBodyCodec.decompress(snapshot.body, plan: plan, host: request.url?.host ?? "") {
            if decoded.count > maxBytes {
                fail(AnywhereError.mitm(.responseTooLarge(limit: maxBytes)))
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
        let captured: (reservedBytes: Int, endStreamReceived: Bool)? = lock.withLock { state in
            guard !state.finished else { return nil }
            state.finished = true
            let c = (state.reservedBytes, state.endStreamReceived)
            state.reservedBytes = 0
            return c
        }
        guard let captured else { return }
        
        finishPoke.finish()
        idleActivity.finish()
        MITMScriptHTTPClient.releaseInFlight(captured.reservedBytes)
        if removeFromConnection {
            connection?.removeStream(self, sendRST: sendRST && !captured.endStreamReceived)
        }
        connection?.wakeFlowParks()
        switch result {
        case .success(let response):
            responseSignal.yield(response)
            responseSignal.finish()
        case .failure(let error):
            responseSignal.finish(throwing: error)
        }
    }
}
