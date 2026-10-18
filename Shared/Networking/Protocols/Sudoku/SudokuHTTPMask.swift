//
//  SudokuHTTPMask.swift
//  Anywhere
//
//  Created by saba-futai on 10/18/26.
//

import Foundation
import Synchronization

nonisolated private let sudokuHTTPMaskMaxQueueBytes = 4 * 1024 * 1024
nonisolated private let sudokuHTTPMaskMaxPollLineBytes = 256 * 1024
nonisolated private let sudokuHTTPMaskStreamEOFHeader = "x-sudoku-stream-eof"
nonisolated private let sudokuHTTPMaskUploadSequenceCapability = "upload-seq"

nonisolated private struct SudokuHTTPMaskStatusError: Error {
    let status: Int
}

nonisolated enum SudokuHTTPMaskWebSocketAuth {
    static func token(key: String, mode: String, method: String, path: String) -> String {
        var keyMaterial = Data("sudoku-httpmask-auth-v1:".utf8)
        keyMaterial.append(Data(key.utf8))
        let authKey = SudokuNativeCrypto.sha256(keyMaterial)
        var ts = UInt64(Date().timeIntervalSince1970).bigEndian
        let tsData = Data(bytes: &ts, count: 8)
        let zero = Data([0])
        let mac = SudokuNativeCrypto.hmacSHA256(
            key: authKey,
            parts: [Data(mode.utf8), zero, Data(method.utf8), zero, Data(path.utf8), zero, tsData]
        )
        var payload = tsData
        payload.append(mac.prefix(16))
        return payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

nonisolated enum SudokuHTTPMaskPathRoot {
    static func apply(_ root: String, to path: String) -> String {
        let clean = normalize(root)
        guard !clean.isEmpty else { return path }
        let suffix = path.hasPrefix("/") ? path : "/\(path)"
        return "/\(clean)\(suffix)"
    }

    private static func normalize(_ root: String) -> String {
        let slashes = CharacterSet(charactersIn: "/")
        let trimmed = root.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: slashes)
        guard !trimmed.isEmpty else { return "" }
        for scalar in trimmed.unicodeScalars {
            switch scalar.value {
            case 48...57, 65...90, 97...122, 45, 95:
                continue
            default:
                return ""
            }
        }
        return trimmed
    }
}

private nonisolated func sudokuReadHTTPLine(
    from stream: BlockingProxyStream,
    maxBytes: Int = 8 * 1024
) async throws -> String {
    var data = Data()
    while true {
        let byte = try await stream.readExact(1).uint8(at: 0)
        if byte == 0x0a { break }
        if byte != 0x0d { data.append(byte) }
        if data.count > maxBytes {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "HTTP line too long"))
        }
    }
    return String(data: data, encoding: .utf8) ?? ""
}

nonisolated private final class SudokuHTTPBodyReader {
    private let stream: BlockingProxyStream
    let status: Int
    private let chunked: Bool
    private let closeDelimited: Bool
    private var contentRemaining: Int
    private var chunkRemaining = 0
    private var done = false
    private(set) var streamEOF = false

    init(stream: BlockingProxyStream, status: Int, chunked: Bool, contentLength: Int?) {
        self.stream = stream
        self.status = status
        self.chunked = chunked
        self.contentRemaining = contentLength ?? 0
        self.closeDelimited = !chunked && contentLength == nil
    }
    
    func finish() {
        stream.cancel()
    }

    func readSome(max: Int = 32 * 1024) async throws -> Data {
        if done { return Data() }
        if chunked {
            while chunkRemaining == 0 {
                let line = try await sudokuReadHTTPLine(from: stream)
                let lenText = line.split(separator: ";", maxSplits: 1).first.map(String.init) ?? line
                guard let length = Int(lenText.trimmingCharacters(in: .whitespacesAndNewlines), radix: 16), length >= 0 else {
                    throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad chunk length"))
                }
                if length == 0 {
                    while true {
                        let trailer = try await sudokuReadHTTPLine(from: stream)
                        if trailer.isEmpty { break }
                        let parts = trailer.split(separator: ":", maxSplits: 1)
                        guard parts.count == 2 else { continue }
                        if parts[0].trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == sudokuHTTPMaskStreamEOFHeader,
                           parts[1].trimmingCharacters(in: .whitespacesAndNewlines) == "1" {
                            streamEOF = true
                        }
                    }
                    done = true
                    return Data()
                }
                chunkRemaining = length
            }
            let n = min(max, chunkRemaining)
            let data = try await stream.readExact(n)
            chunkRemaining -= n
            if chunkRemaining == 0 { _ = try await stream.readExact(2) }
            return data
        }
        if !closeDelimited {
            if contentRemaining == 0 {
                done = true
                return Data()
            }
            let n = min(max, contentRemaining)
            let data = try await stream.readExact(n)
            contentRemaining -= n
            if contentRemaining == 0 { done = true }
            return data
        }
        do { return try await stream.readSome(max: max) }
        catch AnywhereError.proxy(.sudoku, .connectionClosed) {
            done = true
            return Data()
        }
    }

    func readAll(limit: Int) async throws -> Data {
        var out = Data()
        while out.count < limit {
            let part = try await readSome(max: min(4096, limit - out.count))
            if part.isEmpty { break }
            out.append(part)
        }
        return out
    }
}

nonisolated final class SudokuHTTPMaskTransport: Sendable {
    private let config: SudokuNativeConfig
    private let factory: SudokuConnectionFactory
    private let mode: SudokuHTTPMaskMode
    private let earlyRequestPayload: Data?
    
    private struct Paths {
        let pullPath: String
        let pushPath: String
        let closePath: String
    }
    private let paths: Paths
    
    var earlyResponsePayload: Data { state.withLock { $0.earlyResponsePayload } }

    private enum Step<T> {
        case done(T)
        case fail(Error)
        case wait(UInt64)
    }
    
    private struct State: PhaseHolding {
        var rxQueue = SudokuDataQueue()
        var txQueue = SudokuDataQueue()
        var phase: SudokuLifecycle = .open
        var fatal = false
        var readEOF = false
        var pullReady = false
        var pushReady = false
        var nextUploadSequence: UInt64 = 1
        var earlyResponsePayload = Data()
        var runTask: Task<Void, Never>?
        var closeTask: Task<Void, Never>?
        var generation: UInt64 = 0
        var nextWaiterID: UInt64 = 0
        var waiters: [(id: UInt64, cont: AsyncStream<Never>.Continuation)] = []
    }
    private let state = Mutex(State())

    init(config: SudokuNativeConfig, factory: SudokuConnectionFactory, mode: SudokuHTTPMaskMode, earlyRequestPayload: Data? = nil) async throws {
        let earlyRequest = earlyRequestPayload?.isEmpty == false ? earlyRequestPayload : nil
        self.config = config
        self.factory = factory
        self.mode = mode
        self.earlyRequestPayload = earlyRequest
        let serverName = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        factory.prepare(
            host: config.serverHost,
            port: config.serverPort,
            useTLS: config.httpMask.tls,
            serverName: serverName,
            count: 3
        )
        let auth = try await Self.authorize(config: config, factory: factory, mode: mode, earlyRequestPayload: earlyRequest)
        self.paths = auth.paths
        state.withLock { $0.earlyResponsePayload = auth.earlyResponse }
        let run = Task {
            await withTaskGroup(of: Void.self) { group in
                group.addTask { await self.pullLoop() }
                group.addTask { await self.pushLoop() }
            }
        }
        state.withLock { $0.runTask = run }
    }

    // MARK: Async broadcast
    
    private func drainWaitersLocked(_ s: inout State) -> [AsyncStream<Never>.Continuation] {
        s.generation &+= 1
        let conts = s.waiters.map { $0.cont }
        s.waiters.removeAll(keepingCapacity: true)
        return conts
    }
    
    private func waitSignal(observed: UInt64) async {
        let id = state.withLock { s -> UInt64 in
            let id = s.nextWaiterID
            s.nextWaiterID &+= 1
            return id
        }
        let stream: AsyncStream<Never>? = state.withLock { s -> AsyncStream<Never>? in
            if s.generation != observed { return nil }
            let (stream, cont) = AsyncStream.makeStream(of: Never.self)
            s.waiters.append((id: id, cont: cont))
            return stream
        }
        guard let stream else { return }
        for await _ in stream {}
        state.withLock { s in s.waiters.removeAll { $0.id == id } }
    }
    
    private func waitSignal(observed: UInt64, until deadline: TimeInterval) async {
        let interval = deadline - MonotonicClock.now
        guard interval > 0 else { return }
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.waitSignal(observed: observed) }
            group.addTask { try? await Task.sleep(seconds: interval, precision: .prompt) }
            _ = await group.next()
            group.cancelAll()
        }
    }

    // MARK: Public I/O

    func send(_ data: Data) async throws {
        let queueLimit = max(sudokuHTTPMaskMaxQueueBytes, data.count)
        while true {
            try Task.checkCancellation()
            var toResume: [AsyncStream<Never>.Continuation] = []
            let step: Step<Void> = state.withLock { s in
                if s.phase == .closed { return .fail(AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))) }
                if s.txQueue.count + data.count > queueLimit { return .wait(s.generation) }
                s.txQueue.append(data)
                toResume = drainWaitersLocked(&s)
                return .done(())
            }
            for cont in toResume { cont.finish() }
            switch step {
            case .done: return
            case .fail(let error): throw error
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    func receive(max: Int) async throws -> Data {
        while true {
            try Task.checkCancellation()
            var toResume: [AsyncStream<Never>.Continuation] = []
            let step: Step<Data> = state.withLock { s in
                if !s.rxQueue.isEmpty {
                    let out = s.rxQueue.read(max: max)
                    if s.rxQueue.isEmpty { s.rxQueue.removeAll(keepingCapacity: false) }
                    toResume = drainWaitersLocked(&s)
                    return .done(out)
                }
                if s.readEOF { return .fail(AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil))) }
                if s.phase == .closed {
                    return .fail(s.fatal ? AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask closed")) : AnywhereError.proxy(.sudoku, .connectionClosed(detail: nil)))
                }
                return .wait(s.generation)
            }
            for cont in toResume { cont.finish() }
            switch step {
            case .done(let out): return out
            case .fail(let error): throw error
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    func close() {
        markClosed(fatal: false)
        let path = paths.closePath
        let task: Task<Void, Never> = Task {
            _ = try? await self.sendSessionControl(path: path, attempts: 1)
        }
        let previous: Task<Void, Never>? = state.withLock { s in
            let previous = s.closeTask
            s.closeTask = task
            return previous
        }
        previous?.cancel()
    }

    func waitReady(timeout: TimeInterval) async throws {
        let deadline = MonotonicClock.now + timeout
        ready: while true {
            try Task.checkCancellation()
            let step: Step<Void> = state.withLock { s in
                if s.pullReady && s.pushReady { return .done(()) }
                if s.phase == .closed { return .fail(AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask closed before tunnel became ready"))) }
                return .wait(s.generation)
            }
            switch step {
            case .done: break ready
            case .fail(let error): throw error
            case .wait(let generation):
                if MonotonicClock.now >= deadline {
                    throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "timeout waiting for HTTPMask tunnel readiness"))
                }
                await waitSignal(observed: generation, until: deadline)
            }
        }
    }

    private static func hostHeader(config: SudokuNativeConfig) -> String {
        let host = config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host
        if (config.httpMask.tls && config.serverPort == 443) || (!config.httpMask.tls && config.serverPort == 80) { return host }
        return "\(host):\(config.serverPort)"
    }

    private static func applyPathRoot(config: SudokuNativeConfig, _ path: String) -> String {
        SudokuHTTPMaskPathRoot.apply(config.httpMask.pathRoot, to: path)
    }

    private static func appendEarlyData(_ path: String, payload: Data?) -> String {
        guard let payload, !payload.isEmpty else { return path }
        let encoded = payload.base64URLEncodedString()
        return path + (path.contains("?") ? "&" : "?") + "ed=\(encoded)"
    }
    
    private static func request(
        config: SudokuNativeConfig,
        factory: SudokuConnectionFactory,
        mode: SudokuHTTPMaskMode,
        method: String,
        requestPath: String,
        contentType: String? = nil,
        body: Data
    ) async throws -> SudokuHTTPBodyReader {
        let stream = try await factory.open(host: config.serverHost, port: config.serverPort, useTLS: config.httpMask.tls, serverName: config.httpMask.host.isEmpty ? config.serverHost : config.httpMask.host)
        let modeName = mode == .poll ? "poll" : "stream"
        var requestHead = "\(method) \(requestPath) HTTP/1.1\r\nHost: \(hostHeader(config: config))\r\nUser-Agent: \(ProxyUserAgent.chrome)\r\nAccept: */*\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nConnection: close\r\nX-Sudoku-Tunnel: \(modeName)\r\n"
        if let contentType { requestHead += "Content-Type: \(contentType)\r\n" }
        requestHead += "Content-Length: \(body.count)\r\n\r\n"
        var data = Data(requestHead.utf8)
        data.append(body)
        do {
            try await stream.sendAll(data)
            return try await readHeaders(stream: stream)
        } catch {
            stream.cancel()
            throw error
        }
    }

    private func sendSessionControl(path: String, attempts: Int = 3) async throws {
        guard !path.isEmpty else {
            throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "HTTPMask session control path is empty"))
        }
        var lastError: Error = AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask session control failed"))
        for _ in 0..<max(1, attempts) {
            do {
                let opened = try await Self.request(
                    config: config,
                    factory: factory,
                    mode: mode,
                    method: "POST",
                    requestPath: path,
                    body: Data()
                )
                defer { opened.finish() }
                _ = try await opened.readAll(limit: 256)
                if opened.status == 200 {
                    return
                }
                if [403, 404, 410].contains(opened.status) {
                    return
                }
                lastError = AnywhereError.proxy(.sudoku, .connectionClosed(detail:
                    "HTTPMask session control status \(opened.status)"
                ))
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    private static func readHeaders(stream: BlockingProxyStream) async throws -> SudokuHTTPBodyReader {
        let statusLine = try await sudokuReadHTTPLine(from: stream)
        let parts = statusLine.split(separator: " ")
        guard parts.count >= 2, let status = Int(parts[1]) else { throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "bad HTTP response")) }
        var chunked = false
        var contentLength: Int?
        while true {
            let header = try await sudokuReadHTTPLine(from: stream)
            if header.isEmpty { break }
            let lower = header.lowercased()
            if lower.hasPrefix("transfer-encoding:") && lower.contains("chunked") { chunked = true }
            if lower.hasPrefix("content-length:"),
               let value = Int(header.dropFirst("content-length:".count).trimmingCharacters(in: .whitespaces)),
               value >= 0 { contentLength = value }
        }
        return SudokuHTTPBodyReader(stream: stream, status: status, chunked: chunked, contentLength: contentLength)
    }
    
    private static func authorize(
        config: SudokuNativeConfig,
        factory: SudokuConnectionFactory,
        mode: SudokuHTTPMaskMode,
        earlyRequestPayload: Data?
    ) async throws -> (paths: Paths, earlyResponse: Data) {
        let sessionPath = applyPathRoot(config: config, "/session")
        let opened = try await request(config: config, factory: factory, mode: mode, method: "GET", requestPath: appendEarlyData(sessionPath, payload: earlyRequestPayload), body: Data())
        defer { opened.finish() }
        guard opened.status == 200 else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask authorize status \(opened.status)")) }
        let body = try await opened.readAll(limit: 4096)
        guard let text = String(data: body, encoding: .utf8), let range = text.range(of: "token=") else {
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask authorize missing token"))
        }
        let tail = text[range.upperBound...]
        let token = String(tail.prefix { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        guard !token.isEmpty else { throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask empty token")) }
        guard text.split(whereSeparator: \.isNewline).contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines) == "cap=\(sudokuHTTPMaskUploadSequenceCapability)" }) else {
            throw AnywhereError.proxy(.sudoku, .connectionClosed(detail: "HTTPMask server does not support upload sequencing"))
        }
        var earlyResponse = Data()
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("ed=") else { continue }
            let encoded = String(trimmed.dropFirst(3))
            if let decoded = Data(base64URLEncoded: encoded) {
                earlyResponse = decoded
            }
            break
        }
        let streamPath = applyPathRoot(config: config, "/stream")
        let uploadPath = applyPathRoot(config: config, "/api/v1/upload")
        let pushPath = "\(uploadPath)?token=\(token)"
        let paths = Paths(
            pullPath: "\(streamPath)?token=\(token)",
            pushPath: pushPath,
            closePath: "\(pushPath)&close=1"
        )
        return (paths, earlyResponse)
    }

    private func markReadEOF() {
        let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
            guard !s.readEOF else { return [] }
            s.readEOF = true
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.finish() }
    }

    private func markClosed(fatal: Bool) {
        var tasksToCancel: [Task<Void, Never>] = []
        let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
            s.fatal = s.fatal || fatal
            _ = s.transition(to: .closed)
            tasksToCancel = [s.runTask, s.closeTask].compactMap { $0 }
            s.runTask = nil
            s.closeTask = nil
            return drainWaitersLocked(&s)
        }
        for cont in conts { cont.finish() }
        for task in tasksToCancel { task.cancel() }
    }

    private func pullLoop() async {
        var retryDelayMs = 10
        while true {
            if state.withLock({ $0.phase == .closed }) { return }

            do {
                let opened = try await Self.request(config: config, factory: factory, mode: mode, method: "GET", requestPath: paths.pullPath, body: Data())
                defer { opened.finish() }
                guard opened.status == 200 else {
                    if Self.isTerminalHTTPMaskStatus(opened.status) {
                        markClosed(fatal: true)
                        return
                    }
                    guard await waitForHTTPMaskRetry(delayMilliseconds: &retryDelayMs) else { return }
                    continue
                }

                let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
                    s.pullReady = true
                    return drainWaitersLocked(&s)
                }
                for cont in conts { cont.finish() }

                var pollLine = Data()
                while true {
                    let data = try await opened.readSome()
                    if data.isEmpty { break }
                    retryDelayMs = 10
                    if mode == .poll {
                        for byte in data where byte != 0x0d {
                            if byte == 0x0a {
                                if !pollLine.isEmpty {
                                    guard let decoded = Data(base64Encoded: pollLine) else {
                                        throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "invalid HTTPMask poll payload"))
                                    }
                                    await enqueueRX(decoded)
                                    pollLine.removeAll()
                                }
                            } else {
                                pollLine.append(byte)
                                if pollLine.count > sudokuHTTPMaskMaxPollLineBytes {
                                    throw AnywhereError.proxy(.sudoku, .protocolViolation(detail: "HTTPMask poll line too long"))
                                }
                            }
                        }
                    } else {
                        await enqueueRX(data)
                    }
                }
                if opened.streamEOF {
                    markReadEOF()
                    return
                }
            } catch {
                if case AnywhereError.proxy(.sudoku, .protocolViolation) = error {
                    markClosed(fatal: true)
                    return
                }
            }
            guard await waitForHTTPMaskRetry(delayMilliseconds: &retryDelayMs) else { return }
        }
    }

    private static func isTerminalHTTPMaskStatus(_ status: Int) -> Bool {
        [403, 404, 409, 410].contains(status)
    }

    private func waitForHTTPMaskRetry(delayMilliseconds: inout Int) async -> Bool {
        if state.withLock({ $0.phase == .closed }) { return false }
        do {
            try await Task.sleep(for: .milliseconds(delayMilliseconds), precision: .prompt)
        } catch {
            return false
        }
        delayMilliseconds = min(delayMilliseconds * 2, 250)
        return !state.withLock { $0.phase == .closed }
    }

    private func enqueueRX(_ data: Data) async {
        let queueLimit = max(sudokuHTTPMaskMaxQueueBytes, data.count)
        while true {
            var toResume: [AsyncStream<Never>.Continuation] = []
            let step: Step<Void> = state.withLock { s in
                if s.phase == .closed { return .done(()) }
                if s.rxQueue.count + data.count > queueLimit { return .wait(s.generation) }
                s.rxQueue.append(data)
                toResume = drainWaitersLocked(&s)
                return .done(())
            }
            for cont in toResume { cont.finish() }
            switch step {
            case .done, .fail: return
            case .wait(let generation): await waitSignal(observed: generation)
            }
        }
    }

    private func pushLoop() async {
        let maxBatchBytes = mode == .poll ? 49_152 : 262_144
        let flushInterval: TimeInterval = 0.005
        while true {
            waitData: while true {
                let step: Step<Void> = state.withLock { s in
                    if s.phase == .closed || !s.txQueue.isEmpty { return .done(()) }
                    return .wait(s.generation)
                }
                switch step {
                case .done, .fail: break waitData
                case .wait(let generation): await waitSignal(observed: generation)
                }
            }
            if state.withLock({ $0.phase == .closed }) { return }
            
            let flushDeadline = MonotonicClock.now + flushInterval
            coalesce: while true {
                let step: Step<Void> = state.withLock { s in
                    if s.phase == .closed || s.txQueue.isEmpty { return .done(()) }
                    if s.txQueue.count >= maxBatchBytes { return .done(()) }
                    return .wait(s.generation)
                }
                switch step {
                case .done, .fail: break coalesce
                case .wait(let generation):
                    if MonotonicClock.now >= flushDeadline { break coalesce }
                    await waitSignal(observed: generation, until: flushDeadline)
                }
            }
            
            var toResume: [AsyncStream<Never>.Continuation] = []
            let (batch, isClosed): (Data?, Bool) = state.withLock { s in
                if s.phase == .closed { return (nil, true) }
                if s.txQueue.isEmpty { return (nil, false) }
                let n = min(maxBatchBytes, s.txQueue.count)
                let batch = s.txQueue.readCoalesced(max: n)
                if s.txQueue.isEmpty { s.txQueue.removeAll(keepingCapacity: false) }
                toResume = drainWaitersLocked(&s)
                return (batch, false)
            }
            for cont in toResume { cont.finish() }
            if isClosed { return }

            guard let batch, !batch.isEmpty else { continue }
            do {
                let body: Data
                let contentType: String
                if mode == .poll {
                    var encoded = batch.base64EncodedData()
                    encoded.append(0x0a)
                    body = encoded
                    contentType = "text/plain"
                } else {
                    body = batch
                    contentType = "application/octet-stream"
                }
                let sequence = state.withLock { $0.nextUploadSequence }
                let requestPath = paths.pushPath + "&seq=\(sequence)"
                var retryDelayMs = 10
                while true {
                    do {
                        let opened = try await Self.request(config: config, factory: factory, mode: mode, method: "POST", requestPath: requestPath, contentType: contentType, body: body)
                        defer { opened.finish() }
                        let status = opened.status
                        _ = try await opened.readAll(limit: 256)
                        guard status == 200 else { throw SudokuHTTPMaskStatusError(status: status) }
                        break
                    } catch let error as SudokuHTTPMaskStatusError {
                        guard !Self.isTerminalHTTPMaskStatus(error.status) else { throw error }
                        guard await waitForHTTPMaskRetry(delayMilliseconds: &retryDelayMs) else { return }
                    } catch {
                        guard await waitForHTTPMaskRetry(delayMilliseconds: &retryDelayMs) else { return }
                    }
                }
                state.withLock { s in
                    if s.nextUploadSequence == sequence { s.nextUploadSequence &+= 1 }
                }
                let conts = state.withLock { s -> [AsyncStream<Never>.Continuation] in
                    s.pushReady = true
                    return drainWaitersLocked(&s)
                }
                for cont in conts { cont.finish() }
            } catch {
                markClosed(fatal: true)
                return
            }
        }
    }
}
