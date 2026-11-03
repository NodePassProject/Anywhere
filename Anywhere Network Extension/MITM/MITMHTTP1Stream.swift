//
//  MITMHTTP1Stream.swift
//  Anywhere
//
//  Created by NodePassProject on 5/4/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMHTTP1Stream")

nonisolated protocol MITMHTTP1ResponseIRSink: AnyObject, Sendable {
    func http1ResponseHead(status: Int, headers: [(name: String, value: String)], endStream: Bool)
    func http1ResponseInterim(status: Int, headers: [(name: String, value: String)])
    func http1ResponseBody(_ data: Data, endStream: Bool)
    func http1ResponseReset()
}

nonisolated protocol MITMHTTP1StreamDelegate: AnyObject {
    func http1StreamDidUpgrade(_ stream: MITMHTTP1Stream)
    func http1StreamFatalClose(_ stream: MITMHTTP1Stream)
    func http1StreamHardClose(_ stream: MITMHTTP1Stream)
}

actor MITMHTTP1Stream {
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        sessionContext.executor.asUnownedSerialExecutor()
    }

    private static let maxHeadBytes: Int = 64 * 1024

    fileprivate static let maxChunkLineBytes: Int = 16 * 1024

    fileprivate static let maxTrackedChunkSizes: Int = 8192

    private static let maxSynthesizedResponseBodyBytes: Int = MITMBodyCodec.maxBufferedBodyBytes

    private let host: String
    private var logPrefix: String { "[MITM] \(host): HTTP/1 \(direction == .httpRequest ? "request" : "response")" }
    private let scheme: String
    let direction: MITMPhase

    let bridgeClientStreamID: UInt32?
    private let rules: [CompiledMITMRule]
    private let responseBodyGateRules: [CompiledMITMRule]
    private let ruleSetID: UUID?
    private var effectiveAuthority: String?

    private var resolvedUpstreamValue: (host: String, port: UInt16?)?

    nonisolated var resolvedUpstream: (host: String, port: UInt16?)? {
        assumeIsolated { $0.resolvedUpstreamValue }
    }

    private var currentRequestOriginalURL: String?

    weak var delegate: MITMHTTP1StreamDelegate?

    private let requestLog: MITMRequestLog

    private let sessionContext: SessionExecutionContext

    init(
        host: String,
        scheme: String = "https",
        direction: MITMPhase,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?,
        requestLog: MITMRequestLog,
        sessionContext: SessionExecutionContext,
        bridgeClientStreamID: UInt32? = nil
    ) {
        self.host = host
        self.scheme = scheme
        self.direction = direction
        self.bridgeClientStreamID = bridgeClientStreamID
        let matchedSet = policy.set(for: host)
        let urlPrefix = MITMGateRegex.urlPrefix(scheme: scheme, host: host)
        let reachableRules = matchedSet?.rules.filter { $0.gate.mayMatch(urlPrefix: urlPrefix) } ?? []
        self.rules = reachableRules.filter { $0.phase == direction }
        self.responseBodyGateRules = direction == .httpRequest
            ? reachableRules.filter { $0.phase == .httpResponse }
            : []
        self.ruleSetID = matchedSet?.id
        self.effectiveAuthority = effectiveAuthority
        self.requestLog = requestLog
        self.sessionContext = sessionContext
    }

    // MARK: - State

    private struct PendingHead {
        let startLine: String
        let headers: [Header]
        let codec: MITMBodyCodec.Plan
        let originatingRequest: MITMRequestLog.Record?
    }

    private struct StreamingState: Sendable {
        let headers: [Header]
        let originatingRequest: MITMRequestLog.Record?
        let startLine: String
        var frameIndex: Int = 0
        var pendingChunk: Data? = nil
        var lineScanCursor: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
    }

    private enum StreamingPostFrame {
        case hold(nextPending: Data?, inner: StreamingChunkedInner)
        case finalThenTrailer
        case bypassRemainder(left: Int)
    }

    private enum StreamingChunkedInner {
        case sizeLine
        case chunkData(remaining: Int)
        case dataCRLF
        case trailerOrEnd
    }

    private enum Mode {
        case awaitingHead
        case forwardingLength(remaining: Int)
        case forwardingChunked(reader: ChunkedReader)
        case bridgeForwardUntilClose
        case rewritingLength(pending: PendingHead, expected: Int)
        case rewritingChunked(pending: PendingHead, reader: ChunkedReader)
        case rewritingUntilClose(pending: PendingHead)
        case discardingChunked(reader: ChunkedReader)
        case discardingLength(remaining: Int)
        case draining
        case streamingChunked(streaming: StreamingState, inner: StreamingChunkedInner)
        case passthrough
        case awaitingScript
        case awaitingGates
    }

    private var mode: Mode = .awaitingHead

    private enum ResumeMode: Sendable {
        case awaitingHead
        case passthrough

        var mode: Mode {
            switch self {
            case .awaitingHead: return .awaitingHead
            case .passthrough: return .passthrough
            }
        }
    }

    private enum RewriteSelection {
        case none
        case transparent(line: String, replacement: ReplacementURL)
        case synthesize(MITMScriptEngine.SynthesizedResponse)
    }

    private struct PendingGateTables {
        var rewriteTable: MITMGateVerdictTable?
        var rewriteSelection: (url: String?, selection: RewriteSelection)?
        var ruleTable: MITMGateVerdictTable?
        var responseGateTable: MITMGateVerdictTable?
    }

    private var pendingGateTables = PendingGateTables()

    private struct HeadGates {
        let rewriteSelection: RewriteSelection
        let ruleTable: MITMGateVerdictTable
        let responseGateTable: MITMGateVerdictTable
    }

    weak var responseIRSink: MITMHTTP1ResponseIRSink?

    private var parkedContinuation: CheckedContinuation<Data, Never>?

    private var pendingHop: Task<Void, Never>?

    private var pendingPreParkOutput = Data()

    private enum Phase: PhaseTransitionable {
        case open, torn

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.open, .torn):
                return true
            default:
                return false
            }
        }
    }

    private var phase: Phase = .open

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        Phase.transition(&phase, to: new)
    }

    private var forcePassthroughPending = false
    private var receiveBuffer = MITMByteBuffer()

    private var bodyAccumulator = Data()
    private var chunkAccumulator = Data()

    private func takeBodyAccumulator() -> Data {
        defer { bodyAccumulator = Data() }
        return bodyAccumulator
    }

    private func takeChunkAccumulator() -> Data {
        defer { chunkAccumulator = Data() }
        return chunkAccumulator
    }

    private var headScanned: Int = 0

    private var verbatimHead: (startLine: String, headers: [Header], bytes: Data)?

    private var pendingClientBytes = Data()

    private var pendingSynthesizedAfterCurrentResponse = Data()

    private var hasRewriteRule: Bool {
        rules.contains { rule in
            if case .rewrite = rule.operation { return true }
            return false
        }
    }

    var isBetweenMessages: Bool {
        guard case .awaitingHead = mode else { return false }
        return receiveBuffer.isEmpty
            && parkedContinuation == nil
            && !forcePassthroughPending
            && pendingSynthesizedAfterCurrentResponse.isEmpty
    }

    // MARK: - Public API

    func transform(_ data: Data) async -> Data {
        await withCheckedContinuation { transformOnQueue(data, continuation: $0) }
    }

    private func transformOnQueue(_ data: Data, continuation: CheckedContinuation<Data, Never>) {
        guard parkedContinuation == nil else { return failClosedReentry(continuation) }
        if phase == .torn {
            continuation.resume(returning: Data())
            return
        }
        if case .passthrough = mode {
            continuation.resume(returning: data)
            return
        }
        parkedContinuation = continuation
        var output = Data()
        var unread = forwardLengthDirectly(data, into: &output)
        guard phase != .torn else { return }
        unread = forwardChunkedDirectly(unread, into: &output)
        guard phase != .torn else { return }
        if !unread.isEmpty { receiveBuffer.append(unread) }
        while drive(into: &output) { }
        finishDrivePass(output)
    }

    private func finishDrivePass(_ output: Data) {
        switch mode {
        case .awaitingScript, .awaitingGates:
            pendingPreParkOutput = output
            return
        default:
            break
        }
        let continuation = parkedContinuation
        parkedContinuation = nil
        continuation?.resume(returning: output)
    }

    func markTorn() {
        guard transition(to: .torn) else { return }
        pendingHop?.cancel()
        pendingHop = nil
        let continuation = parkedContinuation
        parkedContinuation = nil
        pendingPreParkOutput = Data()
        mode = .passthrough
        receiveBuffer = MITMByteBuffer()
        bodyAccumulator = Data()
        chunkAccumulator = Data()
        verbatimHead = nil
        pendingGateTables = PendingGateTables()
        forcePassthroughPending = false
        pendingClientBytes.removeAll(keepingCapacity: false)
        pendingSynthesizedAfterCurrentResponse.removeAll(keepingCapacity: false)
        continuation?.resume(returning: Data())
    }

    func forcePassthrough() -> Data {
        guard parkedContinuation == nil else {
            forcePassthroughPending = true
            return Data()
        }
        if case .passthrough = mode { return Data() }
        let buffered = receiveBuffer.prefix(receiveBuffer.count)
        receiveBuffer.removeAll(keepingCapacity: false)
        headScanned = 0
        mode = .passthrough
        return buffered
    }

    private func resumeIntoForcedPassthroughIfNeeded() -> Bool {
        guard forcePassthroughPending else { return false }
        forcePassthroughPending = false
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        receiveBuffer.appendPrefix(receiveBuffer.count, to: &resumed)
        receiveBuffer.removeAll(keepingCapacity: false)
        headScanned = 0
        mode = .passthrough
        finishDrivePass(resumed)
        return true
    }

    private func failClosedReentry(_ continuation: CheckedContinuation<Data, Never>) {
        logger.error("\(logPrefix): Reentrant transform")
        continuation.resume(returning: Data())
    }

    nonisolated func drainPendingClientBytes() -> Data {
        assumeIsolated { $0.drainPendingClientBytesOnQueue() }
    }

    private func drainPendingClientBytesOnQueue() -> Data {
        let bytes = pendingClientBytes
        pendingClientBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    func finish() async -> Data {
        await withCheckedContinuation { finishOnQueue(continuation: $0) }
    }

    private func finishOnQueue(continuation: CheckedContinuation<Data, Never>) {
        guard parkedContinuation == nil else { return failClosedReentry(continuation) }
        if responseIRSink != nil {
            switch mode {
            case .bridgeForwardUntilClose:
                _ = emitBridgeBody(Data(), endStream: true)
                mode = .draining
                continuation.resume(returning: Data())
                return
            case .forwardingLength, .forwardingChunked, .rewritingLength, .rewritingChunked:
                responseIRSink?.http1ResponseReset()
                mode = .draining
                continuation.resume(returning: Data())
                return
            case .rewritingUntilClose:
                break
            default:
                continuation.resume(returning: Data())
                return
            }
        }
        guard case .rewritingUntilClose(let pending) = mode else {
            continuation.resume(returning: Data())
            return
        }
        parkedContinuation = continuation
        var output = Data()
        let parked = applyScriptsAndEmit(
            pending: pending,
            rawBody: takeBodyAccumulator(),
            originalSizes: nil,
            resumeMode: .passthrough,
            into: &output
        )
        if parked {
            pendingPreParkOutput = output
            return
        }
        finishDrivePass(output)
    }

    private func flushSynthesizedAfterResponse(into output: inout Data) {
        if direction == .httpResponse {
            pendingSynthesizedAfterCurrentResponse.append(requestLog.closeHTTP1Response())
        }
        if !pendingSynthesizedAfterCurrentResponse.isEmpty {
            output.append(pendingSynthesizedAfterCurrentResponse)
            pendingSynthesizedAfterCurrentResponse.removeAll(keepingCapacity: false)
        }
    }

    // MARK: - Driver

    private func drive(into output: inout Data) -> Bool {
        switch mode {
        case .passthrough:
            if bridgeResetIfNeeded() { return false }
            receiveBuffer.appendPrefix(receiveBuffer.count, to: &output)
            receiveBuffer.removeAll(keepingCapacity: false)
            return false

        case .bridgeForwardUntilClose:
            guard !receiveBuffer.isEmpty else { return false }
            _ = emitBridgeBody(Data(receiveBuffer.prefix(receiveBuffer.count)), endStream: false)
            receiveBuffer.removeAll(keepingCapacity: false)
            return false

        case .awaitingScript, .awaitingGates:
            return false

        case .awaitingHead:
            return consumeHead(into: &output)

        case .forwardingLength(let remaining):
            return forwardLength(remaining: remaining, into: &output)

        case .forwardingChunked(var reader):
            mode = .forwardingChunked(reader: reader)
            return forwardChunked(reader: &reader, into: &output)

        case .rewritingLength(let pending, let expected):
            return rewriteLength(pending: pending, expected: expected, into: &output)

        case .rewritingChunked(let pending, let reader):
            return rewriteChunked(pending: pending, reader: reader, into: &output)

        case .rewritingUntilClose(let pending):
            return rewriteUntilClose(pending: pending, into: &output)

        case .discardingChunked(var reader):
            mode = .discardingChunked(reader: reader)
            return discardChunked(reader: &reader)

        case .discardingLength(let remaining):
            return discardLength(remaining: remaining)

        case .draining:
            receiveBuffer.removeAll(keepingCapacity: false)
            return false

        case .streamingChunked(var streaming, let inner):
            mode = .streamingChunked(streaming: streaming, inner: inner)
            return driveStreamingChunked(streaming: &streaming, inner: inner, into: &output)
        }
    }

    // MARK: - Head consumption

    private func consumeHead(into output: inout Data) -> Bool {
        while receiveBuffer.count >= 2, receiveBuffer[0] == 0x0D, receiveBuffer[1] == 0x0A {
            output.append(contentsOf: [0x0D, 0x0A])
            receiveBuffer.removeFirst(2)
            headScanned = 0
        }
        let headTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A])
        let searchFrom = max(0, headScanned - (headTerminator.count - 1))
        guard let terminator = receiveBuffer.range(of: headTerminator, from: searchFrom) else {
            if receiveBuffer.count > Self.maxHeadBytes {
                logger.warning("\(logPrefix): Head too large")
                receiveBuffer.removeAll(keepingCapacity: false)
                headScanned = 0
                mode = .draining
                delegate?.http1StreamFatalClose(self)
                return false
            }
            headScanned = receiveBuffer.count
            return false
        }
        headScanned = 0
        let headEnd = terminator.upperBound
        guard headEnd <= Self.maxHeadBytes else {
            logger.warning("\(logPrefix): Head too large")
            receiveBuffer.removeAll(keepingCapacity: false)
            mode = .draining
            delegate?.http1StreamFatalClose(self)
            return false
        }
        let headData = receiveBuffer.subdata(in: 0..<headEnd)

        let parsed: ParsedHead
        switch parseHead(headData) {
        case .ok(let parsedHead):
            parsed = parsedHead
            verbatimHead = parsedHead.verbatim.map { (startLine: parsedHead.startLine, headers: parsedHead.headers, bytes: $0) }
        case .forward:
            receiveBuffer.removeFirst(headEnd)
            mode = .passthrough
            output.append(headData)
            return true
        case .smuggling:
            receiveBuffer.removeFirst(headEnd)
            logger.warning("\(logPrefix): Invalid message framing")
            mode = .draining
            delegate?.http1StreamFatalClose(self)
            return false
        }

        guard let gates = ensureGateTables(parsed: parsed) else { return false }
        receiveBuffer.removeFirst(headEnd)
        pendingGateTables = PendingGateTables()

        let rewrittenStartLine: String
        if direction == .httpRequest, hasRewriteRule {
            effectiveAuthority = nil
            resolvedUpstreamValue = nil
        }
        switch gates.rewriteSelection {
        case .none:
            rewrittenStartLine = parsed.startLine
        case .transparent(let line, let replacement):
            effectiveAuthority = replacement.authority
            resolvedUpstreamValue = (host: replacement.host, port: replacement.port)
            rewrittenStartLine = line
        case .synthesize(let response):
            return synthesizeRequestResponse(
                response,
                requestHeaders: parsed.headers,
                into: &output
            )
        }

        if direction == .httpRequest {
            let originalParts = parsed.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            currentRequestOriginalURL = originalParts.count >= 2 ? "\(scheme)://\(host)\(String(originalParts[1]))" : nil
        }

        let originatingRequest: MITMRequestLog.Record?
        if direction == .httpResponse {
            if isInterimResponseStartLine(rewrittenStartLine) {
                originatingRequest = requestLog.peekHTTP1()
            } else {
                let popped = requestLog.popHTTP1()
                originatingRequest = popped
                if let popped, !popped.synthesizedAfter.isEmpty {
                    pendingSynthesizedAfterCurrentResponse.append(popped.synthesizedAfter)
                }
            }
        } else {
            originatingRequest = nil
        }

        let withAuthority = applyAuthorityRewrite(parsed.headers)
        var rewrittenHeaders = applyHeaderRules(withAuthority, verdicts: gates.ruleTable)
        if direction == .httpRequest,
           MITMScriptTransform.hasBodyAccessingRule(in: responseBodyGateRules, verdicts: gates.responseGateTable) {
            rewrittenHeaders = rewrittenHeaders.map { entry in
                ASCII.equalsIgnoringCase(entry.name, "accept-encoding")
                    ? (name: entry.name, value: MITMBodyCodec.constrainedAcceptEncoding(entry.value))
                    : entry
            }
        }

        let framing = bodyFraming(
            startLine: rewrittenStartLine,
            headers: rewrittenHeaders,
            originatingMethod: originatingRequest?.method
        )

        let scriptsApply = MITMScriptTransform.hasScriptRule(in: rules, verdicts: gates.ruleTable)
        let buffersBody = scriptsApply
            || MITMScriptTransform.hasBodyReplaceRule(in: rules, verdicts: gates.ruleTable)
            || MITMScriptTransform.hasBodyJSONRule(in: rules, verdicts: gates.ruleTable)

        switch framing {
        case .switchingProtocols, .readUntilClose:
            if case .readUntilClose = framing, buffersBody,
               !MITMScriptTransform.hasStreamScriptRule(in: rules, verdicts: gates.ruleTable) {
                let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
                let hasContentCodedTransferEncoding = Self.transferEncodingHasContentCoding(combinedHeaderValue(rewrittenHeaders, name: "transfer-encoding"))
                if codec.isSupported, !codec.requiresDecompression, !hasContentCodedTransferEncoding {
                    warnIfBufferedScriptDeStreams(rewrittenHeaders)
                    var headers = rewrittenHeaders.filter {
                        !ASCII.equalsIgnoringCase($0.name, "connection")
                    }
                    headers.append((name: "Connection", value: "close"))
                    bodyAccumulator = Data()
                    mode = .rewritingUntilClose(
                        pending: PendingHead(
                            startLine: rewrittenStartLine,
                            headers: headers,
                            codec: codec,
                            originatingRequest: originatingRequest
                        )
                    )
                    return true
                }
                if hasContentCodedTransferEncoding {
                    logger.warning("\(logPrefix): Unsupported Transfer-Encoding for rewrite")
                }
            }
            if direction == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            let finalHeaders: [Header]
            if case .readUntilClose = framing {
                var headers = rewrittenHeaders.filter {
                    !ASCII.equalsIgnoringCase($0.name, "connection")
                }
                headers.append((name: "Connection", value: "close"))
                finalHeaders = headers
            } else {
                finalHeaders = rewrittenHeaders
            }
            if responseIRSink != nil {
                if case .switchingProtocols = framing {
                    _ = bridgeResetIfNeeded()
                    return false
                }
                emitResponseHead(startLine: rewrittenStartLine, headers: finalHeaders, bodyFollows: true, into: &output)
                mode = .bridgeForwardUntilClose
                return true
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: finalHeaders))
            flushSynthesizedAfterResponse(into: &output)
            mode = .passthrough
            if case .switchingProtocols = framing {
                delegate?.http1StreamDidUpgrade(self)
            }
            return true
        case .none, .contentLength, .chunked:
            break
        }

        switch framing {
        case .none:
            let runScripts = scriptsApply && !isInterimResponseStartLine(rewrittenStartLine)
            if runScripts {
                let message = buildMessage(
                    startLine: rewrittenStartLine,
                    headers: rewrittenHeaders,
                    body: Data(),
                    originatingRequest: originatingRequest
                )
                let fallback = rewrittenStartLine
                let originatingMethod = originatingRequest?.method
                mode = .awaitingScript
                let rules = self.rules
                pendingHop = Task { [weak self] in
                    let outcome = await MITMScriptTransform.apply(message, rules: rules)
                    guard let self else { return }
                    self.sessionContext.enqueue {
                        self.assumeIsolated {
                            $0.resumeHeadNoBody(
                                outcome: outcome,
                                fallbackStartLine: fallback,
                                originatingMethod: originatingMethod
                            )
                        }
                    }
                }
                return false
            }
            if direction == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            if let sink = responseIRSink, isInterimResponseStartLine(rewrittenStartLine) {
                sink.http1ResponseInterim(
                    status: responseStatusCode(from: rewrittenStartLine) ?? 0,
                    headers: rewrittenHeaders
                )
                mode = .awaitingHead
                return true
            }
            emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: false, into: &output)
            flushSynthesizedAfterResponse(into: &output)
            mode = .awaitingHead
            return true
        case .contentLength(let length):
            return enterContentLength(
                rewrittenStartLine: rewrittenStartLine,
                rewrittenHeaders: rewrittenHeaders,
                length: length,
                buffersBody: buffersBody,
                verdicts: gates.ruleTable,
                originatingRequest: originatingRequest,
                into: &output
            )
        case .chunked:
            return enterChunked(
                rewrittenStartLine: rewrittenStartLine,
                rewrittenHeaders: rewrittenHeaders,
                buffersBody: buffersBody,
                verdicts: gates.ruleTable,
                originatingRequest: originatingRequest,
                into: &output
            )
        case .readUntilClose, .switchingProtocols:
            return true
        }
    }

    private func ensureGateTables(parsed: ParsedHead) -> HeadGates? {
        if rules.isEmpty && responseBodyGateRules.isEmpty {
            return HeadGates(rewriteSelection: .none, ruleTable: .empty, responseGateTable: .empty)
        }
        let rewriteURL = requestURLForGating(
            startLine: parsed.startLine,
            originatingRequest: direction == .httpResponse ? requestLog.peekHTTP1() : nil
        )
        guard let rewriteTable = obtainTable(\.rewriteTable, rules: rules, url: rewriteURL) else { return nil }

        let selection: RewriteSelection
        if let cached = pendingGateTables.rewriteSelection, cached.url == rewriteURL {
            selection = cached.selection
        } else {
            selection = selectRewrite(parsed.startLine, verdicts: rewriteTable)
            pendingGateTables.rewriteSelection = (url: rewriteURL, selection: selection)
        }

        let postURL: String?
        switch selection {
        case .none:
            postURL = rewriteURL
        case .transparent(let line, _):
            postURL = requestURLForGating(startLine: line, originatingRequest: nil)
        case .synthesize:
            return HeadGates(rewriteSelection: selection, ruleTable: .empty, responseGateTable: .empty)
        }
        let ruleTable: MITMGateVerdictTable
        if postURL == rewriteURL {
            ruleTable = rewriteTable
        } else {
            guard let resolved = obtainTable(\.ruleTable, rules: rules, url: postURL) else { return nil }
            ruleTable = resolved
        }
        guard direction == .httpRequest, !responseBodyGateRules.isEmpty else {
            return HeadGates(rewriteSelection: selection, ruleTable: ruleTable, responseGateTable: .empty)
        }
        guard let responseGateTable = obtainTable(\.responseGateTable, rules: responseBodyGateRules, url: postURL)
        else { return nil }
        return HeadGates(rewriteSelection: selection, ruleTable: ruleTable, responseGateTable: responseGateTable)
    }

    private func obtainTable(
        _ slot: WritableKeyPath<PendingGateTables, MITMGateVerdictTable?> & Sendable,
        rules: [CompiledMITMRule],
        url: String?
    ) -> MITMGateVerdictTable? {
        if let cached = pendingGateTables[keyPath: slot], cached.url == url {
            return cached
        }
        if let peeked = MITMGateVerdictTable.peek(rules: rules, url: url) {
            pendingGateTables[keyPath: slot] = peeked
            return peeked
        }
        mode = .awaitingGates
        pendingHop = Task { [weak self] in
            let table = await MITMGateVerdictTable.resolve(rules: rules, url: url)
            guard let self else { return }
            self.sessionContext.enqueue {
                self.assumeIsolated { $0.resumeGateResolution(slot: slot, table: table) }
            }
        }
        return nil
    }

    private func resumeGateResolution(
        slot: WritableKeyPath<PendingGateTables, MITMGateVerdictTable?> & Sendable,
        table: MITMGateVerdictTable
    ) {
        guard phase != .torn else { return }
        pendingGateTables[keyPath: slot] = table
        guard case .awaitingGates = mode else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        mode = .awaitingHead
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    private func enterContentLength(
        rewrittenStartLine: String,
        rewrittenHeaders: [Header],
        length: Int,
        buffersBody: Bool,
        verdicts: MITMGateVerdictTable,
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        let rewrittenHeaders = rewrittenHeaders.filter { !ASCII.equalsIgnoringCase($0.name, "transfer-encoding") }
        if MITMScriptTransform.hasStreamScriptRule(in: rules, verdicts: verdicts) {
            logger.warning("[MITM] \(host): streamScript unsupported for Content-Length body")
        }

        let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
        let canRewrite = buffersBody && codec.isSupported && length <= MITMBodyCodec.maxBufferedBodyBytes

        if canRewrite {
            let headers = handleExpectContinue(startLine: rewrittenStartLine, headers: rewrittenHeaders)
            bodyAccumulator = Data()
            mode = .rewritingLength(
                pending: PendingHead(
                    startLine: rewrittenStartLine,
                    headers: headers,
                    codec: codec,
                    originatingRequest: originatingRequest
                ),
                expected: length
            )
            return true
        }
        if buffersBody, length > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] \(host): Body too large for rewrite")
        }
        if direction == .httpRequest {
            logRequest(startLine: rewrittenStartLine)
        }
        emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: true, into: &output)
        mode = .forwardingLength(remaining: length)
        return true
    }

    private func enterChunked(
        rewrittenStartLine: String,
        rewrittenHeaders: [Header],
        buffersBody: Bool,
        verdicts: MITMGateVerdictTable,
        originatingRequest: MITMRequestLog.Record?,
        into output: inout Data
    ) -> Bool {
        let rewrittenHeaders = rewrittenHeaders.filter { !ASCII.equalsIgnoringCase($0.name, "content-length") }
        if MITMScriptTransform.hasStreamScriptRule(in: rules, verdicts: verdicts) {
            if responseIRSink != nil {
                logger.warning("[MITM] \(host): streamScript unsupported on bridged response")
                emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: true, into: &output)
                mode = .forwardingChunked(reader: ChunkedReader())
                return true
            }
            if buffersBody {
                logger.warning("[MITM] \(host): Body rule conflicts with streamScript")
            }
            if direction == .httpRequest {
                logRequest(startLine: rewrittenStartLine)
            }
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            let streaming = StreamingState(
                headers: rewrittenHeaders,
                originatingRequest: originatingRequest,
                startLine: rewrittenStartLine,
                cursor: MITMScriptTransform.makeFrameCursor(rules: rules, verdicts: verdicts)
            )
            mode = .streamingChunked(streaming: streaming, inner: .sizeLine)
            return true
        }

        let codec = MITMBodyCodec.plan(for: combinedHeaderValue(rewrittenHeaders, name: "content-encoding"))
        let hasContentCodedTransferEncoding = Self.transferEncodingHasContentCoding(combinedHeaderValue(rewrittenHeaders, name: "transfer-encoding"))
        if buffersBody, codec.isSupported, !hasContentCodedTransferEncoding {
            warnIfBufferedScriptDeStreams(rewrittenHeaders)
            let headers = handleExpectContinue(startLine: rewrittenStartLine, headers: rewrittenHeaders)
            bodyAccumulator = Data()
            mode = .rewritingChunked(
                pending: PendingHead(
                    startLine: rewrittenStartLine,
                    headers: headers,
                    codec: codec,
                    originatingRequest: originatingRequest
                ),
                reader: ChunkedReader()
            )
            return true
        }
        if buffersBody, hasContentCodedTransferEncoding {
            logger.warning("\(logPrefix): Unsupported Transfer-Encoding for rewrite")
        }
        if direction == .httpRequest {
            logRequest(startLine: rewrittenStartLine)
        }
        emitResponseHead(startLine: rewrittenStartLine, headers: rewrittenHeaders, bodyFollows: true, into: &output)
        mode = .forwardingChunked(reader: ChunkedReader())
        return true
    }

    private func handleExpectContinue(startLine: String, headers: [Header]) -> [Header] {
        guard direction == .httpRequest, startLine.hasSuffix(" HTTP/1.1") else { return headers }
        let expectsContinue = headers.contains { entry in
            ASCII.equalsIgnoringCase(entry.name, "expect")
                && ASCII.equalsIgnoringCase(
                    entry.value.trimmingCharacters(in: CharacterSet.whitespaces),
                    "100-continue"
                )
        }
        guard expectsContinue else { return headers }
        let interim = serializeHead(startLine: "HTTP/1.1 100 Continue", headers: [])
        if requestLog.isHTTP1QueueEmpty {
            pendingClientBytes.append(interim)
        } else {
            requestLog.attachSynthesizedAfterLastHTTP1(interim)
        }
        return headers.filter { !ASCII.equalsIgnoringCase($0.name, "expect") }
    }

    // MARK: - Body forwarding (no rewrite)

    private func forwardLength(remaining: Int, into output: inout Data) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        let take = min(remaining, receiveBuffer.count)
        let left = remaining - take
        if responseIRSink != nil {
            let slice = receiveBuffer.prefix(take)
            receiveBuffer.removeFirst(take)
            _ = emitBridgeBody(slice, endStream: left == 0)
        } else {
            receiveBuffer.appendPrefix(take, to: &output)
            receiveBuffer.removeFirst(take)
        }
        finishForwardedLength(left: left, into: &output)
        return true
    }

    private func forwardLengthDirectly(_ data: Data, into output: inout Data) -> Data {
        guard receiveBuffer.isEmpty, !data.isEmpty, case .forwardingLength(let remaining) = mode else { return data }
        let take = min(remaining, data.count)
        let left = remaining - take
        let body = data.prefix(take)
        if !emitBridgeBody(body, endStream: left == 0) {
            if output.isEmpty { output = body } else { output.append(body) }
        }
        finishForwardedLength(left: left, into: &output)
        return take == data.count ? Data() : data.suffix(from: data.startIndex + take)
    }

    private func finishForwardedLength(left: Int, into output: inout Data) {
        if left == 0 {
            flushSynthesizedAfterResponse(into: &output)
            mode = .awaitingHead
        } else {
            mode = .forwardingLength(remaining: left)
        }
    }

    private func forwardChunked(reader: inout ChunkedReader, into output: inout Data) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        let result: ChunkedReader.ForwardResult
        if let sink = responseIRSink {
            var slices: [Data] = []
            result = reader.consumeForwardIR(&receiveBuffer) { slices.append($0) }
            for slice in slices {
                sink.http1ResponseBody(slice, endStream: false)
                if phase == .torn { return false }
            }
        } else {
            result = reader.consumeForward(&receiveBuffer, into: &output)
        }
        return finishForwardedChunked(result, reader: reader, into: &output)
    }

    private func forwardChunkedDirectly(_ data: Data, into output: inout Data) -> Data {
        guard receiveBuffer.isEmpty, !data.isEmpty, case .forwardingChunked(let reader) = mode else { return data }
        let sink = responseIRSink
        var bodyRanges: [Range<Data.Index>] = []
        let scan = reader.scanForward(data, onData: sink == nil ? nil : { bodyRanges.append($0) })
        if let sink {
            for range in bodyRanges where !range.isEmpty {
                sink.http1ResponseBody(data.subdata(in: range), endStream: false)
                if phase == .torn { return Data() }
            }
        } else if scan.consumed > 0 {
            let forwarded = data.prefix(scan.consumed)
            if output.isEmpty { output = forwarded } else { output.append(forwarded) }
        }
        _ = finishForwardedChunked(scan.result, reader: reader, into: &output)
        return scan.consumed == data.count ? Data() : data.suffix(from: data.startIndex + scan.consumed)
    }

    private func finishForwardedChunked(_ result: ChunkedReader.ForwardResult, reader: ChunkedReader, into output: inout Data) -> Bool {
        switch result {
        case .needMore:
            mode = .forwardingChunked(reader: reader)
            return false
        case .complete:
            if emitBridgeBody(Data(), endStream: true) {
                mode = .awaitingHead
                return true
            }
            flushSynthesizedAfterResponse(into: &output)
            mode = .awaitingHead
            return true
        case .malformed:
            if bridgeResetIfNeeded() { return false }
            logger.warning("\(logPrefix): Malformed chunked body")
            receiveBuffer.removeAll(keepingCapacity: false)
            mode = .draining
            delegate?.http1StreamHardClose(self)
            return true
        }
    }

    // MARK: - Body rewriting

    private func rewriteLength(
        pending: PendingHead,
        expected: Int,
        into output: inout Data
    ) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        let needed = expected - bodyAccumulator.count
        let take = min(needed, receiveBuffer.count)
        receiveBuffer.appendPrefix(take, to: &bodyAccumulator)
        receiveBuffer.removeFirst(take)
        if bodyAccumulator.count == expected {
            let parked = applyScriptsAndEmit(
                pending: pending,
                rawBody: takeBodyAccumulator(),
                originalSizes: nil,
                resumeMode: .awaitingHead,
                into: &output
            )
            return !parked
        }
        return false
    }

    private func rewriteChunked(
        pending: PendingHead,
        reader: ChunkedReader,
        into output: inout Data
    ) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        let result = reader.consumeBuffered(&receiveBuffer, into: &bodyAccumulator)
        switch result {
        case .needMore:
            if bodyAccumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                logger.warning("[MITM] \(host): Body too large for rewrite")
                mode = .draining
                delegate?.http1StreamFatalClose(self)
                return false
            }
            return false
        case .complete(let originalSizes):
            let parked = applyScriptsAndEmit(
                pending: pending,
                rawBody: takeBodyAccumulator(),
                originalSizes: originalSizes,
                resumeMode: .awaitingHead,
                into: &output
            )
            return !parked
        case .malformed:
            if bridgeResetIfNeeded() { return false }
            logger.warning("\(logPrefix): Malformed chunked body")
            mode = .draining
            delegate?.http1StreamFatalClose(self)
            return true
        }
    }

    private func rewriteUntilClose(
        pending: PendingHead,
        into output: inout Data
    ) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        receiveBuffer.appendPrefix(receiveBuffer.count, to: &bodyAccumulator)
        receiveBuffer.removeAll(keepingCapacity: false)
        if bodyAccumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] \(host): Body too large for rewrite")
            if bridgeResetIfNeeded() { return false }
            output.append(serializeHead(startLine: pending.startLine, headers: pending.headers))
            output.append(takeBodyAccumulator())
            flushSynthesizedAfterResponse(into: &output)
            mode = .passthrough
            return true
        }
        return false
    }

    private func driveStreamingChunked(
        streaming: inout StreamingState,
        inner startInner: StreamingChunkedInner,
        into output: inout Data
    ) -> Bool {
        var currentInner = startInner
        while true {
            switch currentInner {
            case .sizeLine:
                guard let lineEnd = receiveBuffer.firstCRLF(from: streaming.lineScanCursor) else {
                    if receiveBuffer.count > Self.maxChunkLineBytes {
                        logger.warning("\(logPrefix): Malformed chunked body")
                        receiveBuffer.removeAll(keepingCapacity: false)
                        mode = .draining
                        delegate?.http1StreamHardClose(self)
                        return true
                    }
                    streaming.lineScanCursor = max(0, receiveBuffer.count - 1)
                    mode = .streamingChunked(streaming: streaming, inner: .sizeLine)
                    return false
                }
                let parsedSize = receiveBuffer.withUnsafeBytes(in: 0..<lineEnd, Self.parseHexSize)
                receiveBuffer.removeFirst(lineEnd + 2)
                streaming.lineScanCursor = 0
                guard let size = parsedSize else {
                    logger.warning("\(logPrefix): Malformed chunked body")
                    receiveBuffer.removeAll(keepingCapacity: false)
                    mode = .draining
                    delegate?.http1StreamHardClose(self)
                    return true
                }
                if size == 0 {
                    let finalChunk = streaming.pendingChunk ?? Data()
                    streaming.pendingChunk = nil
                    if emitOrParkStreamingFrame(
                        streaming: &streaming,
                        chunk: finalChunk,
                        isLast: true,
                        postFrame: .finalThenTrailer,
                        into: &output
                    ) {
                        return false
                    }
                    output.append(contentsOf: "0\r\n".utf8)
                    currentInner = .trailerOrEnd
                } else {
                    chunkAccumulator = Data()
                    currentInner = .chunkData(remaining: size)
                }
            case .chunkData(let remaining):
                guard !receiveBuffer.isEmpty else {
                    mode = .streamingChunked(streaming: streaming, inner: .chunkData(remaining: remaining))
                    return false
                }
                let take = min(remaining, receiveBuffer.count)
                receiveBuffer.appendPrefix(take, to: &chunkAccumulator)
                receiveBuffer.removeFirst(take)
                let left = remaining - take
                if left != 0, chunkAccumulator.count > MITMBodyCodec.maxBufferedBodyBytes {
                    logger.warning("[MITM] \(host): Chunk too large for rewrite")
                    if let held = streaming.pendingChunk {
                        streaming.pendingChunk = nil
                        if emitOrParkStreamingFrame(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            postFrame: .bypassRemainder(left: left),
                            into: &output
                        ) {
                            return false
                        }
                    }
                    streaming.cursor.mutable.withLock { $0.isBypassed = true }
                    appendChunk(takeChunkAccumulator(), into: &output)
                    mode = .streamingChunked(streaming: streaming, inner: .chunkData(remaining: left))
                    return false
                }
                if left == 0 {
                    let completed = takeChunkAccumulator()
                    if let held = streaming.pendingChunk {
                        if emitOrParkStreamingFrame(
                            streaming: &streaming,
                            chunk: held,
                            isLast: false,
                            postFrame: .hold(nextPending: completed, inner: .dataCRLF),
                            into: &output
                        ) {
                            return false
                        }
                    }
                    streaming.pendingChunk = completed
                    currentInner = .dataCRLF
                } else {
                    mode = .streamingChunked(streaming: streaming, inner: .chunkData(remaining: left))
                    return false
                }
            case .dataCRLF:
                guard receiveBuffer.count >= 2 else {
                    mode = .streamingChunked(streaming: streaming, inner: .dataCRLF)
                    return false
                }
                guard receiveBuffer[0] == 0x0D,
                      receiveBuffer[1] == 0x0A
                else {
                    logger.warning("\(logPrefix): Malformed chunked body")
                    receiveBuffer.removeAll(keepingCapacity: false)
                    mode = .draining
                    delegate?.http1StreamHardClose(self)
                    return true
                }
                receiveBuffer.removeFirst(2)
                currentInner = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = receiveBuffer.firstCRLF(from: streaming.lineScanCursor) else {
                    if receiveBuffer.count > Self.maxChunkLineBytes {
                        logger.warning("\(logPrefix): Malformed chunked body")
                        receiveBuffer.removeAll(keepingCapacity: false)
                        mode = .draining
                        delegate?.http1StreamHardClose(self)
                        return true
                    }
                    streaming.lineScanCursor = max(0, receiveBuffer.count - 1)
                    mode = .streamingChunked(streaming: streaming, inner: .trailerOrEnd)
                    return false
                }
                receiveBuffer.appendPrefix(lineEnd + 2, to: &output)
                receiveBuffer.removeFirst(lineEnd + 2)
                streaming.lineScanCursor = 0
                if lineEnd == 0 {
                    flushSynthesizedAfterResponse(into: &output)
                    mode = .awaitingHead
                    return true
                }
            }
        }
    }

    private func emitOrParkStreamingFrame(
        streaming: inout StreamingState,
        chunk: Data,
        isLast: Bool,
        postFrame: StreamingPostFrame,
        into output: inout Data
    ) -> Bool {
        if streaming.cursor.mutable.withLock({ $0.isBypassed }) {
            streaming.frameIndex += 1
            if !chunk.isEmpty {
                appendChunk(chunk, into: &output)
            }
            return false
        }
        let frameContext = MITMScriptEngine.FrameContext(
            phase: direction,
            method: streamingMethod(streaming),
            url: streamingURL(streaming),
            originalURL: streamingOriginalURL(streaming),
            status: streamingStatus(streaming),
            headers: streaming.headers,
            frameIndex: streaming.frameIndex,
            isLast: isLast,
            ruleSetID: ruleSetID
        )
        let captured = streaming
        mode = .awaitingScript
        let cursor = streaming.cursor
        pendingHop = Task { [weak self] in
            let result = await MITMScriptTransform.applyFrame(
                chunk,
                frameContext: frameContext,
                cursor: cursor
            )
            guard let self else { return }
            self.sessionContext.enqueue {
                self.assumeIsolated { $0.resumeStreamingFrame(result: result, streaming: captured, postFrame: postFrame) }
            }
        }
        return true
    }

    private func resumeStreamingFrame(
        result: MITMScriptTransform.StreamFrameResult,
        streaming: StreamingState,
        postFrame: StreamingPostFrame
    ) {
        guard phase != .torn else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        var streaming = streaming
        streaming.frameIndex += 1
        if !result.body.isEmpty {
            appendChunk(result.body, into: &resumed)
        }
        switch postFrame {
        case .hold(let nextPending, let inner):
            streaming.pendingChunk = nextPending
            mode = .streamingChunked(streaming: streaming, inner: inner)
        case .finalThenTrailer:
            resumed.append(contentsOf: "0\r\n".utf8)
            mode = .streamingChunked(streaming: streaming, inner: .trailerOrEnd)
        case .bypassRemainder(let left):
            streaming.cursor.mutable.withLock { $0.isBypassed = true }
            appendChunk(takeChunkAccumulator(), into: &resumed)
            mode = .streamingChunked(streaming: streaming, inner: .chunkData(remaining: left))
        }
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    private func streamingMethod(_ streaming: StreamingState) -> String? {
        switch direction {
        case .httpRequest:
            let parts = streaming.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            return parts.first.map(String.init)
        case .httpResponse:
            return streaming.originatingRequest?.method
        }
    }

    private func streamingURL(_ streaming: StreamingState) -> String? {
        switch direction {
        case .httpRequest:
            let parts = streaming.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 2 else { return nil }
            return "\(scheme)://\(host)\(String(parts[1]))"
        case .httpResponse:
            return streaming.originatingRequest?.url
        }
    }

    private func streamingOriginalURL(_ streaming: StreamingState) -> String? {
        switch direction {
        case .httpRequest:
            return currentRequestOriginalURL
        case .httpResponse:
            return streaming.originatingRequest?.originalURL
        }
    }

    private func streamingStatus(_ streaming: StreamingState) -> Int? {
        guard direction == .httpResponse else { return nil }
        let parts = streaming.startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        return HTTPHeader.parseStatusCode(parts[1])
    }

    fileprivate static func parseHexSize(_ line: UnsafeRawBufferPointer) -> Int? {
        var end = line.firstIndex(of: 0x3B) ?? line.count
        var start = 0
        while start < end, line[start] == 0x20 || line[start] == 0x09 { start += 1 }
        while end > start, line[end - 1] == 0x20 || line[end - 1] == 0x09 { end -= 1 }
        guard start < end else { return nil }
        var size = 0
        for byte in line[start..<end] {
            let digit: Int
            switch byte {
            case 0x30...0x39: digit = Int(byte - 0x30)
            case 0x41...0x46: digit = Int(byte - 0x37)
            case 0x61...0x66: digit = Int(byte - 0x57)
            default: return nil
            }
            guard size <= Int.max >> 4 else { return nil }
            size = size << 4 | digit
        }
        return size
    }

    private func discardLength(remaining: Int) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        let take = min(remaining, receiveBuffer.count)
        receiveBuffer.removeFirst(take)
        let left = remaining - take
        mode = left == 0 ? .awaitingHead : .discardingLength(remaining: left)
        return true
    }

    private func discardChunked(reader: inout ChunkedReader) -> Bool {
        guard !receiveBuffer.isEmpty else { return false }
        let result = reader.consumeForwardIR(&receiveBuffer, deliver: nil)
        switch result {
        case .needMore:
            mode = .discardingChunked(reader: reader)
            return false
        case .complete:
            mode = .awaitingHead
            return true
        case .malformed:
            mode = .draining
            return true
        }
    }

    // MARK: - Script application + head rebuild

    @discardableResult
    private func applyScriptsAndEmit(
        pending: PendingHead,
        rawBody: Data,
        originalSizes: [Int]?,
        resumeMode: ResumeMode,
        into output: inout Data
    ) -> Bool {
        let body: Data
        if pending.codec.requiresDecompression {
            guard let decoded = MITMBodyCodec.decompress(rawBody, plan: pending.codec, host: host) else {
                if responseIRSink != nil {
                    emitResponseHead(startLine: pending.startLine, headers: pending.headers, bodyFollows: !rawBody.isEmpty, into: &output)
                    if !rawBody.isEmpty { _ = emitBridgeBody(rawBody, endStream: true) }
                    mode = resumeMode.mode
                    return false
                }
                if direction == .httpRequest {
                    logRequest(startLine: pending.startLine)
                }
                output.append(serializeHead(startLine: pending.startLine, headers: pending.headers))
                if let originalSizes {
                    output.append(rechunk(body: rawBody, originalSizes: originalSizes))
                } else {
                    output.append(rawBody)
                }
                flushSynthesizedAfterResponse(into: &output)
                mode = resumeMode.mode
                return false
            }
            body = decoded
        } else {
            body = rawBody
        }

        let message = buildMessage(
            startLine: pending.startLine,
            headers: pending.headers,
            body: body,
            originatingRequest: pending.originatingRequest
        )
        let encodedOriginal = pending.codec.requiresDecompression ? (raw: rawBody, decoded: body) : nil
        mode = .awaitingScript
        let rules = self.rules
        pendingHop = Task { [weak self] in
            let outcome = await MITMScriptTransform.apply(message, rules: rules)
            guard let self else { return }
            self.sessionContext.enqueue {
                self.assumeIsolated {
                    $0.resumeBufferedBody(outcome: outcome, pending: pending, encodedOriginal: encodedOriginal, resumeMode: resumeMode)
                }
            }
        }
        return true
    }

    private func resumeBufferedBody(
        outcome: MITMScriptTransform.Outcome,
        pending: PendingHead,
        encodedOriginal: (raw: Data, decoded: Data)?,
        resumeMode: ResumeMode
    ) {
        guard phase != .torn else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        switch outcome {
        case .message(let result):
            let finalStartLine = rebuildStartLine(from: result, fallback: pending.startLine)
            let keptRaw = encodedOriginal.flatMap { original -> Data? in
                let unchanged = result.body == original.decoded
                    && combinedHeaderValue(result.headers, name: "content-encoding")
                        == combinedHeaderValue(pending.headers, name: "content-encoding")
                return unchanged ? original.raw : nil
            }
            let body = keptRaw ?? result.body
            var finalHeaders = strippedFramingHeaders(
                result.headers,
                dropContentEncoding: pending.codec.requiresDecompression && keptRaw == nil
            )
            finalHeaders.append((name: "Content-Length", value: String(body.count)))
            if direction == .httpRequest {
                logRequest(startLine: finalStartLine)
            }
            if responseIRSink != nil {
                emitResponseHead(startLine: finalStartLine, headers: finalHeaders, bodyFollows: !body.isEmpty, into: &resumed)
                if !body.isEmpty { _ = emitBridgeBody(body, endStream: true) }
            } else {
                resumed.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
                if !body.isEmpty {
                    resumed.append(body)
                }
            }
        case .synthesizedResponse(let response):
            if responseIRSink != nil {
                _ = bridgeResetIfNeeded()
                finishDrivePass(resumed)
                return
            }
            queueSynthesizedResponse(response)
        }
        flushSynthesizedAfterResponse(into: &resumed)
        mode = resumeMode.mode
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    private func resumeHeadNoBody(
        outcome: MITMScriptTransform.Outcome,
        fallbackStartLine: String,
        originatingMethod: String?
    ) {
        guard phase != .torn else { return }
        if resumeIntoForcedPassthroughIfNeeded() { return }
        var resumed = pendingPreParkOutput
        pendingPreParkOutput = Data()
        switch outcome {
        case .message(let result):
            emitScriptedHead(
                fallbackStartLine: fallbackStartLine,
                result: result,
                codecRequiresDecompression: false,
                originatingMethod: originatingMethod,
                into: &resumed
            )
        case .synthesizedResponse(let response):
            if responseIRSink != nil {
                _ = bridgeResetIfNeeded()
                finishDrivePass(resumed)
                return
            }
            queueSynthesizedResponse(response)
        }
        flushSynthesizedAfterResponse(into: &resumed)
        mode = .awaitingHead
        while drive(into: &resumed) { }
        finishDrivePass(resumed)
    }

    private func emitScriptedHead(
        fallbackStartLine: String,
        result: HTTPMessage,
        codecRequiresDecompression: Bool,
        originatingMethod: String?,
        into output: inout Data
    ) {
        let finalStartLine = rebuildStartLine(from: result, fallback: fallbackStartLine)
        let isHeadResponse = direction == .httpResponse
            && originatingMethod?.uppercased() == "HEAD"

        let finalHeaders: [Header]
        if isHeadResponse {
            finalHeaders = codecRequiresDecompression
                ? result.headers.filter { !ASCII.equalsIgnoringCase($0.name, "content-encoding") }
                : result.headers
        } else {
            var stripped = strippedFramingHeaders(result.headers, dropContentEncoding: codecRequiresDecompression)
            let preserveNoBody = result.body.isEmpty
                && isNoBodyStatus(responseStatusCode(from: finalStartLine))
            if !preserveNoBody {
                stripped.append((name: "Content-Length", value: String(result.body.count)))
            }
            finalHeaders = stripped
        }

        if direction == .httpRequest {
            logRequest(startLine: finalStartLine)
        }
        let hasBody = !result.body.isEmpty && !isHeadResponse
        if responseIRSink != nil {
            emitResponseHead(startLine: finalStartLine, headers: finalHeaders, bodyFollows: hasBody, into: &output)
            if hasBody { _ = emitBridgeBody(result.body, endStream: true) }
        } else {
            output.append(serializeHead(startLine: finalStartLine, headers: finalHeaders))
            if hasBody {
                output.append(result.body)
            }
        }
    }

    private func isNoBodyStatus(_ status: Int?) -> Bool {
        guard let status else { return false }
        switch status {
        case 204, 304:
            return true
        default:
            return (100..<200).contains(status) && status != 101
        }
    }

    private func responseStatusCode(from startLine: String) -> Int? {
        guard startLine.hasPrefix("HTTP/") else { return nil }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else { return nil }
        return HTTPHeader.parseStatusCode(parts[1])
    }

    private func strippedFramingHeaders(
        _ headers: [Header],
        dropContentEncoding: Bool
    ) -> [Header] {
        headers.filter { entry in
            if ASCII.equalsIgnoringCase(entry.name, "content-length")
                || ASCII.equalsIgnoringCase(entry.name, "transfer-encoding") {
                return false
            }
            if dropContentEncoding, ASCII.equalsIgnoringCase(entry.name, "content-encoding") {
                return false
            }
            return true
        }
    }

    // MARK: - Re-chunking (chunked decompression-failure passthrough only)

    private func rechunk(body: Data, originalSizes: [Int]) -> Data {
        var out = Data()
        var emitted = 0
        let total = body.count

        if originalSizes.count > 1 {
            for size in originalSizes.dropLast() {
                guard emitted < total else { break }
                let take = min(size, total - emitted)
                appendChunk(body.subdata(in: (body.startIndex + emitted)..<(body.startIndex + emitted + take)), into: &out)
                emitted += take
            }
        }
        if emitted < total || originalSizes.count == 1 {
            let remaining = total - emitted
            if remaining > 0 {
                appendChunk(body.subdata(in: (body.startIndex + emitted)..<body.endIndex), into: &out)
            }
        }
        out.append(contentsOf: "0\r\n\r\n".utf8)
        return out
    }

    private func appendChunk(_ data: Data, into out: inout Data) {
        out.append(contentsOf: String(data.count, radix: 16).utf8)
        out.append(contentsOf: [0x0D, 0x0A])
        out.append(data)
        out.append(contentsOf: [0x0D, 0x0A])
    }

    // MARK: - Head parsing

    private typealias Header = (name: String, value: String)

    private struct ParsedHead {
        let startLine: String
        let headers: [Header]
        let verbatim: Data?
    }

    private enum ParsedHeadResult {
        case ok(ParsedHead)
        case forward
        case smuggling
    }

    private enum FieldLine {
        case span(Range<Int>)
        case folded([UInt8])

        func bytes(in head: UnsafeRawBufferPointer) -> [UInt8] {
            switch self {
            case .span(let range): return Array(head[range])
            case .folded(let joined): return joined
            }
        }
    }

    private static let fieldValueOWS = CharacterSet(charactersIn: " \t")

    private func parseHead(_ data: Data) -> ParsedHeadResult {
        data.withUnsafeBytes { parseHead($0, verbatim: data) }
    }

    private func parseHead(_ bytes: UnsafeRawBufferPointer, verbatim: Data) -> ParsedHeadResult {
        var lines: [Range<Int>] = []
        var lineStart = 0
        var index = 0
        while index + 1 < bytes.count {
            if bytes[index] == 0x0D, bytes[index + 1] == 0x0A {
                lines.append(lineStart..<index)
                index += 2
                lineStart = index
            } else {
                index += 1
            }
        }
        lines.append(lineStart..<bytes.count)
        guard let firstLine = lines.first, !firstLine.isEmpty else { return .forward }
        let startLine = Self.latin1String(UnsafeRawBufferPointer(rebasing: bytes[firstLine]))
        guard isHTTPStartLine(startLine) else {
            return parsesStartLine(startLine) ? .forward : .smuggling
        }
        if Self.containsCRorLF(startLine) { return .smuggling }
        guard parsesStartLine(startLine) else { return .smuggling }
        if direction == .httpRequest, isConnectRequestLine(startLine) { return .smuggling }
        var fieldLines: [FieldLine] = []
        var sawFold = false
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            let first = bytes[line.lowerBound]
            if first == 0x20 || first == 0x09 {
                guard let previous = fieldLines.popLast() else { return .smuggling } // continuation with no field
                var contentStart = line.lowerBound
                while contentStart < line.upperBound, bytes[contentStart] == 0x20 || bytes[contentStart] == 0x09 {
                    contentStart += 1
                }
                var joined = previous.bytes(in: bytes)
                joined.append(0x20)
                joined.append(contentsOf: bytes[contentStart..<line.upperBound])
                fieldLines.append(.folded(joined))
                sawFold = true
                continue
            }
            fieldLines.append(.span(line))
        }
        var headers: [Header] = []
        headers.reserveCapacity(fieldLines.count)
        var contentLengthValues: [String] = []
        var transferEncodingValues: [String] = []
        for fieldLine in fieldLines {
            let field: Header?
            switch fieldLine {
            case .span(let range):
                field = Self.parseFieldLine(UnsafeRawBufferPointer(rebasing: bytes[range]))
            case .folded(let joined):
                field = joined.withUnsafeBytes { Self.parseFieldLine($0) }
            }
            guard let (name, value) = field else { return .smuggling }
            guard HTTPHeader.isValidName(name) else { return .smuggling }
            if Self.containsCRorLF(value) { return .smuggling }
            if ASCII.equalsIgnoringCase(name, "content-length") {
                contentLengthValues.append(value)
            } else if ASCII.equalsIgnoringCase(name, "transfer-encoding") {
                transferEncodingValues.append(value)
            }
            headers.append((name: name, value: value))
        }
        if contentLengthValues.contains(where: { !Self.isCleanContentLength($0) }) {
            return .smuggling
        }
        if contentLengthValues.count > 1 {
            return .smuggling
        }
        if !transferEncodingValues.isEmpty {
            if transferEncodingValues.count > 1 { return .smuggling }
            guard startLineIsHTTP11(startLine) else { return .smuggling }
            if direction == .httpResponse, let status = responseStatusCode(from: startLine),
               (100..<200).contains(status) || status == 204 {
                return .smuggling
            }
            guard let transferEncoding = Self.normalizedTransferEncoding(transferEncodingValues[0]) else {
                return .smuggling
            }
            if direction == .httpRequest, !transferEncoding.hasSuffix("chunked") {
                return .smuggling
            }
        }
        if !transferEncodingValues.isEmpty && !contentLengthValues.isEmpty {
            return .smuggling
        }
        return .ok(ParsedHead(startLine: startLine, headers: headers, verbatim: sawFold ? nil : verbatim))
    }

    private static func parseFieldLine(_ line: UnsafeRawBufferPointer) -> Header? {
        guard let colon = line.firstIndex(of: 0x3A) else { return nil }
        var valueStart = colon + 1
        var valueEnd = line.count
        while valueStart < valueEnd, line[valueStart] == 0x20 || line[valueStart] == 0x09 { valueStart += 1 }
        while valueEnd > valueStart, line[valueEnd - 1] == 0x20 || line[valueEnd - 1] == 0x09 { valueEnd -= 1 }
        return (
            name: latin1String(UnsafeRawBufferPointer(rebasing: line[..<colon])),
            value: latin1String(UnsafeRawBufferPointer(rebasing: line[valueStart..<valueEnd]))
        )
    }

    private static func latin1String(_ bytes: UnsafeRawBufferPointer) -> String {
        if !bytes.contains(where: { $0 >= 0x80 }) {
            return String(decoding: bytes, as: UTF8.self)
        }
        var scalars = String.UnicodeScalarView()
        for byte in bytes { scalars.append(Unicode.Scalar(byte)) }
        return String(scalars)
    }

    static func isCleanContentLength(_ trimmed: String) -> Bool {
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isASCII && $0.isNumber }) else { return false }
        if trimmed.count > 1, trimmed.first == "0" { return false }
        return true
    }

    private func startLineIsHTTP11(_ startLine: String) -> Bool {
        direction == .httpRequest ? startLine.hasSuffix(" HTTP/1.1") : startLine.hasPrefix("HTTP/1.1")
    }

    static func transferEncodingIsChunked(_ value: String) -> Bool {
        let last = value
            .split(separator: ",", omittingEmptySubsequences: false)
            .last?
            .trimmingCharacters(in: CharacterSet.whitespaces)
        return last.map { ASCII.equalsIgnoringCase($0, "chunked") } == true
    }

    static func transferEncodingHasContentCoding(_ value: String?) -> Bool {
        guard let value else { return false }
        return value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: CharacterSet.whitespaces).lowercased() }
            .contains { !$0.isEmpty && $0 != "chunked" && $0 != "identity" }
    }

    static func normalizedTransferEncoding(_ value: String) -> String? {
        guard value.allSatisfy({ $0.isASCII }) else { return nil }
        let normalized = value.lowercased()
            .replacingOccurrences(of: "[\t ]*,[\t ]*", with: ",", options: .regularExpression)
        let allowed: Set<String> = [
            "chunked", "compress,chunked", "deflate,chunked", "gzip,chunked",
            "compress", "deflate", "gzip", "identity",
        ]
        return allowed.contains(normalized) ? normalized : nil
    }

    static func isHTTPVersionToken(_ token: Substring) -> Bool {
        let bytes = Array(token.utf8)
        return bytes.count == 8
            && bytes[0] == 0x48 && bytes[1] == 0x54 && bytes[2] == 0x54 && bytes[3] == 0x50 && bytes[4] == 0x2F
            && (0x30...0x39).contains(bytes[5]) && bytes[6] == 0x2E && (0x30...0x39).contains(bytes[7])
    }

    private func parsesStartLine(_ startLine: String) -> Bool {
        let tokens = startLine.split(whereSeparator: {
            $0 == " " || $0 == "\t" || $0 == "\u{0B}" || $0 == "\u{0C}"
        })
        switch direction {
        case .httpRequest:
            return tokens.count == 3 && Self.isHTTPVersionToken(tokens[2])
        case .httpResponse:
            guard tokens.count >= 2, Self.isHTTPVersionToken(tokens[0]) else { return false }
            return Int(tokens[1]) != nil
        }
    }

    private func isConnectRequestLine(_ startLine: String) -> Bool {
        let tokens = startLine.split(whereSeparator: {
            $0 == " " || $0 == "\t" || $0 == "\u{0B}" || $0 == "\u{0C}"
        })
        return tokens.first == "CONNECT"
    }

    private static func containsCRorLF(_ string: String) -> Bool {
        for byte in string.utf8 {
            if byte == 0x0D || byte == 0x0A {
                return true
            }
        }
        return false
    }

    private func isHTTPStartLine(_ line: String) -> Bool {
        if line.hasPrefix("HTTP/1.") { return true }
        guard line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0") else {
            return false
        }
        guard let firstSpace = line.firstIndex(of: " ") else { return false }
        let method = String(line[..<firstSpace])
        return Self.isValidMethodToken(method)
    }

    private func isInterimResponseStartLine(_ startLine: String) -> Bool {
        guard startLine.hasPrefix("HTTP/1.") else { return false }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, let status = HTTPHeader.parseStatusCode(parts[1]) else { return false }
        return (100..<200).contains(status) && status != 101
    }

    private func emitResponseHead(startLine: String, headers: [Header], bodyFollows: Bool, into output: inout Data) {
        if let sink = responseIRSink {
            sink.http1ResponseHead(status: responseStatusCode(from: startLine) ?? 0, headers: headers, endStream: !bodyFollows)
        } else {
            output.append(serializeHead(startLine: startLine, headers: headers))
        }
    }

    private func emitBridgeBody(_ data: Data, endStream: Bool) -> Bool {
        guard let sink = responseIRSink else { return false }
        sink.http1ResponseBody(data, endStream: endStream)
        return true
    }

    private func bridgeResetIfNeeded() -> Bool {
        guard let sink = responseIRSink else { return false }
        sink.http1ResponseReset()
        mode = .draining
        receiveBuffer.removeAll(keepingCapacity: false)
        return true
    }

    private func serializeHead(startLine: String, headers: [Header]) -> Data {
        if let verbatim = verbatimHead,
           verbatim.startLine == startLine,
           verbatim.headers.elementsEqual(headers, by: { $0.name == $1.name && $0.value == $1.value }) {
            verbatimHead = nil
            return verbatim.bytes
        }
        let safeHeaders = headers.filter { entry in
            guard !Self.containsCRorLF(entry.name),
                  !Self.containsCRorLF(entry.value) else {
                logger.warning("\(logPrefix): Invalid header: \(HTTPHeader.escapedForLog(entry.name))")
                return false
            }
            return true
        }
        var size = startLine.utf8.count + 4
        for (name, value) in safeHeaders {
            size += name.utf8.count + 2 + value.utf8.count + 2
        }
        var out = Data(capacity: size)
        HTTPHeader.appendFieldBytes(startLine, to: &out)
        out.append(contentsOf: [0x0D, 0x0A])
        for (name, value) in safeHeaders {
            HTTPHeader.appendFieldBytes(name, to: &out)
            out.append(contentsOf: [0x3A, 0x20]) // ':'  ' '
            HTTPHeader.appendFieldBytes(value, to: &out)
            out.append(contentsOf: [0x0D, 0x0A])
        }
        out.append(contentsOf: [0x0D, 0x0A])
        return out
    }

    private func queueSynthesizedResponse(_ response: MITMScriptEngine.SynthesizedResponse) {
        let reason = canonicalReasonPhrase(for: response.status)
        let startLine = "HTTP/1.1 \(response.status) \(reason)"
        var headers = response.sanitizedHeaders(lowercaseNames: false) { name in
            logger.warning("[Script] Anywhere.respond: Invalid header: \(name)")
        }
        let body = response.truncatedBody(cap: Self.maxSynthesizedResponseBodyBytes) {
            logger.warning("[Script] Anywhere.respond: Body too large")
        }
        headers = response.withDateStamp(headers, lowercaseName: false)
        headers.append((name: "Content-Length", value: String(body.count)))
        var bytes = serializeHead(startLine: startLine, headers: headers)
        if !body.isEmpty {
            bytes.append(body)
        }
        if requestLog.isHTTP1QueueEmpty {
            pendingClientBytes.append(bytes)
        } else {
            requestLog.attachSynthesizedAfterLastHTTP1(bytes)
        }
    }

    private static func isValidMethodToken(_ token: String) -> Bool {
        HTTPHeader.isValidName(token)
    }

    private static func isValidRequestTarget(_ target: String) -> Bool {
        guard !target.isEmpty else { return false }
        for byte in target.utf8 {
            if byte < 0x21 || byte == 0x7F {
                return false
            }
        }
        return true
    }

    // MARK: - Framing decision

    private enum Framing {
        case none
        case contentLength(Int)
        case chunked
        case readUntilClose
        case switchingProtocols
    }

    private func bodyFraming(
        startLine: String,
        headers: [Header],
        originatingMethod: String? = nil
    ) -> Framing {
        var responseStatus: Int?
        if direction == .httpResponse {
            if let method = originatingMethod,
               method.uppercased() == "HEAD" {
                return .none
            }
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let status = HTTPHeader.parseStatusCode(parts[1]) {
                responseStatus = status
                if (200..<300).contains(status),
                   originatingMethod?.uppercased() == "CONNECT" {
                    return .switchingProtocols
                }
                if status == 101 { return .switchingProtocols }
                if isNoBodyStatus(status) { return .none }
            }
        }
        var transferEncoding: String?
        var contentLength: String?
        for (name, value) in headers {
            if ASCII.equalsIgnoringCase(name, "transfer-encoding") {
                transferEncoding = value
            } else if ASCII.equalsIgnoringCase(name, "content-length") {
                contentLength = value
            }
        }
        if let transferEncoding {
            if Self.transferEncodingIsChunked(transferEncoding) {
                return .chunked
            }
        }
        if let rawContentLength = contentLength {
            let trimmed = rawContentLength.trimmingCharacters(in: Self.fieldValueOWS)
            if Self.isCleanContentLength(trimmed) {
                let length = Int(trimmed) ?? Int.max
                return length == 0 ? .none : .contentLength(length)
            }
        }
        if responseStatus == 205 { return .none }
        return direction == .httpRequest ? .none : .readUntilClose
    }

    private func warnIfBufferedScriptDeStreams(_ headers: [Header]) {
        let contentType = HTTPHeader.firstValue(in: headers, named: "content-type")
        guard direction == .httpResponse,
              MITMScriptTransform.isStreamingMediaType(contentType) else { return }
        logger.warning("[MITM] \(host): Buffered script on streaming response")
    }

    private func combinedHeaderValue(_ headers: [Header], name: String) -> String? {
        var parts: [String] = []
        for (fieldName, fieldValue) in headers where ASCII.equalsIgnoringCase(fieldName, name) {
            parts.append(fieldValue)
        }
        if parts.isEmpty { return nil }
        if parts.count == 1 { return parts[0] }
        return parts.joined(separator: ", ")
    }

    // MARK: - Rule application (head-time)

    private func applyAuthorityRewrite(_ headers: [Header]) -> [Header] {
        guard direction == .httpRequest, let authority = effectiveAuthority else {
            return headers
        }
        var result = headers.filter { !ASCII.equalsIgnoringCase($0.name, "host") }
        result.append((name: "Host", value: authority))
        return result
    }

    private func selectRewrite(_ startLine: String, verdicts: MITMGateVerdictTable) -> RewriteSelection {
        guard direction == .httpRequest else { return .none }
        guard hasRewriteRule else { return .none }

        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return .none }
        let method = String(parts[0])
        let target = String(parts[1])
        let version = String(parts[2])

        if target == "*" { return .none }

        for (index, rule) in rules.enumerated() {
            guard case .rewrite = rule.operation else { continue }
            guard let resolved = rule.resolvedRewriteAction(verdicts: verdicts, at: index) else { continue }
            switch resolved {
            case .transparent(let replacement):
                guard Self.isValidRequestTarget(replacement.requestTarget) else {
                    logger.warning("[MITM] \(host): rewrite: Invalid request target")
                    continue
                }
                return .transparent(line: "\(method) \(replacement.requestTarget) \(version)",
                                    replacement: replacement)
            case .redirect302, .reject200Text, .reject200Gif, .reject200Data:
                guard let response = MITMRespondBuilder.response(for: resolved) else { continue }
                return .synthesize(response)
            }
        }
        return .none
    }

    private func synthesizeRequestResponse(
        _ response: MITMScriptEngine.SynthesizedResponse,
        requestHeaders: [Header],
        into output: inout Data
    ) -> Bool {
        queueSynthesizedResponse(response)
        switch bodyFraming(startLine: "", headers: requestHeaders, originatingMethod: nil) {
        case .contentLength(let length) where length > 0:
            mode = .discardingLength(remaining: length)
        case .chunked:
            mode = .discardingChunked(reader: ChunkedReader())
        case .none, .contentLength, .readUntilClose, .switchingProtocols:
            mode = .awaitingHead
        }
        return true
    }

    private func applyHeaderRules(_ headers: [Header], verdicts: MITMGateVerdictTable) -> [Header] {
        guard !rules.isEmpty else { return headers }
        var current = headers
        for (index, rule) in rules.enumerated() {
            guard verdicts.matches(at: index) else { continue }
            switch rule.operation {
            case .headerAdd(let name, let value):
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                current.removeAll { ASCII.equalsIgnoringCase($0.name, nameLower) }
            case .headerReplace(let name, let value):
                current = current.map { entry in
                    ASCII.equalsIgnoringCase(entry.name, name) ? (name: name, value: value) : entry
                }
            case .rewrite, .script, .streamScript, .bodyReplace, .bodyJSON:
                continue
            }
        }
        return current
    }

    private func requestURLForGating(
        startLine: String,
        originatingRequest: MITMRequestLog.Record?
    ) -> String? {
        switch direction {
        case .httpRequest:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            guard parts.count >= 2 else { return nil }
            let target = String(parts[1])
            return target == "*" ? nil : "\(scheme)://\(host)\(target)" // asterisk-form: no match
        case .httpResponse:
            return originatingRequest?.url
        }
    }

    // MARK: - Message build / head rebuild

    private func buildMessage(
        startLine: String,
        headers: [Header],
        body: Data,
        originatingRequest: MITMRequestLog.Record?
    ) -> HTTPMessage {
        var method: String?
        var url: String?
        var originalURL: String?
        var status: Int?
        switch direction {
        case .httpRequest:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2 {
                method = String(parts[0])
                url = "\(scheme)://\(host)\(String(parts[1]))"
            }
            originalURL = currentRequestOriginalURL
        case .httpResponse:
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let code = HTTPHeader.parseStatusCode(parts[1]) {
                status = code
            }
            method = originatingRequest?.method
            url = originatingRequest?.url
            originalURL = originatingRequest?.originalURL
        }
        return HTTPMessage(
            phase: direction,
            method: method,
            url: url,
            originalURL: originalURL,
            status: status,
            headers: headers,
            body: body,
            ruleSetID: ruleSetID
        )
    }

    private func rebuildStartLine(
        from message: HTTPMessage,
        fallback: String
    ) -> String {
        let parts = fallback.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        switch message.phase {
        case .httpRequest:
            guard let method = message.method, let url = message.url else {
                return fallback
            }
            guard Self.isValidMethodToken(method) else {
                logger.warning("[Script] Invalid method: \(method)")
                return fallback
            }
            let originalTarget = parts.count >= 2 ? String(parts[1]) : "/"
            let candidateTarget = pathAndQuery(fromURL: url) ?? originalTarget
            guard Self.isValidRequestTarget(candidateTarget) else {
                logger.warning("[Script] Invalid request target")
                return fallback
            }
            let version = parts.count >= 3 ? String(parts[2]) : "HTTP/1.1"
            return "\(method) \(candidateTarget) \(version)"
        case .httpResponse:
            guard let status = message.status else { return fallback }
            let version = parts.count >= 1 ? String(parts[0]) : "HTTP/1.1"
            let reason = canonicalReasonPhrase(for: status)
            return "\(version) \(status) \(reason)"
        }
    }

    private func pathAndQuery(fromURL url: String) -> String? {
        guard let components = URLComponents(string: url) else { return nil }
        if components.scheme == nil && components.host == nil {
            return nil
        }
        var target = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        if let query = components.percentEncodedQuery {
            target += "?\(query)"
        }
        return target
    }

    private func canonicalReasonPhrase(for status: Int) -> String {
        switch status {
        case 100: return "Continue"
        case 101: return "Switching Protocols"
        case 200: return "OK"
        case 201: return "Created"
        case 202: return "Accepted"
        case 204: return "No Content"
        case 206: return "Partial Content"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 303: return "See Other"
        case 304: return "Not Modified"
        case 307: return "Temporary Redirect"
        case 308: return "Permanent Redirect"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 408: return "Request Timeout"
        case 409: return "Conflict"
        case 410: return "Gone"
        case 418: return "I'm a teapot"
        case 429: return "Too Many Requests"
        case 500: return "Internal Server Error"
        case 501: return "Not Implemented"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default:  return ""
        }
    }

    // MARK: - Request log helpers

    private func logRequest(startLine: String) {
        guard direction == .httpRequest else { return }
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2 else {
            requestLog.recordHTTP1(method: nil, url: nil, originalURL: nil)
            return
        }
        let method = String(parts[0])
        let target = String(parts[1])
        let url = "\(scheme)://\(host)\(target)"
        requestLog.recordHTTP1(method: method, url: url, originalURL: currentRequestOriginalURL)
    }
}

// MARK: - ChunkedReader

nonisolated private final class ChunkedReader {
    private enum State {
        case sizeLine
        case chunkData(remaining: Int, originalSize: Int)
        case dataCRLF(originalSize: Int)
        case trailerOrEnd
    }

    private var state: State = .sizeLine
    private var sizes: [Int] = []
    /// CRLF scan resume offset (O(n) total, not O(n²)); reset when a line is consumed.
    private var scanCursor = 0

    enum ForwardResult {
        case needMore
        case complete
        case malformed
    }

    enum BufferedResult {
        case needMore
        case complete(sizes: [Int])
        case malformed
    }

    func consumeForward(_ buffer: inout MITMByteBuffer, into output: inout Data) -> ForwardResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                guard let size = buffer.withUnsafeBytes(in: 0..<lineEnd, MITMHTTP1Stream.parseHexSize) else {
                    return .malformed
                }
                buffer.appendPrefix(lineEnd + 2, to: &output)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if size == 0 {
                    state = .trailerOrEnd
                } else {
                    state = .chunkData(remaining: size, originalSize: size)
                }
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                buffer.appendPrefix(take, to: &output)
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF:
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[0] == 0x0D, buffer[1] == 0x0A else {
                    return .malformed
                }
                output.append(contentsOf: [0x0D, 0x0A])
                buffer.removeFirst(2)
                state = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                buffer.appendPrefix(lineEnd + 2, to: &output)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if lineEnd == 0 {
                    return .complete
                }
            }
        }
        return .needMore
    }

    func scanForward(_ data: Data, onData: ((Range<Data.Index>) -> Void)?) -> (consumed: Int, result: ForwardResult) {
        let base = data.startIndex
        let count = data.count
        var cursor = 0
        while cursor < count {
            switch state {
            case .sizeLine:
                guard let lineEnd = Self.firstCRLF(in: data, from: cursor) else { return (cursor, .needMore) }
                let size = data.withUnsafeBytes { bytes in
                    MITMHTTP1Stream.parseHexSize(UnsafeRawBufferPointer(rebasing: bytes[cursor..<lineEnd]))
                }
                guard let size else { return (cursor, .malformed) }
                cursor = lineEnd + 2
                state = size == 0 ? .trailerOrEnd : .chunkData(remaining: size, originalSize: size)
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, count - cursor)
                onData?((base + cursor)..<(base + cursor + take))
                cursor += take
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return (cursor, .needMore)
                }
            case .dataCRLF:
                guard count - cursor >= 2 else { return (cursor, .needMore) }
                guard data[base + cursor] == 0x0D, data[base + cursor + 1] == 0x0A else {
                    return (cursor, .malformed)
                }
                cursor += 2
                state = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = Self.firstCRLF(in: data, from: cursor) else { return (cursor, .needMore) }
                let isEmptyLine = lineEnd == cursor
                cursor = lineEnd + 2
                if isEmptyLine { return (cursor, .complete) }
            }
        }
        return (cursor, .needMore)
    }

    private static func firstCRLF(in data: Data, from start: Int) -> Int? {
        data.withUnsafeBytes { bytes -> Int? in
            guard let base = bytes.baseAddress, bytes.count >= 2 else { return nil }
            var index = start
            while index < bytes.count - 1 {
                guard let found = memchr(base + index, 0x0D, bytes.count - 1 - index) else { return nil }
                index = base.distance(to: UnsafeRawPointer(found))
                if bytes[index + 1] == 0x0A { return index }
                index += 1
            }
            return nil
        }
    }

    func consumeForwardIR(_ buffer: inout MITMByteBuffer, deliver: ((Data) -> Void)?) -> ForwardResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                guard let size = buffer.withUnsafeBytes(in: 0..<lineEnd, MITMHTTP1Stream.parseHexSize) else {
                    return .malformed
                }
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                state = size == 0 ? .trailerOrEnd : .chunkData(remaining: size, originalSize: size)
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                if take > 0, let deliver { deliver(buffer.prefix(take)) }
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF:
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[0] == 0x0D, buffer[1] == 0x0A else { return .malformed }
                buffer.removeFirst(2)
                state = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if lineEnd == 0 { return .complete }
            }
        }
        return .needMore
    }

    func consumeBuffered(_ buffer: inout MITMByteBuffer, into output: inout Data) -> BufferedResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                let parsedSize = buffer.withUnsafeBytes(in: 0..<lineEnd, MITMHTTP1Stream.parseHexSize)
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                guard let size = parsedSize else { return .malformed }
                if size == 0 {
                    state = .trailerOrEnd
                } else {
                    state = .chunkData(remaining: size, originalSize: size)
                }
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                buffer.appendPrefix(take, to: &output)
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF(let originalSize):
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[0] == 0x0D, buffer[1] == 0x0A else {
                    return .malformed
                }
                buffer.removeFirst(2)
                if sizes.count < MITMHTTP1Stream.maxTrackedChunkSizes { sizes.append(originalSize) }
                state = .sizeLine
            case .trailerOrEnd:
                guard let lineEnd = buffer.firstCRLF(from: scanCursor) else {
                    if buffer.count > MITMHTTP1Stream.maxChunkLineBytes { return .malformed }
                    scanCursor = max(0, buffer.count - 1)
                    return .needMore
                }
                buffer.removeFirst(lineEnd + 2)
                scanCursor = 0
                if lineEnd == 0 {
                    return .complete(sizes: sizes)
                }
            }
        }
        return .needMore
    }
}

// MARK: - MITMMessageRewriter

extension MITMHTTP1Stream: MITMMessageRewriter {
    func feed(_ data: Data) async -> Data {
        await transform(data)
    }

    nonisolated func drainPendingServerBytes() -> Data { Data() }
}
