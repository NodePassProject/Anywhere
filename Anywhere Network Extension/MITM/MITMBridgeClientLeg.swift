//
//  MITMBridgeClientLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "MITMBridgeClientLeg")

nonisolated protocol MITMBridgeClientLegDelegate: AnyObject {
    func clientLegSendRequestHead(_ head: MITMRequestHead, url: String?, endStream: Bool)
    func clientLegSendRequestData(streamID: UInt32, _ data: Data, endStream: Bool)
    func clientLegSendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    func clientLegAbortRequest(streamID: UInt32)
    func clientLegResponseComplete(streamID: UInt32)
    func clientLegWriteToClient(_ data: Data)
    func clientLegFatalError(_ message: String)
    func clientLegResponseDrained(streamID: UInt32, byteCount: Int)
}

actor MITMBridgeClientLeg: MITMResponseSink {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    weak var delegate: MITMBridgeClientLegDelegate?

    private let host: String
    private let rewriter: MITMHTTP2Rewriter
    private let flowController: MITMHTTP2FlowController
    private let lwipBridge: LWIPConcurrencyBridge
    private let decoder = HPACKDecoder()

    private typealias Codec = MITMHTTP2FrameCodec

    private static let maxHeaderBlockBytes = 256 * 1024
    private static let maxTrackedStreams = 256
    private static let advertisedMaxConcurrentStreams = 128
    private static let maxClientBufferedBytes = 8 * 1024 * 1024

    private static let receiveWindow = 4 * 1024 * 1024

    // MARK: Connection state

    enum Phase: PhaseTransitionable {
        case idle
        case prefaceSent
        case failed
        case torn

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .prefaceSent):
                return true
            case (_, .failed):
                return old != .failed && old != .torn
            case (_, .torn):
                return old != .torn
            default:
                return false
            }
        }
    }

    private(set) var phase: Phase = .idle

    @discardableResult
    private func transition(to new: Phase) -> Bool {
        Phase.transition(&phase, to: new)
    }

    private var prefaceRemaining = Codec.clientPrefaceLength
    private var rxBuffer = MITMByteBuffer()
    private var goAwaySent = false

    private var parkedContinuation: CheckedContinuation<Void, Never>?

    private var highestStreamID: UInt32 = 0

    private struct Pending {
        let streamID: UInt32
        var fragments: Data
        let endStream: Bool
        var continuationCount = 0
    }
    private var pending: Pending?
    private static let maxContinuationFrames = 1024

    // MARK: Request streams

    private struct BufferedReq {
        var rewrittenHeaders: [(name: String, value: String)]
        let codec: MITMBodyCodec.Plan
        var data: Data
        let neverIndexed: Set<String>
        let scripted: Bool
        let resolvedUpstream: (host: String, port: UInt16?)?
        let originalURL: String?
    }

    private enum RequestStream {
        case streaming(remaining: Int?)
        case buffering(BufferedReq)
        case synthAnswered
    }
    private var requestStreams: [UInt32: RequestStream] = [:]
    private var streamMethods: [UInt32: String] = [:]

    // MARK: Client-bound (response) state

    private struct PaceState {
        var pending = Data()
        var streamWindow: Int
        var sawEnd = false
        var finished = false
        var pendingTrailers: [(name: String, value: String)]?
    }
    private var paceStates: [UInt32: PaceState] = [:]

    private var pendingStreamCredit: [UInt32: Int] = [:]

    private var batchedConnCredit = 0
    private var batchedStreamCredit: [UInt32: Int] = [:]

    var uploadDrainCoupled = false

    private var streamDeferredUpload: Set<UInt32> = []


    init(
        host: String,
        rewriter: MITMHTTP2Rewriter,
        flowController: MITMHTTP2FlowController,
        lwipBridge: LWIPConcurrencyBridge
    ) {
        self.host = host
        self.rewriter = rewriter
        self.flowController = flowController
        self.lwipBridge = lwipBridge
    }

    func markTorn() {
        transition(to: .torn)
        let continuation = parkedContinuation
        parkedContinuation = nil
        rxBuffer = MITMByteBuffer()
        requestStreams.removeAll()
        streamMethods.removeAll()
        paceStates.removeAll()
        pendingStreamCredit.removeAll()
        batchedConnCredit = 0
        batchedStreamCredit.removeAll()
        streamDeferredUpload.removeAll()
        pending = nil
        continuation?.resume()
    }

    func rejectStream(_ streamID: UInt32, errorCode: UInt32) {
        guard phase != .torn else { return }
        rstToClient(streamID, errorCode: errorCode, abortUpstream: false)
    }

    func failStream(streamID: UInt32, status: Int, message: String) {
        guard phase != .torn else { return }
        let body = Data(message.utf8)
        let headers: [(name: String, value: String)] = [
            (name: "content-type", value: "text/plain; charset=utf-8"),
            (name: "content-length", value: String(body.count)),
        ]
        deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: body.isEmpty)
        if !body.isEmpty { deliverResponseData(streamID: streamID, body, endStream: true) }
    }

    // MARK: - Client → MITM

    private func onLwipParked<T>(_ body: @escaping (CheckedContinuation<T, Never>) -> Void) async -> T {
        await lwipBridge.runParked(body)
    }

    func feed(_ data: Data) async {
        await onLwipParked { (continuation: CheckedContinuation<Void, Never>) in
            self.assumeIsolated { $0.feedOnQueue(data, continuation: continuation) }
        }
    }

    private func feedOnQueue(_ data: Data, continuation: CheckedContinuation<Void, Never>) {
        guard parkedContinuation == nil else {
            fail("feed re-entered while a script hop is outstanding", code: Codec.ErrorCode.internalError)
            continuation.resume()
            return
        }
        if phase == .failed || phase == .torn { continuation.resume(); return }
        var input = data
        if prefaceRemaining > 0, !input.isEmpty {
            let take = min(prefaceRemaining, input.count)
            input.removeFirst(take)
            prefaceRemaining -= take
        }
        if !input.isEmpty { rxBuffer.append(input) }
        ensureServerPrefaceSent()
        parkedContinuation = continuation
        let parked = pump()
        finishPass(parked: parked)
    }

    private func ensureServerPrefaceSent() {
        guard phase == .idle else { return }
        transition(to: .prefaceSent)
        var preface = Data()
        Codec.appendFrameHeader(typeCode: Codec.FrameType.settings, flags: 0, streamID: 0, payloadLength: 24, into: &preface)
        preface.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]) // SETTINGS_ENABLE_PUSH = 0
        let maxStreams = UInt32(Self.advertisedMaxConcurrentStreams)
        preface.append(
            contentsOf: [0x00, 0x03, // SETTINGS_MAX_CONCURRENT_STREAMS
                         UInt8((maxStreams >> 24) & 0xFF), UInt8((maxStreams >> 16) & 0xFF),
                         UInt8((maxStreams >> 8) & 0xFF), UInt8(maxStreams & 0xFF)]
        )
        let w = UInt32(Self.receiveWindow)
        preface.append(
            contentsOf: [0x00, 0x04, // SETTINGS_INITIAL_WINDOW_SIZE
                         UInt8((w >> 24) & 0xFF), UInt8((w >> 16) & 0xFF),
                         UInt8((w >> 8) & 0xFF), UInt8(w & 0xFF)]
        )
        let maxHeaderList = UInt32(HPACKDecoder.maxDecodedHeaderListSize)
        preface.append(
            contentsOf: [0x00, 0x06, // SETTINGS_MAX_HEADER_LIST_SIZE
                         UInt8((maxHeaderList >> 24) & 0xFF), UInt8((maxHeaderList >> 16) & 0xFF),
                         UInt8((maxHeaderList >> 8) & 0xFF), UInt8(maxHeaderList & 0xFF)]
        )
        delegate?.clientLegWriteToClient(preface)
        delegate?.clientLegWriteToClient(Codec.windowUpdate(streamID: 0, increment: Self.receiveWindow - 65_535))
    }

    private func pump() -> Bool {
        while true {
            switch Codec.parseFrame(from: &rxBuffer) {
            case .needMore:
                return false
            case .error:
                fail("frame length exceeded receive cap", code: Codec.ErrorCode.frameSizeError)
                return false
            case .frame(let frame):
                if handleFrame(frame) { return true }
                if phase == .failed || phase == .torn { return false }
            }
        }
    }

    private func finishPass(parked: Bool) {
        flushBatchedCredits()
        if parked { return }
        let continuation = parkedContinuation
        parkedContinuation = nil
        continuation?.resume()
    }

    private func flushBatchedCredits() {
        if batchedConnCredit > 0 {
            delegate?.clientLegWriteToClient(Codec.windowUpdate(streamID: 0, increment: batchedConnCredit))
            batchedConnCredit = 0
        }
        guard !batchedStreamCredit.isEmpty else { return }
        for (sid, n) in batchedStreamCredit where n > 0 {
            delegate?.clientLegWriteToClient(Codec.windowUpdate(streamID: sid, increment: n))
        }
        batchedStreamCredit.removeAll(keepingCapacity: true)
    }

    private func fail(_ message: String, code: UInt32 = Codec.ErrorCode.protocolError) {
        guard transition(to: .failed) else { return }
        rxBuffer = MITMByteBuffer()
        pending = nil
        sendGoAwayToClient(code: code)
        logger.warning("bridge \(host): \(message); tearing down")
        delegate?.clientLegFatalError(message)
    }

    func sendGoAwayToClient(code: UInt32) {
        guard phase != .torn, !goAwaySent else { return }
        goAwaySent = true
        delegate?.clientLegWriteToClient(Codec.goAway(lastStreamID: highestStreamID, errorCode: code))
    }

    private func handleFrame(_ frame: Codec.RawFrame) -> Bool {
        if let p = pending, frame.typeCode != Codec.FrameType.continuation {
            fail("frame interleaved with pending HEADERS on stream \(p.streamID)")
            return false
        }
        switch frame.typeCode {
        case Codec.FrameType.headers:      return handleHeaders(frame)
        case Codec.FrameType.continuation: return handleContinuation(frame)
        case Codec.FrameType.data:         return handleData(frame)
        case Codec.FrameType.settings:     handleSettings(frame)
        case Codec.FrameType.windowUpdate: handleWindowUpdate(frame)
        case Codec.FrameType.ping:
            if frame.flags & 0x1 == 0 { delegate?.clientLegWriteToClient(Codec.pingAck(opaque: frame.payload)) }
        case Codec.FrameType.rstStream:    handleClientRST(frame)
        case Codec.FrameType.priority:     break
        case Codec.FrameType.goaway:       break
        case Codec.FrameType.pushPromise:  fail("client sent PUSH_PROMISE")
        default:                           break // RFC 9113 §4.1: ignore unknown types
        }
        return false
    }

    // MARK: SETTINGS / WINDOW_UPDATE / RST

    private func handleSettings(_ frame: Codec.RawFrame) {
        guard frame.streamID == 0 else { fail("SETTINGS on non-zero stream"); return }
        if frame.flags & 0x1 != 0 { return }
        let payload = frame.payload
        var i = payload.startIndex
        while i + 6 <= payload.endIndex {
            let identifier = (UInt16(payload[i]) << 8) | UInt16(payload[i + 1])
            let value = (UInt32(payload[i + 2]) << 24)
                | (UInt32(payload[i + 3]) << 16)
                | (UInt32(payload[i + 4]) << 8)
                | UInt32(payload[i + 5])
            if identifier == 0x4 { applyClientInitialWindowSize(Int(value)) }
            i += 6
        }
        delegate?.clientLegWriteToClient(Codec.settingsAck())
    }

    private func applyClientInitialWindowSize(_ newValue: Int) {
        let delta = flowController.updateInitialStreamWindow(newValue)
        guard delta != 0 else { return }
        for id in paceStates.keys { paceStates[id]?.streamWindow += delta }
        if delta > 0 { distributeClientConnectionWindow() }
    }

    private func handleWindowUpdate(_ frame: Codec.RawFrame) {
        guard let inc = Codec.windowUpdateIncrement(frame.payload), inc > 0 else { return }
        if frame.streamID == 0 {
            flowController.creditConnection(inc)
            distributeClientConnectionWindow()
        } else if paceStates[frame.streamID] != nil {
            let current = paceStates[frame.streamID]?.streamWindow ?? 0
            paceStates[frame.streamID]?.streamWindow = min(MITMHTTP2FlowController.maxWindow, current + inc)
            flushResponse(frame.streamID)
        } else if streamMethods[frame.streamID] != nil {
            // Window enlarged before the response head delivered (no PaceState yet); stash the
            // credit for makePaceState to fold in.
            let acc = (pendingStreamCredit[frame.streamID] ?? 0) + inc
            pendingStreamCredit[frame.streamID] = min(MITMHTTP2FlowController.maxWindow, acc)
        }
    }

    private func makePaceState(_ streamID: UInt32) -> PaceState {
        let seed = flowController.clientInitialStreamWindow + (pendingStreamCredit.removeValue(forKey: streamID) ?? 0)
        return PaceState(streamWindow: min(MITMHTTP2FlowController.maxWindow, max(0, seed)))
    }

    private func handleClientRST(_ frame: Codec.RawFrame) {
        let id = frame.streamID
        guard id != 0 else { return }
        let wasOpen = requestStreams[id] != nil || isLiveResponseStream(id)
        requestStreams.removeValue(forKey: id)
        streamMethods.removeValue(forKey: id)
        paceStates.removeValue(forKey: id)
        pendingStreamCredit.removeValue(forKey: id)
        streamDeferredUpload.remove(id)
        if wasOpen { delegate?.clientLegAbortRequest(streamID: id) }
    }

    // MARK: HEADERS

    private func handleHeaders(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else { fail("HEADERS on stream 0"); return false }
        guard frame.streamID % 2 == 1 else { fail("client HEADERS with even stream id"); return false }
        guard let block = Codec.stripHeadersPadding(payload: frame.payload, flags: frame.flags) else {
            fail("HEADERS with invalid padding")
            return false
        }
        if block.count > Self.maxHeaderBlockBytes { fail("HEADERS block over cap"); return false }
        let endStream = frame.flags & 0x1 != 0
        if frame.flags & 0x4 != 0 {
            return finalizeHeaders(streamID: frame.streamID, fragments: block, endStream: endStream)
        }
        pending = Pending(streamID: frame.streamID, fragments: block, endStream: endStream)
        return false
    }

    private func handleContinuation(_ frame: Codec.RawFrame) -> Bool {
        guard var p = pending, p.streamID == frame.streamID else { fail("stray CONTINUATION"); return false }
        let isFinal = frame.flags & 0x4 != 0
        if frame.payload.isEmpty && !isFinal { fail("zero-length CONTINUATION without END_HEADERS"); return false }
        p.continuationCount += 1
        if p.continuationCount > Self.maxContinuationFrames { fail("too many CONTINUATION frames"); return false }
        if p.fragments.count + frame.payload.count > Self.maxHeaderBlockBytes { fail("header block over cap"); return false }
        p.fragments.append(frame.payload)
        if isFinal {
            pending = nil
            return finalizeHeaders(streamID: p.streamID, fragments: p.fragments, endStream: p.endStream)
        }
        pending = p
        return false
    }

    private func finalizeHeaders(streamID: UInt32, fragments: Data, endStream: Bool) -> Bool {
        guard let result = decoder.decodeHeaders(from: fragments) else {
            fail("HPACK decode failure (table desync)", code: Codec.ErrorCode.compressionError)
            return false
        }
        let decoded = result.fields
        let neverIndexed = result.neverIndexed

        let isNewStream = streamID > highestStreamID
        if isNewStream { highestStreamID = streamID }

        guard MITMBridgeHeaders.pseudoHeadersValid(decoded, isRequest: true) else {
            logger.warning("bridge \(host) stream \(streamID): malformed pseudo-header section; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError,
                        abortUpstream: requestStreams[streamID] != nil)
            return false
        }

        if let bad = HTTPHeader.firstInvalidOctet(decoded) {
            logger.warning("bridge \(host) stream \(streamID): header rejected — \(bad.reason) on \"\(HTTPHeader.escapedForLog(bad.name))\"; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError,
                        abortUpstream: requestStreams[streamID] != nil)
            return false
        }

        guard MITMBridgeHeaders.h2ConnectionHeadersAbsent(decoded) else {
            logger.warning("bridge \(host) stream \(streamID): connection-specific header in HTTP/2; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError,
                        abortUpstream: requestStreams[streamID] != nil)
            return false
        }

        if HTTPHeader.firstValue(in: decoded, named: ":method") == nil {
            guard requestStreams[streamID] != nil else {
                logger.warning("bridge \(host) stream \(streamID): request HEADERS missing :method; RST")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: false)
                return false
            }
            guard endStream else {
                logger.warning("bridge \(host) stream \(streamID): trailer HEADERS without END_STREAM; RST")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                return false
            }
            guard !decoded.contains(where: { $0.name.hasPrefix(":") }) else {
                logger.warning("bridge \(host) stream \(streamID): pseudo-header in request trailer; RST")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                return false
            }
            let trailers = MITMBridgeHeaders.upstreamRequestHeaders(decoded: decoded)
            return endRequestBody(streamID, trailers: trailers)
        }

        guard isNewStream else { fail("non-increasing stream id \(streamID)"); return false }

        let method = HTTPHeader.firstValue(in: decoded, named: ":method") ?? "GET"
        let path = HTTPHeader.firstValue(in: decoded, named: ":path")
        let requestURL = path.map { "https://\(host)\($0)" }
        streamMethods[streamID] = method.uppercased()

        if method.uppercased() == "CONNECT" {
            logger.warning("bridge \(host) stream \(streamID): CONNECT can't bridge; RST HTTP_1_1_REQUIRED")
            rstToClient(streamID, errorCode: Codec.ErrorCode.http11Required, abortUpstream: false)
            return false
        }

        guard MITMBridgeHeaders.requestPseudoHeadersComplete(decoded) else {
            logger.warning("bridge \(host) stream \(streamID): request missing/inconsistent required pseudo-header; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: false)
            return false
        }

        if requestStreams.count + paceStates.count >= Self.maxTrackedStreams {
            logger.warning("bridge \(host) stream \(streamID): tracked-stream cap reached; REFUSED_STREAM")
            rstToClient(streamID, errorCode: Codec.ErrorCode.refusedStream, abortUpstream: false)
            return false
        }

        let head = PendingRequestHead(
            streamID: streamID, decoded: decoded, neverIndexed: neverIndexed,
            endStream: endStream, method: method.uppercased(), requestURL: requestURL, originalPath: path
        )
        if let gates = rewriter.peekRequestHeadGates(originalPath: path) {
            return applyRequestHead(head, gates: gates)
        }
        return parkForRequestGates(head)
    }

    private struct PendingRequestHead: Sendable {
        let streamID: UInt32
        let decoded: [(name: String, value: String)]
        let neverIndexed: Set<String>
        let endStream: Bool
        let method: String
        let requestURL: String?
        let originalPath: String?
    }

    private func applyRequestHead(_ head: PendingRequestHead, gates: MITMHTTP2Rewriter.RequestHeadGates) -> Bool {
        let streamID = head.streamID
        let endStream = head.endStream
        let requestURL = head.requestURL
        let neverIndexed = head.neverIndexed

        if let synth = rewriter.requestSynthResponse(gates: gates) {
            answerSynth(streamID: streamID, response: synth)
            return false
        }

        var rewritten: [(name: String, value: String)]
        let resolvedUpstream: (host: String, port: UInt16?)?
        (rewritten, resolvedUpstream) = rewriter.transformRequestHeaders(head.decoded, gates: gates)
        let gateURL = MITMHTTP2Rewriter.requestPath(in: rewritten).map { "https://\(host)\($0)" } ?? requestURL

        if rewriter.hasBodyAccessingRule(phase: .httpResponse, verdicts: gates.responseGates) {
            rewritten = MITMBridgeHeaders.clampingAcceptEncoding(rewritten)
        }

        if rewriter.hasStreamScriptRule(phase: .httpRequest, verdicts: gates.post) {
            logger.warning("bridge \(host) stream \(streamID): request stream-script not supported on the bridge; forwarding body unscripted")
        }

        let hasBufferedRule = rewriter.hasBufferedBodyRule(phase: .httpRequest, verdicts: gates.post)
        let method = head.method
        let willBufferBody = hasBufferedRule && (endStream || shouldBuffer(headers: rewritten))

        if willBufferBody, !endStream, Self.expectsContinue(rewritten) {
            sendInterimContinue(streamID)
            rewritten = rewritten.filter { !ASCII.equalsIgnoringCase($0.name, "expect") }
        }

        if willBufferBody {
            let codec = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: rewritten, named: "content-encoding"))
            requestStreams[streamID] = .buffering(BufferedReq(rewrittenHeaders: rewritten, codec: codec, data: Data(), neverIndexed: neverIndexed, scripted: true, resolvedUpstream: resolvedUpstream, originalURL: requestURL))
            if endStream { return finishBufferedRequest(streamID) }
            return false
        }

        let bodylessMethod = ["GET", "HEAD", "DELETE", "OPTIONS", "TRACE"].contains(method.uppercased())
        let framing: MITMBridgeBodyFraming
        if endStream {
            framing = .none
        } else if let raw = HTTPHeader.firstValue(in: rewritten, named: "content-length"),
                  let n = Int(raw.trimmingCharacters(in: .whitespaces)), n >= 0 {
            framing = n == 0 ? .none : .contentLength(n)
        } else if bodylessMethod {
            let codec = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: rewritten, named: "content-encoding"))
            requestStreams[streamID] = .buffering(BufferedReq(rewrittenHeaders: rewritten, codec: codec, data: Data(), neverIndexed: neverIndexed, scripted: false, resolvedUpstream: resolvedUpstream, originalURL: requestURL))
            return false
        } else {
            framing = .chunked
        }
        guard let head = makeRequestHead(streamID: streamID, rewritten: rewritten, framing: framing, neverIndexed: neverIndexed, resolvedUpstream: resolvedUpstream, originalURL: requestURL) else {
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: false)
            return false
        }
        let remaining: Int?
        switch framing {
        case .none: remaining = 0
        case .contentLength(let n): remaining = n
        case .chunked: remaining = nil
        }
        requestStreams[streamID] = .streaming(remaining: remaining)
        if uploadDrainCoupled, !endStream { streamDeferredUpload.insert(streamID) }
        delegate?.clientLegSendRequestHead(head, url: gateURL, endStream: endStream)
        if endStream { requestStreams.removeValue(forKey: streamID) }
        return false
    }

    private func parkForRequestGates(_ head: PendingRequestHead) -> Bool {
        let rewriter = self.rewriter
        Task { [weak self] in
            let gates = await rewriter.resolveRequestHeadGates(originalPath: head.originalPath)
            guard let self else { return }
            self.lwipBridge.enqueue {
                self.assumeIsolated { me in
                    guard me.phase != .torn, me.phase != .failed else {
                        let continuation = me.parkedContinuation; me.parkedContinuation = nil
                        continuation?.resume()
                        return
                    }
                    _ = me.applyRequestHead(head, gates: gates)
                    let parked = me.pump()
                    me.finishPass(parked: parked)
                }
            }
        }
        return true
    }

    private func makeRequestHead(
        streamID: UInt32,
        rewritten: [(name: String, value: String)],
        framing: MITMBridgeBodyFraming,
        neverIndexed: Set<String>,
        resolvedUpstream: (host: String, port: UInt16?)?,
        originalURL: String?
    ) -> MITMRequestHead? {
        guard let method = HTTPHeader.firstValue(in: rewritten, named: ":method"),
              let path = HTTPHeader.firstValue(in: rewritten, named: ":path"),
              !method.isEmpty, !path.isEmpty else { return nil }
        let scheme = HTTPHeader.firstValue(in: rewritten, named: ":scheme") ?? "https"
        let authority = HTTPHeader.firstValue(in: rewritten, named: ":authority") ?? host
        guard HTTPHeader.isValidName(method),
              HTTPHeader.isValidValue(path), !path.utf8.contains(0x20),
              HTTPHeader.isValidValue(authority) else {
            logger.warning("bridge \(host): refusing request with malformed pseudo-header")
            return nil
        }
        return MITMRequestHead(
            clientStreamID: streamID,
            method: method,
            scheme: scheme,
            authority: authority,
            path: path,
            headers: MITMBridgeHeaders.upstreamRequestHeaders(decoded: rewritten),
            framing: framing,
            neverIndexed: neverIndexed,
            resolvedUpstream: resolvedUpstream,
            originalURL: originalURL
        )
    }

    private func shouldBuffer(headers: [(name: String, value: String)]) -> Bool {
        let codec = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: headers, named: "content-encoding"))
        guard codec.supported else { return false }
        if let raw = HTTPHeader.firstValue(in: headers, named: "content-length"),
           let length = Int(raw.trimmingCharacters(in: .whitespaces)) {
            return length <= MITMBodyCodec.maxBufferedBodyBytes
        }
        return !codec.requiresDecompression
    }

    // MARK: DATA

    private func handleData(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else { fail("DATA on stream 0"); return false }
        let onWireLength = frame.payload.count
        guard let body = Codec.stripDataPadding(payload: frame.payload, flags: frame.flags) else {
            fail("DATA with invalid padding")
            return false
        }
        let endStream = frame.flags & 0x1 != 0
        let id = frame.streamID

        switch requestStreams[id] {
        case .streaming(let remaining):
            if streamDeferredUpload.contains(id) {
                batchedConnCredit += onWireLength
                let padding = onWireLength - body.count
                if padding > 0 { batchedStreamCredit[id, default: 0] += padding }
            } else {
                creditClientUpload(streamID: id, length: onWireLength)
            }
            if let remaining {
                guard body.count <= remaining else {
                    logger.warning("bridge \(host) stream \(id): request body exceeds Content-Length; resetting (RFC 9113 §8.1.2.6)")
                    rstToClient(id, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                    return false
                }
                let left = remaining - body.count
                guard !(endStream && left != 0) else {
                    logger.warning("bridge \(host) stream \(id): request body shorter than Content-Length; resetting (RFC 9113 §8.1.2.6)")
                    rstToClient(id, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                    return false
                }
                if !endStream { requestStreams[id] = .streaming(remaining: left) }
            }
            delegate?.clientLegSendRequestData(streamID: id, body, endStream: endStream)
            if endStream { finishRequestUpload(id) }
            return false

        case .buffering(var buffer):
            creditClientUpload(streamID: id, length: onWireLength)
            buffer.data.append(body)
            if !endStream, buffer.data.count > MITMBodyCodec.maxBufferedBodyBytes {
                return abandonBufferedToChunked(streamID: id, buf: buffer)
            }
            requestStreams[id] = .buffering(buffer)
            if endStream { return finishBufferedRequest(id) }
            return false

        case .synthAnswered:
            creditClientUpload(streamID: id, length: onWireLength)
            return false

        case nil:
            if id > highestStreamID {
                fail("DATA on idle stream \(id)")
                return false
            }
            if onWireLength > 0 { batchedConnCredit += onWireLength }
            return false
        }
    }

    private func endRequestBody(_ streamID: UInt32, trailers: [(name: String, value: String)] = []) -> Bool {
        switch requestStreams[streamID] {
        case .streaming(let remaining):
            if let remaining, remaining != 0 {
                logger.warning("bridge \(host) stream \(streamID): request ended before Content-Length; resetting (RFC 9113 §8.1.2.6)")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                return false
            }
            if trailers.isEmpty {
                delegate?.clientLegSendRequestData(streamID: streamID, Data(), endStream: true)
            } else {
                delegate?.clientLegSendRequestTrailers(streamID: streamID, trailers)
            }
            finishRequestUpload(streamID)
            return false
        case .buffering:
            return finishBufferedRequest(streamID)
        default:
            return false
        }
    }

    private func abandonBufferedToChunked(streamID: UInt32, buf: BufferedReq) -> Bool {
        logger.warning("bridge \(host) stream \(streamID): request body over buffer cap; streaming remainder chunked")
        guard let head = makeRequestHead(streamID: streamID, rewritten: buf.rewrittenHeaders, framing: .chunked, neverIndexed: buf.neverIndexed, resolvedUpstream: buf.resolvedUpstream, originalURL: buf.originalURL) else {
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
            return false
        }
        let url = HTTPHeader.firstValue(in: buf.rewrittenHeaders, named: ":path").map { "https://\(host)\($0)" }
        delegate?.clientLegSendRequestHead(head, url: url, endStream: false)
        if !buf.data.isEmpty { delegate?.clientLegSendRequestData(streamID: streamID, buf.data, endStream: false) }
        requestStreams[streamID] = .streaming(remaining: nil)
        return false
    }

    private func creditClientUpload(streamID: UInt32, length: Int) {
        guard length > 0 else { return }
        batchedStreamCredit[streamID, default: 0] += length
        batchedConnCredit += length
    }

    func creditUploadDrained(_ clientStreamID: UInt32, _ n: Int) {
        guard n > 0, streamDeferredUpload.contains(clientStreamID) else { return }
        delegate?.clientLegWriteToClient(Codec.windowUpdate(streamID: clientStreamID, increment: n))
    }

    // MARK: Buffered request script application

    private func finishBufferedRequest(_ streamID: UInt32) -> Bool {
        guard case .buffering(let buffer)? = requestStreams[streamID] else { return false }
        guard buffer.scripted else {
            requestStreams.removeValue(forKey: streamID)
            emitBufferedRequest(streamID: streamID, headers: buffer.rewrittenHeaders, body: buffer.data, neverIndexed: buffer.neverIndexed, resolvedUpstream: buffer.resolvedUpstream, originalURL: buffer.originalURL)
            return false
        }
        return runRequestScripts(streamID)
    }

    private func runRequestScripts(_ streamID: UInt32) -> Bool {
        guard case .buffering(let buffer)? = requestStreams[streamID] else { return false }
        requestStreams.removeValue(forKey: streamID)

        let plaintext: Data
        if buffer.codec.requiresDecompression {
            guard let decoded = MITMBodyCodec.decompress(buffer.data, plan: buffer.codec, host: host) else {
                emitBufferedRequest(streamID: streamID, headers: buffer.rewrittenHeaders, body: buffer.data, neverIndexed: buffer.neverIndexed, resolvedUpstream: buffer.resolvedUpstream, originalURL: buffer.originalURL)
                return false
            }
            plaintext = decoded
        } else {
            plaintext = buffer.data
        }
        let scriptedHeaders = buffer.codec.requiresDecompression
            ? buffer.rewrittenHeaders.filter { !ASCII.equalsIgnoringCase($0.name, "content-encoding") }
            : buffer.rewrittenHeaders
        let url = HTTPHeader.firstValue(in: buffer.rewrittenHeaders, named: ":path").map { "https://\(host)\($0)" }
        let message = HTTPMessage(
            phase: .httpRequest,
            method: HTTPHeader.firstValue(in: scriptedHeaders, named: ":method"),
            url: url,
            originalUrl: buffer.originalURL,
            status: nil,
            headers: scriptedHeaders.filter { !$0.name.hasPrefix(":") },
            body: plaintext,
            ruleSetID: rewriter.ruleSetID
        )
        let rewriter = self.rewriter
        Task { [weak self] in
            let outcome = await rewriter.applyScripts(message, phase: .httpRequest)
            guard let self else { return }
            self.lwipBridge.enqueue {
                self.assumeIsolated { me in
                    guard me.phase != .torn else { return }
                    guard me.streamMethods[streamID] != nil else { return }
                    switch outcome {
                    case .message(let updated):
                        me.emitBufferedRequest(streamID: streamID, headers: scriptedHeaders, body: updated.body, neverIndexed: buffer.neverIndexed, resolvedUpstream: buffer.resolvedUpstream, originalURL: buffer.originalURL)
                    case .synthesizedResponse(let response):
                        me.answerSynth(streamID: streamID, response: response)
                    }
                }
            }
        }
        return false
    }

    private func emitBufferedRequest(streamID: UInt32, headers: [(name: String, value: String)], body: Data, neverIndexed: Set<String>, resolvedUpstream: (host: String, port: UInt16?)?, originalURL: String?) {
        guard let head = makeRequestHead(streamID: streamID, rewritten: headers, framing: .contentLength(body.count), neverIndexed: neverIndexed, resolvedUpstream: resolvedUpstream, originalURL: originalURL) else {
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
            return
        }
        let url = HTTPHeader.firstValue(in: headers, named: ":path").map { "https://\(host)\($0)" }
        delegate?.clientLegSendRequestHead(head, url: url, endStream: body.isEmpty)
        if !body.isEmpty { delegate?.clientLegSendRequestData(streamID: streamID, body, endStream: true) }
    }

    // MARK: Local (synth) responses

    private func answerSynth(streamID: UInt32, response: MITMScriptEngine.SynthesizedResponse) {
        requestStreams[streamID] = .synthAnswered // swallow further request DATA
        let sanitized = response.sanitizedHeaders(lowercaseNames: true) { name in
            logger.warning("[MITM][JS] bridge \(host): Anywhere.respond dropping invalid header: \(name)")
        }
        let headers = response.withDateStamp(sanitized, lowercaseName: true)
        let body = response.truncatedBody(cap: MITMBodyCodec.maxBufferedBodyBytes) { size in
            logger.warning("[MITM][JS] bridge \(host): Anywhere.respond body \(size) B over cap; truncating")
        }
        deliverResponseHead(streamID: streamID, status: response.status, headers: headers, endStream: body.isEmpty)
        if !body.isEmpty { deliverResponseData(streamID: streamID, body, endStream: true) }
    }

    // MARK: Expect: 100-continue

    private static func expectsContinue(_ headers: [(name: String, value: String)]) -> Bool {
        headers.contains { entry in
            ASCII.equalsIgnoringCase(entry.name, "expect")
                && ASCII.equalsIgnoringCase(
                    entry.value.trimmingCharacters(in: CharacterSet.whitespaces),
                    "100-continue"
                )
        }
    }

    private func sendInterimContinue(_ streamID: UInt32) {
        let block: [(name: String, value: String)] = [(name: ":status", value: "100")]
        delegate?.clientLegWriteToClient(Codec.emitHeaders(
            streamID: streamID,
            block: HPACKEncoder.encodeHeaderBlock(block),
            endStream: false
        ))
    }

    // MARK: - MITMResponseSink (upstream → client)

    private func isLiveResponseStream(_ streamID: UInt32) -> Bool {
        streamMethods[streamID] != nil || paceStates[streamID] != nil
    }

    nonisolated func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>) {
        assumeIsolated { $0.deliverResponseHeadOnQueue(streamID: streamID, status: status, headers: headers, endStream: endStream, neverIndexed: neverIndexed) }
    }

    private func deliverResponseHeadOnQueue(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>) {
        guard phase != .torn, isLiveResponseStream(streamID) else { return }
        var block: [(name: String, value: String)] = [(name: ":status", value: String(status))]
        block.append(contentsOf: MITMBridgeHeaders.responseHeadersToH2(headers))
        delegate?.clientLegWriteToClient(Codec.emitHeaders(
            streamID: streamID,
            block: HPACKEncoder.encodeHeaderBlock(block, neverIndexed: neverIndexed),
            endStream: endStream
        ))
        if endStream {
            finishClientStream(streamID, notifyUpstream: true)
        } else if paceStates[streamID] == nil {
            paceStates[streamID] = makePaceState(streamID)
        }
    }

    nonisolated func deliverResponseInterim(streamID: UInt32, status: Int, headers: [(name: String, value: String)]) {
        assumeIsolated { $0.deliverResponseInterimOnQueue(streamID: streamID, status: status, headers: headers) }
    }

    private func deliverResponseInterimOnQueue(streamID: UInt32, status: Int, headers: [(name: String, value: String)]) {
        guard phase != .torn, isLiveResponseStream(streamID) else { return }
        var block: [(name: String, value: String)] = [(name: ":status", value: String(status))]
        block.append(contentsOf: MITMBridgeHeaders.responseHeadersToH2(headers))
        delegate?.clientLegWriteToClient(Codec.emitHeaders(
            streamID: streamID,
            block: HPACKEncoder.encodeHeaderBlock(block),
            endStream: false
        ))
    }

    nonisolated func deliverResponseData(streamID: UInt32, _ data: Data, endStream: Bool) {
        assumeIsolated { $0.deliverResponseDataOnQueue(streamID: streamID, data, endStream: endStream) }
    }

    private func deliverResponseDataOnQueue(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard phase != .torn, isLiveResponseStream(streamID) else { return }
        appendClientBody(streamID: streamID, data: data, endStream: endStream)
    }

    nonisolated func deliverResponseTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        assumeIsolated { $0.deliverResponseTrailersOnQueue(streamID: streamID, trailers) }
    }

    private func deliverResponseTrailersOnQueue(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard phase != .torn, isLiveResponseStream(streamID) else { return }
        var paceState = paceStates[streamID] ?? makePaceState(streamID)
        paceState.sawEnd = true
        let normalized = MITMBridgeHeaders.responseHeadersToH2(trailers)
        if !normalized.isEmpty { paceState.pendingTrailers = normalized }
        paceStates[streamID] = paceState
        flushResponse(streamID)
    }

    nonisolated func deliverResponseReset(streamID: UInt32, errorCode: UInt32) {
        assumeIsolated { $0.deliverResponseResetOnQueue(streamID: streamID, errorCode: errorCode) }
    }

    private func deliverResponseResetOnQueue(streamID: UInt32, errorCode: UInt32) {
        guard phase != .torn, isLiveResponseStream(streamID) || requestStreams[streamID] != nil else { return }
        rstToClient(streamID, errorCode: errorCode, abortUpstream: false)
    }

    // MARK: - HTTP/1.1 upstream response failure

    func acceptResponseAborted(streamID: UInt32) {
        guard phase != .torn else { return }
        deliverResponseReset(streamID: streamID)
    }

    // MARK: Client-bound body pacing

    private func appendClientBody(streamID: UInt32, data: Data, endStream: Bool) {
        var paceState = paceStates[streamID] ?? makePaceState(streamID)
        paceState.pending.append(data)
        if endStream { paceState.sawEnd = true }
        paceStates[streamID] = paceState
        flushResponse(streamID)
        if let backlog = paceStates[streamID]?.pending.count, backlog > Self.maxClientBufferedBytes {
            logger.warning("bridge \(host) stream \(streamID): client-bound backlog \(backlog) B over cap; resetting stream")
            rstToClient(streamID, errorCode: Codec.ErrorCode.internalError, abortUpstream: true)
        }
    }

    @discardableResult
    private func flushResponse(_ streamID: UInt32, cap: Int = .max) -> Bool {
        guard var paceState = paceStates[streamID] else { return false }
        var progressed = false
        let available = flowController.takeConnection(
            upTo: min(paceState.streamWindow, paceState.pending.count, cap)
        )
        if available > 0 {
            let chunk = paceState.pending.prefix(available)
            let bodyDrained = paceState.sawEnd && available == paceState.pending.count
            let endOnData = bodyDrained && paceState.pendingTrailers == nil
            delegate?.clientLegWriteToClient(Codec.frameData(streamID: streamID, payload: chunk, endStream: endOnData))
            paceState.streamWindow -= available
            paceState.pending.removeFirst(available)
            if endOnData { paceState.finished = true }
            delegate?.clientLegResponseDrained(streamID: streamID, byteCount: available)
            progressed = true
        }
        if paceState.sawEnd, paceState.pending.isEmpty, !paceState.finished {
            if let trailers = paceState.pendingTrailers {
                let block = HPACKEncoder.encodeHeaderBlock(trailers)
                delegate?.clientLegWriteToClient(Codec.emitHeaders(streamID: streamID, block: block, endStream: true))
                paceState.pendingTrailers = nil
            } else {
                delegate?.clientLegWriteToClient(Codec.frameData(streamID: streamID, payload: Data(), endStream: true))
            }
            paceState.finished = true
            progressed = true
        }
        paceStates[streamID] = paceState
        if paceState.finished {
            paceStates.removeValue(forKey: streamID)
            finishClientStream(streamID, notifyUpstream: true)
        }
        return progressed
    }

    private func distributeClientConnectionWindow() {
        let ready = paceStates.keys.filter { (paceStates[$0]?.pending.count ?? 0) > 0 }.sorted()
        var remaining = ready.count
        for id in ready {
            guard flowController.connectionWindow > 0 else { break }
            let share = max(Codec.maxFramePayloadSize, flowController.connectionWindow / max(1, remaining))
            flushResponse(id, cap: share)
            remaining -= 1
        }
    }

    private func finishClientStream(_ streamID: UInt32, notifyUpstream: Bool) {
        streamMethods.removeValue(forKey: streamID)
        paceStates.removeValue(forKey: streamID)
        pendingStreamCredit.removeValue(forKey: streamID)
        if uploadDrainCoupled, isRequestUploading(streamID) {
            return
        }
        requestStreams.removeValue(forKey: streamID)
        streamDeferredUpload.remove(streamID)
        if notifyUpstream { delegate?.clientLegResponseComplete(streamID: streamID) }
    }

    private func isRequestUploading(_ streamID: UInt32) -> Bool {
        if case .streaming = requestStreams[streamID] { return true }
        return false
    }

    private func finishRequestUpload(_ streamID: UInt32) {
        requestStreams.removeValue(forKey: streamID)
        streamDeferredUpload.remove(streamID)
        if !isLiveResponseStream(streamID) {
            delegate?.clientLegResponseComplete(streamID: streamID)
        }
    }

    private func rstToClient(_ streamID: UInt32, errorCode: UInt32, abortUpstream: Bool) {
        delegate?.clientLegWriteToClient(Codec.rstStream(streamID: streamID, errorCode: errorCode))
        streamMethods.removeValue(forKey: streamID)
        paceStates.removeValue(forKey: streamID)
        pendingStreamCredit.removeValue(forKey: streamID)
        requestStreams.removeValue(forKey: streamID)
        streamDeferredUpload.remove(streamID)
        if abortUpstream { delegate?.clientLegAbortRequest(streamID: streamID) }
    }
}
