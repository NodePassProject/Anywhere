//
//  MITMHTTP2UpstreamLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation
import Synchronization

nonisolated private let logger = AnywhereLogger(category: "MITMHTTP2UpstreamLeg")

nonisolated protocol MITMUpstreamLegDelegate: AnyObject {
    func upstreamLegWriteToOrigin(_ data: Data)
    func upstreamLegFatalError(_ message: String)
    func upstreamLegDraining()
    func upstreamLegRequestDrained(clientID: UInt32, count: Int)
}

actor MITMHTTP2UpstreamLeg {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    weak var sink: MITMResponseSink?
    weak var delegate: MITMUpstreamLegDelegate?

    private let host: String
    private let rewriter: MITMHTTP2Rewriter
    private let flowController: MITMHTTP2FlowController
    private let lwipBridge: LWIPConcurrencyBridge
    private let decoder = HPACKDecoder()

    private typealias Codec = MITMHTTP2FrameCodec

    private static let maxHeaderBlockBytes = 256 * 1024

    enum Phase: PhaseTransitionable {
        case idle
        case prefaceSent
        case goingAway
        case failed
        case torn

        static func canTransition(from old: Phase, to new: Phase) -> Bool {
            switch (old, new) {
            case (.idle, .prefaceSent):
                return true
            case (_, .goingAway):
                return old != .goingAway && old != .failed && old != .torn
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

    private var rxBuffer = MITMByteBuffer()

    private var parkedContinuation: CheckedContinuation<Void, Never>?

    private struct Pending {
        let streamID: UInt32
        var fragments: Data
        let originalFlags: UInt8
        var continuationCount = 0
    }
    private var pending: Pending?

    private static let maxContinuationFrames = 1024

    // MARK: Request side (toward upstream)

    private struct PendingRequestBody {
        var remaining: Data
        var streamWindow: Int
        var endStream: Bool
        var pendingTrailers: [(name: String, value: String)]? = nil
    }
    private var pendingRequestBodies: [UInt32: PendingRequestBody] = [:]
    private var openRequestStreams: Set<UInt32> = []

    // MARK: Concurrency limit (SETTINGS_MAX_CONCURRENT_STREAMS)

    private static let provisionalMaxConcurrentStreams = 10

    private static let maxQueuedRequests = 256

    private var serverMaxConcurrentStreams: Int?

    private var firstSettingsSeen = false

    private var maxConcurrentStreams: Int {
        if let s = serverMaxConcurrentStreams { return s }
        return firstSettingsSeen ? Int.max : Self.provisionalMaxConcurrentStreams
    }

    private struct QueuedRequest {
        let head: MITMRequestHead
        let endStreamOnHead: Bool
        var body: [(data: Data, endStream: Bool)] = []
        var bodyBytes = 0
    }
    private var queuedRequests: [UInt32: QueuedRequest] = [:]
    private var queueOrder: [UInt32] = []
    private var draining = false

    private var ourStreamID: [UInt32: UInt32] = [:]   // client → upstream
    private var theirStreamID: [UInt32: UInt32] = [:] // upstream → client
    private var nextUpstreamStreamID: UInt32 = 1

    private func upstreamID(forClient clientID: UInt32) -> UInt32 {
        if let existing = ourStreamID[clientID] { return existing }
        let sid = nextUpstreamStreamID
        nextUpstreamStreamID += 2
        ourStreamID[clientID] = sid
        theirStreamID[sid] = clientID
        return sid
    }

    private func releaseStream(clientID: UInt32, resetOrigin: Bool = false) {
        if resetOrigin, let sid = ourStreamID[clientID] {
            delegate?.upstreamLegWriteToOrigin(Codec.rstStream(streamID: sid, errorCode: Codec.ErrorCode.cancel))
        }
        responseStreams.removeValue(forKey: clientID)
        drainCoupledStreams.remove(clientID)
        responseHalfClosed.remove(clientID)
        pendingRequestBodies.removeValue(forKey: clientID)
        openRequestStreams.remove(clientID)
        if let sid = ourStreamID.removeValue(forKey: clientID) { theirStreamID.removeValue(forKey: sid) }
        drainQueue()
    }

    private func finalizeResponseHalf(clientID: UInt32, originEnded: Bool) {
        if originEnded, openRequestStreams.contains(clientID) {
            responseStreams.removeValue(forKey: clientID)
            drainCoupledStreams.remove(clientID)
            responseHalfClosed.insert(clientID)
        } else {
            releaseStream(clientID: clientID, resetOrigin: !originEnded || openRequestStreams.contains(clientID))
        }
    }

    private func requestHalfFinished(_ clientID: UInt32) {
        if responseHalfClosed.contains(clientID) {
            releaseStream(clientID: clientID, resetOrigin: false)
        }
    }

    private func closeRequestHalf(_ clientID: UInt32) {
        openRequestStreams.remove(clientID)
        requestHalfFinished(clientID)
    }

    private func drainQueue() {
        guard !draining else { return }
        draining = true
        defer { draining = false }
        while ourStreamID.count < maxConcurrentStreams, let clientID = queueOrder.first {
            queueOrder.removeFirst()
            guard let queuedRequest = queuedRequests.removeValue(forKey: clientID) else { continue }
            openUpstreamStream(queuedRequest.head, endStream: queuedRequest.endStreamOnHead)
            for chunk in queuedRequest.body { sendRequestData(streamID: clientID, chunk.data, endStream: chunk.endStream) }
        }
    }

    private func dropFromQueue(_ clientID: UInt32) {
        guard queuedRequests.removeValue(forKey: clientID) != nil else { return }
        queueOrder.removeAll { $0 == clientID }
    }

    private func refuseAllQueued() {
        let queued = queueOrder
        queueOrder.removeAll()
        queuedRequests.removeAll()
        for clientID in queued {
            sink?.deliverResponseReset(streamID: clientID, errorCode: Codec.ErrorCode.refusedStream)
        }
    }

    // MARK: Response side (from upstream)

    private struct BufferedResponse {
        var data: Data
        let codec: MITMBodyCodec.Plan
        let status: Int
        var headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        let neverIndexed: Set<String>
    }
    private struct StreamingResponse {
        let status: Int
        let headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        var frameIndex: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
    }
    private enum ResponseStream {
        case passthrough
        case buffering(BufferedResponse)
        case streaming(StreamingResponse)
    }
    private var responseStreams: [UInt32: ResponseStream] = [:]

    private var drainCoupledStreams: Set<UInt32> = []

    private var responseHalfClosed: Set<UInt32> = []

    private var batchedConnCredit = 0
    private var batchedStreamCredit: [UInt32: Int] = [:]

    private static let maxBufferedRewriteGrowthBytes = 65_535
    private static let maxStreamingRewriteGrowthBytes = 65_535

    private static let maxUpstreamBufferedBytes = 8 * 1024 * 1024

    private static let receiveWindow = 4 * 1024 * 1024

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
        pendingRequestBodies.removeAll()
        responseStreams.removeAll()
        drainCoupledStreams.removeAll()
        responseHalfClosed.removeAll()
        openRequestStreams.removeAll()
        queuedRequests.removeAll()
        queueOrder.removeAll()
        ourStreamID.removeAll()
        theirStreamID.removeAll()
        batchedConnCredit = 0
        batchedStreamCredit.removeAll()
        pending = nil
        continuation?.resume()
    }

    private func ensurePrefaceSent() {
        guard phase == .idle else { return }
        transition(to: .prefaceSent)
        var preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        Codec.appendFrameHeader(typeCode: Codec.FrameType.settings, flags: 0, streamID: 0, payloadLength: 18, into: &preface)
        preface.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]) // SETTINGS_ENABLE_PUSH = 0
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
        delegate?.upstreamLegWriteToOrigin(preface)
        delegate?.upstreamLegWriteToOrigin(Codec.windowUpdate(streamID: 0, increment: Self.receiveWindow - 65_535))
    }

    // MARK: - MITMUpstreamLeg (request IR → upstream h2)

    func sendRequestHead(_ head: MITMRequestHead, endStream: Bool) {
        guard phase != .torn else { return }
        guard phase == .idle || phase == .prefaceSent else {
            sink?.deliverResponseReset(streamID: head.clientStreamID, errorCode: Codec.ErrorCode.refusedStream)
            return
        }
        ensurePrefaceSent()
        guard ourStreamID.count < maxConcurrentStreams else {
            guard queueOrder.count < Self.maxQueuedRequests else {
                logger.warning("h2-upstream \(host) stream \(head.clientStreamID): request queue at cap \(Self.maxQueuedRequests) (origin MAX_CONCURRENT_STREAMS=\(maxConcurrentStreams)); refusing stream")
                sink?.deliverResponseReset(streamID: head.clientStreamID, errorCode: Codec.ErrorCode.refusedStream)
                return
            }
            queuedRequests[head.clientStreamID] = QueuedRequest(head: head, endStreamOnHead: endStream)
            queueOrder.append(head.clientStreamID)
            return
        }
        openUpstreamStream(head, endStream: endStream)
    }

    private func openUpstreamStream(_ head: MITMRequestHead, endStream: Bool) {
        guard nextUpstreamStreamID <= 0x7FFF_FFFF else {
            fail("upstream HTTP/2 stream IDs exhausted")
            return
        }
        let clientID = head.clientStreamID
        let sid = upstreamID(forClient: clientID)
        if !endStream {
            openRequestStreams.insert(clientID)
        }
        var block: [(name: String, value: String)] = [
            (name: ":method", value: head.method),
            (name: ":scheme", value: head.scheme),
            (name: ":authority", value: head.authority),
            (name: ":path", value: head.path),
        ]
        for (name, value) in head.headers {
            block.append((name: name.lowercased(), value: value))
        }
        if case .contentLength(let n) = head.framing {
            block.append((name: "content-length", value: String(n)))
        }
        delegate?.upstreamLegWriteToOrigin(
            Codec.emitHeaders(
                streamID: sid,
                block: HPACKEncoder.encodeHeaderBlock(block, neverIndexed: head.neverIndexed),
                endStream: endStream
            )
        )
        if !endStream {
            pendingRequestBodies[clientID] = PendingRequestBody(
                remaining: Data(),
                streamWindow: flowController.serverInitialStreamWindow,
                endStream: false
            )
        }
    }

    func sendRequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        let clientID = streamID
        if queuedRequests[clientID] != nil {
            queuedRequests[clientID]?.body.append((data, endStream))
            queuedRequests[clientID]?.bodyBytes += data.count
            if let buffered = queuedRequests[clientID]?.bodyBytes, buffered > Self.maxUpstreamBufferedBytes {
                logger.warning("h2-upstream \(host) stream \(clientID): queued request backlog \(buffered) B over cap; resetting stream")
                dropFromQueue(clientID)
                sink?.deliverResponseReset(streamID: clientID)
            }
            return
        }
        guard phase != .torn, openRequestStreams.contains(clientID) else { return }
        var entry = pendingRequestBodies[clientID]
            ?? PendingRequestBody(remaining: Data(), streamWindow: flowController.serverInitialStreamWindow, endStream: false)
        entry.remaining.append(data)
        if endStream { entry.endStream = true }
        pendingRequestBodies[clientID] = entry
        flushRequestBody(clientID)
        if let backlog = pendingRequestBodies[clientID]?.remaining.count, backlog > Self.maxUpstreamBufferedBytes {
            logger.warning("h2-upstream \(host) stream \(clientID): request backlog \(backlog) B over cap; resetting stream")
            if let sid = ourStreamID[clientID] {
                delegate?.upstreamLegWriteToOrigin(Codec.rstStream(streamID: sid, errorCode: Codec.ErrorCode.internalError))
            }
            releaseStream(clientID: clientID)
            sink?.deliverResponseReset(streamID: clientID)
        }
    }

    func abortRequest(streamID: UInt32) {
        guard phase != .torn else { return }
        let clientID = streamID
        if queuedRequests[clientID] != nil {
            dropFromQueue(clientID)
            return
        }
        releaseStream(clientID: clientID, resetOrigin: true)
    }

    func sendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard phase != .torn else { return }
        let clientID = streamID
        let fields = trailers.filter { !$0.name.hasPrefix(":") }
        guard !fields.isEmpty else {
            sendRequestData(streamID: clientID, Data(), endStream: true)
            return
        }
        if queuedRequests[clientID] != nil {
            logger.warning("h2-upstream \(host) stream \(clientID): request trailers on a still-queued stream")
            queuedRequests[clientID]?.body.append((Data(), true))
            return
        }
        guard openRequestStreams.contains(clientID), let sid = ourStreamID[clientID] else { return }
        if var entry = pendingRequestBodies[clientID], !entry.remaining.isEmpty {
            entry.endStream = true
            entry.pendingTrailers = fields
            pendingRequestBodies[clientID] = entry
            flushRequestBody(clientID)
        } else {
            pendingRequestBodies.removeValue(forKey: clientID)
            emitRequestTrailers(sid: sid, fields)
            closeRequestHalf(clientID)
        }
    }

    private func emitRequestTrailers(sid: UInt32, _ trailers: [(name: String, value: String)]) {
        let block = trailers.map { (name: $0.name.lowercased(), value: $0.value) }
        delegate?.upstreamLegWriteToOrigin(Codec.emitHeaders(
            streamID: sid,
            block: HPACKEncoder.encodeHeaderBlock(block),
            endStream: true
        ))
    }

    @discardableResult
    private func flushRequestBody(_ clientID: UInt32, cap: Int = .max) -> Bool {
        guard var entry = pendingRequestBodies[clientID], let sid = ourStreamID[clientID] else { return false }
        let available = flowController.takeServerConnection(
            upTo: min(entry.streamWindow, entry.remaining.count, cap)
        )
        if available > 0 {
            let chunk = entry.remaining.prefix(available)
            entry.remaining.removeFirst(available)
            let bodyDone = entry.endStream && entry.remaining.isEmpty
            delegate?.upstreamLegWriteToOrigin(Codec.frameData(streamID: sid, payload: chunk,
                                             endStream: bodyDone && entry.pendingTrailers == nil))
            entry.streamWindow -= available
            delegate?.upstreamLegRequestDrained(clientID: clientID, count: available)
            if bodyDone {
                if let trailers = entry.pendingTrailers { emitRequestTrailers(sid: sid, trailers) }
                pendingRequestBodies.removeValue(forKey: clientID)
                closeRequestHalf(clientID)
                return true
            }
        } else if entry.remaining.isEmpty, entry.endStream {
            if let trailers = entry.pendingTrailers {
                emitRequestTrailers(sid: sid, trailers)
            } else {
                delegate?.upstreamLegWriteToOrigin(Codec.frameData(streamID: sid, payload: Data(), endStream: true))
            }
            pendingRequestBodies.removeValue(forKey: clientID)
            closeRequestHalf(clientID)
            return true
        }
        pendingRequestBodies[clientID] = entry
        return available > 0
    }

    private func distributeServerConnectionWindow() {
        let ready = pendingRequestBodies.keys.filter { !(pendingRequestBodies[$0]?.remaining.isEmpty ?? true) }.sorted()
        var remaining = ready.count
        for id in ready {
            guard flowController.serverConnectionWindow > 0 else { break }
            let share = max(Codec.maxFramePayloadSize, flowController.serverConnectionWindow / max(1, remaining))
            flushRequestBody(id, cap: share)
            remaining -= 1
        }
    }

    // MARK: - Upstream h2 → response IR

    func feed(_ data: Data) async {
        await lwipBridge.runParked { (continuation: CheckedContinuation<Void, Never>) in
            self.assumeIsolated { $0.feedOnQueue(data, continuation: continuation) }
        }
    }

    private func feedOnQueue(_ data: Data, continuation: CheckedContinuation<Void, Never>) {
        guard parkedContinuation == nil else {
            fail("feed re-entered while parked")
            continuation.resume()
            return
        }
        if phase == .failed || phase == .torn { continuation.resume(); return }
        rxBuffer.append(data)
        parkedContinuation = continuation
        let parked = pump()
        finishPass(parked: parked)
    }

    private func pump() -> Bool {
        while true {
            switch Codec.parseFrame(from: &rxBuffer) {
            case .needMore: return false
            case .error: fail("upstream frame exceeded receive cap"); return false
            case .frame(let frame):
                if handleFrame(frame) { return true }
                if phase == .failed || phase == .torn { return false }
            }
        }
    }

    private func finishPass(parked: Bool) {
        flushBatchedCredits()
        if parked { return }
        let continuation = parkedContinuation; parkedContinuation = nil; continuation?.resume()
    }

    private func flushBatchedCredits() {
        if batchedConnCredit > 0 {
            delegate?.upstreamLegWriteToOrigin(Codec.windowUpdate(streamID: 0, increment: batchedConnCredit))
            batchedConnCredit = 0
        }
        guard !batchedStreamCredit.isEmpty else { return }
        for (sid, n) in batchedStreamCredit where n > 0 {
            delegate?.upstreamLegWriteToOrigin(Codec.windowUpdate(streamID: sid, increment: n))
        }
        batchedStreamCredit.removeAll(keepingCapacity: true)
    }

    private func resumeAfterScript() {
        guard phase != .torn, phase != .failed else { let continuation = parkedContinuation; parkedContinuation = nil; continuation?.resume(); return }
        let parked = pump()
        finishPass(parked: parked)
    }

    private func fail(_ message: String) {
        guard transition(to: .failed) else { return }
        rxBuffer = MITMByteBuffer()
        pending = nil
        refuseAllQueued()
        logger.warning("h2-upstream \(host): \(message); tearing down")
        delegate?.upstreamLegFatalError(message)
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
            if frame.flags & 0x1 == 0 { delegate?.upstreamLegWriteToOrigin(Codec.pingAck(opaque: frame.payload)) }
        case Codec.FrameType.rstStream:    handleUpstreamRST(frame)
        case Codec.FrameType.goaway:       handleGoAway(frame)
        case Codec.FrameType.pushPromise:
            fail("upstream sent PUSH_PROMISE despite ENABLE_PUSH=0")
        default:                           break
        }
        return false
    }

    private func handleSettings(_ frame: Codec.RawFrame) {
        guard frame.streamID == 0 else { fail("upstream SETTINGS on non-zero stream"); return }
        if frame.flags & 0x1 != 0 { return }
        let payload = frame.payload
        var i = payload.startIndex
        while i + 6 <= payload.endIndex {
            let identifier = (UInt16(payload[i]) << 8) | UInt16(payload[i + 1])
            let value = (UInt32(payload[i + 2]) << 24) | (UInt32(payload[i + 3]) << 16)
                | (UInt32(payload[i + 4]) << 8) | UInt32(payload[i + 5])
            if identifier == 0x4 { applyServerInitialWindowSize(Int(value)) }
            if identifier == 0x3 { serverMaxConcurrentStreams = Int(value) } // SETTINGS_MAX_CONCURRENT_STREAMS
            i += 6
        }
        firstSettingsSeen = true
        delegate?.upstreamLegWriteToOrigin(Codec.settingsAck())
        drainQueue()
    }

    private func applyServerInitialWindowSize(_ newValue: Int) {
        let delta = flowController.updateServerInitialStreamWindow(newValue)
        guard delta != 0 else { return }
        for id in pendingRequestBodies.keys { pendingRequestBodies[id]?.streamWindow += delta }
        if delta > 0 { distributeServerConnectionWindow() }
    }

    private func handleWindowUpdate(_ frame: Codec.RawFrame) {
        guard let inc = Codec.windowUpdateIncrement(frame.payload), inc > 0 else { return }
        if frame.streamID == 0 {
            flowController.creditServerConnection(inc)
            distributeServerConnectionWindow()
        } else if let clientID = theirStreamID[frame.streamID], pendingRequestBodies[clientID] != nil {
            let current = pendingRequestBodies[clientID]?.streamWindow ?? 0
            pendingRequestBodies[clientID]?.streamWindow = min(MITMHTTP2FlowController.maxWindow, current + inc)
            flushRequestBody(clientID)
        }
    }

    private func handleUpstreamRST(_ frame: Codec.RawFrame) {
        let sid = frame.streamID
        guard sid != 0, let clientID = theirStreamID[sid] else { return }
        releaseStream(clientID: clientID)
        sink?.deliverResponseReset(streamID: clientID, errorCode: Self.rstErrorCode(frame.payload))
    }

    private static func rstErrorCode(_ payload: Data) -> UInt32 {
        guard payload.count >= 4 else { return Codec.ErrorCode.internalError }
        let s = payload.startIndex
        return UInt32(payload[s]) << 24 | UInt32(payload[s + 1]) << 16
            | UInt32(payload[s + 2]) << 8 | UInt32(payload[s + 3])
    }

    private func handleGoAway(_ frame: Codec.RawFrame) {
        guard frame.streamID == 0, frame.payload.count >= 8 else { return }
        let p = frame.payload
        let s = p.startIndex
        let lastStreamID = (UInt32(p[s]) & 0x7F) << 24 | UInt32(p[s + 1]) << 16 | UInt32(p[s + 2]) << 8 | UInt32(p[s + 3])
        for (clientID, upstreamID) in Array(ourStreamID) where upstreamID > lastStreamID {
            releaseStream(clientID: clientID)
            sink?.deliverResponseReset(streamID: clientID, errorCode: Codec.ErrorCode.refusedStream)
        }
        if transition(to: .goingAway) {
            refuseAllQueued()
            delegate?.upstreamLegDraining()
        }
    }

    // MARK: Response HEADERS

    private func handleHeaders(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else { fail("HEADERS on stream 0"); return false }
        guard let block = Codec.stripHeadersPadding(payload: frame.payload, flags: frame.flags) else {
            fail("HEADERS with invalid padding")
            return false
        }
        if block.count > Self.maxHeaderBlockBytes { fail("HEADERS block over cap"); return false }
        if frame.flags & 0x4 != 0 {
            return finalizeHeaders(streamID: frame.streamID, fragments: block, originalFlags: frame.flags)
        }
        pending = Pending(streamID: frame.streamID, fragments: block, originalFlags: frame.flags)
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
            return finalizeHeaders(streamID: p.streamID, fragments: p.fragments, originalFlags: p.originalFlags)
        }
        pending = p
        return false
    }

    private func finalizeHeaders(streamID: UInt32, fragments: Data, originalFlags: UInt8) -> Bool {
        guard let result = decoder.decodeHeaders(from: fragments) else {
            fail("HPACK decode failure (table desync)")
            return false
        }
        let decoded = result.fields
        let neverIndexed = result.neverIndexed
        let endStream = originalFlags & 0x1 != 0
        guard let clientID = theirStreamID[streamID] else {
            if streamID >= nextUpstreamStreamID {
                fail("response HEADERS on idle upstream stream \(streamID)")
            } else {
                delegate?.upstreamLegWriteToOrigin(Codec.rstStream(streamID: streamID, errorCode: Codec.ErrorCode.cancel))
            }
            return false
        }

        guard MITMBridgeHeaders.pseudoHeadersValid(decoded, isRequest: false) else {
            fail("malformed response pseudo-header section")
            return false
        }

        if let bad = HTTPHeader.firstInvalidOctet(decoded) {
            logger.warning("h2-upstream \(host) stream \(clientID): response header rejected — \(bad.reason) on \"\(HTTPHeader.escapedForLog(bad.name))\"; resetting stream")
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        guard MITMBridgeHeaders.h2ConnectionHeadersAbsent(decoded) else {
            logger.warning("h2-upstream \(host) stream \(clientID): connection-specific header in HTTP/2 response; resetting stream")
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        if responseStreams[clientID] != nil {
            guard endStream else {
                logger.warning("h2-upstream \(host) stream \(clientID): response trailer without END_STREAM; resetting stream")
                sink?.deliverResponseReset(streamID: clientID)
                releaseStream(clientID: clientID, resetOrigin: true)
                return false
            }
            guard !decoded.contains(where: { $0.name.hasPrefix(":") }) else {
                logger.warning("h2-upstream \(host) stream \(clientID): pseudo-header in response trailer; resetting stream")
                sink?.deliverResponseReset(streamID: clientID)
                releaseStream(clientID: clientID, resetOrigin: true)
                return false
            }
            let trailerFields = decoded.filter { !$0.name.hasPrefix(":") }
            return finishResponseStream(streamID: clientID, endStream: true, trailers: trailerFields)
        }

        guard let rawStatus = HTTPHeader.firstValue(in: decoded, named: ":status"),
              let status = HTTPHeader.parseStatusCode(rawStatus) else {
            fail("response missing :status")
            return false
        }

        let isInterim = (100..<200).contains(status) && status != 101
        let originatingRequest = isInterim
            ? rewriter.requestLog.peekHTTP2(streamID: clientID)
            : rewriter.requestLog.popHTTP2(streamID: clientID)
        if isInterim {
            sink?.deliverResponseInterim(streamID: clientID, status: status, headers: decoded.filter { !$0.name.hasPrefix(":") })
            return false
        }
        if status == 101 {
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        let responseURL = originatingRequest?.url
        let head = PendingResponseHead(
            clientID: clientID, status: status, decoded: decoded,
            neverIndexed: neverIndexed, endStream: endStream,
            originatingRequest: originatingRequest, responseURL: responseURL
        )
        if let verdicts = MITMGateVerdictTable.peek(rules: rewriter.rules(phase: .httpResponse), url: responseURL) {
            return applyResponseHead(head, verdicts: verdicts)
        }
        return parkForResponseGates(head)
    }

    private struct PendingResponseHead: Sendable {
        let clientID: UInt32
        let status: Int
        let decoded: [(name: String, value: String)]
        let neverIndexed: Set<String>
        let endStream: Bool
        let originatingRequest: MITMRequestLog.Record?
        let responseURL: String?
    }

    private func applyResponseHead(_ head: PendingResponseHead, verdicts: MITMGateVerdictTable) -> Bool {
        let clientID = head.clientID
        let status = head.status
        let rewritten = rewriter.transformResponseHeaders(head.decoded, verdicts: verdicts)
        let regular = rewritten.filter { !$0.name.hasPrefix(":") }

        let isHead = head.originatingRequest?.method?.uppercased() == "HEAD"
        if head.endStream || isHead || status == 204 || status == 304 {
            sink?.deliverResponseHead(streamID: clientID, status: status, headers: regular, endStream: true, neverIndexed: head.neverIndexed)
            finalizeResponseHalf(clientID: clientID, originEnded: head.endStream)
            return false
        }

        if rewriter.hasStreamScriptRule(phase: .httpResponse, verdicts: verdicts) {
            sink?.deliverResponseHead(streamID: clientID, status: status, headers: MITMBridgeHeaders.droppingContentLength(regular), endStream: false, neverIndexed: head.neverIndexed)
            responseStreams[clientID] = .streaming(StreamingResponse(
                status: status, headers: rewritten, originatingRequest: head.originatingRequest,
                cursor: rewriter.makeResponseFrameCursor(verdicts: verdicts)
            ))
            return false
        }

        if rewriter.hasBufferedBodyRule(phase: .httpResponse, verdicts: verdicts) {
            let codec = MITMBodyCodec.plan(for: HTTPHeader.firstValue(in: rewritten, named: "content-encoding"))
            responseStreams[clientID] = .buffering(BufferedResponse(
                data: Data(), codec: codec, status: status,
                headers: rewritten, originatingRequest: head.originatingRequest, neverIndexed: head.neverIndexed
            ))
            return false
        }

        sink?.deliverResponseHead(streamID: clientID, status: status, headers: regular, endStream: false, neverIndexed: head.neverIndexed)
        responseStreams[clientID] = .passthrough
        drainCoupledStreams.insert(clientID)
        return false
    }

    private func parkForResponseGates(_ head: PendingResponseHead) -> Bool {
        let rules = rewriter.rules(phase: .httpResponse)
        let url = head.responseURL
        Task { [weak self] in
            let verdicts = await MITMGateVerdictTable.resolve(rules: rules, url: url)
            guard let self else { return }
            self.lwipBridge.enqueue {
                self.assumeIsolated { leg in
                    guard leg.phase != .torn, leg.phase != .failed else {
                        let continuation = leg.parkedContinuation; leg.parkedContinuation = nil
                        continuation?.resume()
                        return
                    }
                    _ = leg.applyResponseHead(head, verdicts: verdicts)
                    let parked = leg.pump()
                    leg.finishPass(parked: parked)
                }
            }
        }
        return true
    }

    // MARK: Response DATA

    private func handleData(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else { fail("DATA on stream 0"); return false }
        let onWireLength = frame.payload.count
        guard let body = Codec.stripDataPadding(payload: frame.payload, flags: frame.flags) else {
            fail("DATA with invalid padding")
            return false
        }
        let endStream = frame.flags & 0x1 != 0
        let sid = frame.streamID
        guard let clientID = theirStreamID[sid] else {
            if sid >= nextUpstreamStreamID {
                fail("DATA on idle upstream stream \(sid)")
                return false
            }
            creditConnectionWindow(onWireLength)
            return false
        }

        switch responseStreams[clientID] {
        case .passthrough:
            creditConnectionWindow(onWireLength)
            if drainCoupledStreams.contains(clientID) {
                creditStreamWindow(sid, onWireLength - body.count)
            } else {
                creditStreamWindow(sid, onWireLength)
            }
            sink?.deliverResponseData(streamID: clientID, body, endStream: endStream)
            if endStream { finalizeResponseHalf(clientID: clientID, originEnded: true) }
            return false

        case .buffering(var buffer):
            ackUpstream(upstreamStreamID: sid, length: onWireLength)
            buffer.data.append(body)
            if !endStream, buffer.data.count > MITMBodyCodec.maxBufferedBodyBytes {
                sink?.deliverResponseHead(
                    streamID: clientID, status: buffer.status,
                    headers: buffer.headers.filter { !$0.name.hasPrefix(":") },
                    endStream: false,
                    neverIndexed: buffer.neverIndexed
                )
                sink?.deliverResponseData(streamID: clientID, buffer.data, endStream: false)
                responseStreams[clientID] = .passthrough
                return false
            }
            responseStreams[clientID] = .buffering(buffer)
            if endStream { return runResponseScripts(clientID) }
            return false

        case .streaming:
            ackUpstream(upstreamStreamID: sid, length: onWireLength)
            return handleStreamingData(streamID: clientID, body: body, endStream: endStream)

        case nil:
            ackUpstream(upstreamStreamID: sid, length: onWireLength)
            return false
        }
    }

    private func creditConnectionWindow(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        // Accumulate; flushed at `finishPass`.
        batchedConnCredit += byteCount
    }

    private func creditStreamWindow(_ upstreamStreamID: UInt32, _ byteCount: Int) {
        guard byteCount > 0 else { return }
        batchedStreamCredit[upstreamStreamID, default: 0] += byteCount
    }

    private func ackUpstream(upstreamStreamID: UInt32, length: Int) {
        creditStreamWindow(upstreamStreamID, length)
        creditConnectionWindow(length)
    }

    func creditDrainedResponse(clientID: UInt32, _ n: Int) {
        guard phase != .torn, n > 0, drainCoupledStreams.contains(clientID), let sid = ourStreamID[clientID] else { return }
        creditStreamWindow(sid, n)
        flushBatchedCredits()
    }

    private func finishResponseStream(streamID: UInt32, endStream: Bool, trailers: [(name: String, value: String)] = []) -> Bool {
        switch responseStreams[streamID] {
        case .passthrough:
            finalizeResponseHalf(clientID: streamID, originEnded: true)
            if trailers.isEmpty {
                sink?.deliverResponseData(streamID: streamID, Data(), endStream: true)
            } else {
                sink?.deliverResponseTrailers(streamID: streamID, trailers)
            }
            return false
        case .buffering:
            return runResponseScripts(streamID, trailers: trailers)
        case .streaming:
            return handleStreamingData(streamID: streamID, body: Data(), endStream: true, trailers: trailers)
        case nil:
            return false
        }
    }

    private func deliverFinalResponse(
        streamID: UInt32,
        status: Int,
        headers: [(name: String, value: String)],
        body: Data,
        trailers: [(name: String, value: String)],
        neverIndexed: Set<String>
    ) {
        let headers = MITMBridgeHeaders.settingContentLength(headers, body.count)
        sink?.deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: body.isEmpty && trailers.isEmpty, neverIndexed: neverIndexed)
        if !body.isEmpty { sink?.deliverResponseData(streamID: streamID, body, endStream: trailers.isEmpty) }
        if !trailers.isEmpty { sink?.deliverResponseTrailers(streamID: streamID, trailers) }
    }

    private func deliverStreamingFrame(
        streamID: UInt32,
        body: Data,
        endStream: Bool,
        trailers: [(name: String, value: String)]
    ) {
        if endStream, !trailers.isEmpty {
            if !body.isEmpty { sink?.deliverResponseData(streamID: streamID, body, endStream: false) }
            sink?.deliverResponseTrailers(streamID: streamID, trailers)
            finalizeResponseHalf(clientID: streamID, originEnded: true)
        } else {
            sink?.deliverResponseData(streamID: streamID, body, endStream: endStream)
            if endStream { finalizeResponseHalf(clientID: streamID, originEnded: true) }
        }
    }

    // MARK: Buffered response rewrite

    private func runResponseScripts(_ streamID: UInt32, trailers: [(name: String, value: String)] = []) -> Bool {
        guard case .buffering(let buffer)? = responseStreams[streamID] else { return false }
        finalizeResponseHalf(clientID: streamID, originEnded: true)
        let plaintext: Data
        if buffer.codec.requiresDecompression {
            guard let decoded = MITMBodyCodec.decompress(buffer.data, plan: buffer.codec, host: host) else {
                deliverFinalResponse(
                    streamID: streamID,
                    status: buffer.status,
                    headers: buffer.headers.filter { !$0.name.hasPrefix(":") },
                    body: buffer.data,
                    trailers: trailers,
                    neverIndexed: buffer.neverIndexed
                )
                return false
            }
            plaintext = decoded
        } else {
            plaintext = buffer.data
        }
        let scriptedHeaders = buffer.codec.requiresDecompression
            ? buffer.headers.filter { !ASCII.equalsIgnoringCase($0.name, "content-encoding") }
            : buffer.headers
        let message = HTTPMessage(
            phase: .httpResponse,
            method: buffer.originatingRequest?.method,
            url: buffer.originatingRequest?.url,
            originalUrl: buffer.originatingRequest?.originalUrl,
            status: buffer.status,
            headers: scriptedHeaders.filter { !$0.name.hasPrefix(":") },
            body: plaintext,
            ruleSetID: rewriter.ruleSetID
        )
        let rewriter = self.rewriter
        Task { [weak self] in
            let outcome = await rewriter.applyScripts(message, phase: .httpResponse)
            guard let self else { return }
            self.lwipBridge.enqueue {
                self.assumeIsolated { leg in
                    guard leg.phase != .torn else { return }
                    let regular = scriptedHeaders.filter { !$0.name.hasPrefix(":") }
                    switch outcome {
                    case .message(let updated):
                        var body = updated.body
                        if body.count > plaintext.count, body.count - plaintext.count > Self.maxBufferedRewriteGrowthBytes {
                            logger.warning("h2-upstream \(leg.host) stream \(streamID): response grew over cap; using original body")
                            body = plaintext
                        }
                        leg.deliverFinalResponse(streamID: streamID, status: buffer.status, headers: regular, body: body, trailers: trailers, neverIndexed: buffer.neverIndexed)
                    case .synthesizedResponse:
                        leg.deliverFinalResponse(streamID: streamID, status: buffer.status, headers: regular, body: plaintext, trailers: trailers, neverIndexed: buffer.neverIndexed)
                    }
                }
            }
        }
        return false
    }

    // MARK: Streaming-script response rewrite

    private func handleStreamingData(streamID: UInt32, body: Data, endStream: Bool, trailers: [(name: String, value: String)] = []) -> Bool {
        guard case .streaming(let streamingResponse)? = responseStreams[streamID] else { return false }
        if streamingResponse.cursor.mutable.withLock({ $0.bypass }) {
            advanceStreaming(streamID)
            deliverStreamingFrame(streamID: streamID, body: body, endStream: endStream, trailers: trailers)
            return false
        }
        let context = MITMScriptEngine.FrameContext(
            phase: .httpResponse,
            method: streamingResponse.originatingRequest?.method,
            url: streamingResponse.originatingRequest?.url,
            originalUrl: streamingResponse.originatingRequest?.originalUrl,
            status: streamingResponse.status,
            headers: streamingResponse.headers.filter { !$0.name.hasPrefix(":") },
            frameIndex: streamingResponse.frameIndex,
            isLast: endStream,
            ruleSetID: rewriter.ruleSetID
        )
        let rewriter = self.rewriter
        let cursor = streamingResponse.cursor
        Task { [weak self] in
            let result = await MITMScriptTransform.applyFrame(
                body,
                frameContext: context,
                cursor: cursor,
                engineProvider: rewriter.scriptEngineProvider
            )
            guard let self else { return }
            self.lwipBridge.enqueue {
                self.assumeIsolated { leg in
                    guard leg.phase != .torn else { return }
                    leg.advanceStreaming(streamID, growth: result.body.count - body.count)
                    leg.deliverStreamingFrame(streamID: streamID, body: result.body, endStream: endStream, trailers: trailers)
                    leg.resumeAfterScript()
                }
            }
        }
        return true
    }

    private func advanceStreaming(_ streamID: UInt32, growth: Int = 0) {
        guard case .streaming(var streamingResponse)? = responseStreams[streamID] else { return }
        streamingResponse.frameIndex += 1
        if growth > Self.maxStreamingRewriteGrowthBytes { streamingResponse.cursor.mutable.withLock { $0.bypass = true } }
        responseStreams[streamID] = .streaming(streamingResponse)
    }
}
