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
    func upstreamLegWriteReplyToOrigin(_ data: Data)
    func upstreamLegFatalError(_ message: String)
    func upstreamLegDraining()
    func upstreamLegRequestDrained(clientID: UInt32, count: Int)
}

actor MITMHTTP2UpstreamLeg {
    nonisolated var unownedExecutor: UnownedSerialExecutor {
        sessionContext.executor.asUnownedSerialExecutor()
    }

    weak var sink: MITMResponseSink?
    weak var delegate: MITMUpstreamLegDelegate?

    private let host: String
    private let rewriter: MITMHTTP2Rewriter
    private let flowController: MITMHTTP2FlowController
    private let sessionContext: SessionExecutionContext
    private let decoder = HPACKDecoder()
    private let encoder = HPACKDynamicEncoder()

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

    private var receiveBuffer = MITMByteBuffer()

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
        var remaining = MITMByteQueue()
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

    private static let unadvertisedMaxConcurrentStreams = 100

    private var maxConcurrentStreams: Int {
        serverMaxConcurrentStreams
            ?? (firstSettingsSeen ? Self.unadvertisedMaxConcurrentStreams : Self.provisionalMaxConcurrentStreams)
    }

    private struct QueuedRequest {
        let head: MITMRequestHead
        let endStreamOnHead: Bool
        var body: [(data: Data, endStream: Bool)] = []
        var bodyBytes = 0
    }
    private var queuedRequests: [UInt32: QueuedRequest] = [:]
    private var queueOrder: [UInt32] = []
    private var isDraining = false

    private var upstreamStreamIDByClient: [UInt32: UInt32] = [:]
    private var clientStreamIDByUpstream: [UInt32: UInt32] = [:]
    private var nextUpstreamStreamID: UInt32 = 1

    private func upstreamID(forClient clientID: UInt32) -> UInt32 {
        if let existing = upstreamStreamIDByClient[clientID] { return existing }
        let upstreamStreamID = nextUpstreamStreamID
        nextUpstreamStreamID += 2
        upstreamStreamIDByClient[clientID] = upstreamStreamID
        clientStreamIDByUpstream[upstreamStreamID] = clientID
        return upstreamStreamID
    }

    private func releaseStream(clientID: UInt32, resetOrigin: Bool = false) {
        if resetOrigin, let upstreamStreamID = upstreamStreamIDByClient[clientID] {
            delegate?.upstreamLegWriteToOrigin(Codec.rstStream(streamID: upstreamStreamID, errorCode: Codec.ErrorCode.cancel))
        }
        responseStreams.removeValue(forKey: clientID)
        drainCoupledStreams.remove(clientID)
        responseHalfClosed.remove(clientID)
        pendingRequestBodies.removeValue(forKey: clientID)
        openRequestStreams.remove(clientID)
        if let upstreamStreamID = upstreamStreamIDByClient.removeValue(forKey: clientID) {
            clientStreamIDByUpstream.removeValue(forKey: upstreamStreamID)
            unannouncedStreamCredit.removeValue(forKey: upstreamStreamID)
        }
        drainQueue()
    }

    private func finalizeResponseHalf(clientID: UInt32, originEnded: Bool) {
        if originEnded, openRequestStreams.contains(clientID) {
            responseStreams.removeValue(forKey: clientID)
            drainCoupledStreams.remove(clientID)
            responseHalfClosed.insert(clientID)
            if let upstreamStreamID = upstreamStreamIDByClient[clientID] { unannouncedStreamCredit.removeValue(forKey: upstreamStreamID) }
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
        guard !isDraining, phase == .idle || phase == .prefaceSent else { return }
        isDraining = true
        defer { isDraining = false }
        while upstreamStreamIDByClient.count < maxConcurrentStreams, let clientID = queueOrder.first {
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

    private var unannouncedConnCredit = 0
    private var unannouncedStreamCredit: [UInt32: Int] = [:]

    private static let maxBufferedRewriteGrowthBytes = 65_535
    private static let maxStreamingRewriteGrowthBytes = 65_535

    private static let maxUpstreamBufferedBytes = 8 * 1024 * 1024

    private static let receiveWindow = 4 * 1024 * 1024

    private static let creditAnnouncementThreshold = receiveWindow / 2

    init(
        host: String,
        rewriter: MITMHTTP2Rewriter,
        flowController: MITMHTTP2FlowController,
        sessionContext: SessionExecutionContext
    ) {
        self.host = host
        self.rewriter = rewriter
        self.flowController = flowController
        self.sessionContext = sessionContext
    }

    func markTorn() {
        transition(to: .torn)
        let continuation = parkedContinuation
        parkedContinuation = nil
        receiveBuffer = MITMByteBuffer()
        pendingRequestBodies.removeAll()
        responseStreams.removeAll()
        drainCoupledStreams.removeAll()
        responseHalfClosed.removeAll()
        openRequestStreams.removeAll()
        queuedRequests.removeAll()
        queueOrder.removeAll()
        upstreamStreamIDByClient.removeAll()
        clientStreamIDByUpstream.removeAll()
        unannouncedConnCredit = 0
        unannouncedStreamCredit.removeAll()
        pending = nil
        continuation?.resume()
    }

    private func ensurePrefaceSent() {
        guard phase == .idle else { return }
        transition(to: .prefaceSent)
        var preface = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        Codec.appendFrameHeader(typeCode: Codec.FrameType.settings, flags: 0, streamID: 0, payloadLength: 18, into: &preface)
        preface.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        let window = UInt32(Self.receiveWindow)
        preface.append(
            contentsOf: [
                0x00, 0x04,
                UInt8((window >> 24) & 0xFF), UInt8((window >> 16) & 0xFF),
                UInt8((window >> 8) & 0xFF), UInt8(window & 0xFF)
            ]
        )
        let maxHeaderList = UInt32(HPACKDecoder.maxDecodedHeaderListSize)
        preface.append(
            contentsOf: [
                0x00, 0x06,
                UInt8((maxHeaderList >> 24) & 0xFF), UInt8((maxHeaderList >> 16) & 0xFF),
                UInt8((maxHeaderList >> 8) & 0xFF), UInt8(maxHeaderList & 0xFF)
            ]
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
        guard upstreamStreamIDByClient.count < maxConcurrentStreams else {
            guard queueOrder.count < Self.maxQueuedRequests else {
                logger.warning("[MITM] \(host): Upstream stream limit reached")
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
        let upstreamStreamID = upstreamID(forClient: clientID)
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
        if case .contentLength(let length) = head.framing {
            block.append((name: "content-length", value: String(length)))
        }
        delegate?.upstreamLegWriteToOrigin(
            Codec.emitHeaders(
                streamID: upstreamStreamID,
                block: encoder.encodeHeaderBlock(
                    block,
                    neverIndexed: head.indexing.neverIndexed,
                    indexedFields: head.indexing.indexedFields
                ),
                endStream: endStream
            )
        )
        if !endStream {
            pendingRequestBodies[clientID] = PendingRequestBody(
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
                logger.warning("[MITM] \(host): Upstream buffer full")
                dropFromQueue(clientID)
                sink?.deliverResponseReset(streamID: clientID)
            }
            return
        }
        guard phase != .torn, openRequestStreams.contains(clientID) else { return }
        if pendingRequestBodies[clientID] == nil {
            pendingRequestBodies[clientID] = PendingRequestBody(streamWindow: flowController.serverInitialStreamWindow, endStream: false)
        }
        pendingRequestBodies[clientID]?.remaining.append(data)
        if endStream { pendingRequestBodies[clientID]?.endStream = true }
        flushRequestBody(clientID)
        if let backlog = pendingRequestBodies[clientID]?.remaining.count, backlog > Self.maxUpstreamBufferedBytes {
            logger.warning("[MITM] \(host): Upstream buffer full")
            if let upstreamStreamID = upstreamStreamIDByClient[clientID] {
                delegate?.upstreamLegWriteToOrigin(Codec.rstStream(streamID: upstreamStreamID, errorCode: Codec.ErrorCode.internalError))
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
            queuedRequests[clientID]?.body.append((Data(), true))
            return
        }
        guard openRequestStreams.contains(clientID), let upstreamStreamID = upstreamStreamIDByClient[clientID] else { return }
        if pendingRequestBodies[clientID]?.remaining.isEmpty == false {
            pendingRequestBodies[clientID]?.endStream = true
            pendingRequestBodies[clientID]?.pendingTrailers = fields
            flushRequestBody(clientID)
        } else {
            pendingRequestBodies.removeValue(forKey: clientID)
            emitRequestTrailers(upstreamStreamID: upstreamStreamID, fields)
            closeRequestHalf(clientID)
        }
    }

    private func emitRequestTrailers(upstreamStreamID: UInt32, _ trailers: [(name: String, value: String)]) {
        let block = trailers.map { (name: $0.name.lowercased(), value: $0.value) }
        delegate?.upstreamLegWriteToOrigin(Codec.emitHeaders(
            streamID: upstreamStreamID,
            block: encoder.encodeHeaderBlock(block),
            endStream: true
        ))
    }

    @discardableResult
    private func flushRequestBody(_ clientID: UInt32, cap: Int = .max) -> Bool {
        guard let upstreamStreamID = upstreamStreamIDByClient[clientID], var entry = pendingRequestBodies.removeValue(forKey: clientID) else { return false }
        let available = flowController.takeServerConnection(
            upTo: min(entry.streamWindow, entry.remaining.count, cap)
        )
        if available > 0 {
            let chunks = entry.remaining.popChunks(available)
            let bodyDone = entry.endStream && entry.remaining.isEmpty
            let frames = Codec.dataFrames(
                streamID: upstreamStreamID,
                payload: chunks,
                endStream: bodyDone && entry.pendingTrailers == nil
            )
            for part in frames { delegate?.upstreamLegWriteToOrigin(part) }
            entry.streamWindow -= available
            delegate?.upstreamLegRequestDrained(clientID: clientID, count: available)
            if bodyDone {
                if let trailers = entry.pendingTrailers { emitRequestTrailers(upstreamStreamID: upstreamStreamID, trailers) }
                closeRequestHalf(clientID)
                return true
            }
        } else if entry.remaining.isEmpty, entry.endStream {
            if let trailers = entry.pendingTrailers {
                emitRequestTrailers(upstreamStreamID: upstreamStreamID, trailers)
            } else {
                delegate?.upstreamLegWriteToOrigin(Codec.frameData(streamID: upstreamStreamID, payload: Data(), endStream: true))
            }
            closeRequestHalf(clientID)
            return true
        }
        pendingRequestBodies[clientID] = entry
        return available > 0
    }

    private func distributeServerConnectionWindow() {
        let readyStreamIDs = pendingRequestBodies.keys.filter { !(pendingRequestBodies[$0]?.remaining.isEmpty ?? true) }.sorted()
        var remaining = readyStreamIDs.count
        for id in readyStreamIDs {
            guard flowController.serverConnectionWindow > 0 else { break }
            let share = max(Codec.maxFramePayloadSize, flowController.serverConnectionWindow / max(1, remaining))
            flushRequestBody(id, cap: share)
            remaining -= 1
        }
    }

    // MARK: - Upstream h2 → response IR

    func feed(_ data: Data) async {
        await withCheckedContinuation { feedOnQueue(data, continuation: $0) }
    }

    private func feedOnQueue(_ data: Data, continuation: CheckedContinuation<Void, Never>) {
        guard parkedContinuation == nil else {
            fail("feed re-entered while parked")
            continuation.resume()
            return
        }
        if phase == .failed || phase == .torn {
            continuation.resume()
            return
        }
        var input = data
        parkedContinuation = continuation
        let parked = pump(&input)
        if !input.isEmpty, phase != .failed, phase != .torn { receiveBuffer.append(input) }
        finishPass(parked: parked)
    }

    private func pump() -> Bool {
        var input = Data()
        return pump(&input)
    }

    private func pump(_ input: inout Data) -> Bool {
        while true {
            switch Codec.parseFrame(from: &receiveBuffer, then: &input) {
            case .needMore: return false
                        case .error:
                fail("upstream frame exceeded receive cap")
                return false
            case .frame(let frame):
                if handleFrame(frame) { return true }
                if phase == .failed || phase == .torn { return false }
            }
        }
    }

    private func finishPass(parked: Bool) {
        announceDueCredits()
        if parked { return }
        let continuation = parkedContinuation
        parkedContinuation = nil
        continuation?.resume()
    }

    private func announceDueCredits() {
        if unannouncedConnCredit >= Self.creditAnnouncementThreshold {
            delegate?.upstreamLegWriteToOrigin(Codec.windowUpdate(streamID: 0, increment: unannouncedConnCredit))
            unannouncedConnCredit = 0
        }
        var announced: [UInt32] = []
        for (upstreamStreamID, credit) in unannouncedStreamCredit where credit >= Self.creditAnnouncementThreshold {
            delegate?.upstreamLegWriteToOrigin(Codec.windowUpdate(streamID: upstreamStreamID, increment: credit))
            announced.append(upstreamStreamID)
        }
        for upstreamStreamID in announced { unannouncedStreamCredit.removeValue(forKey: upstreamStreamID) }
    }

    private func announceStreamCreditIfDue(_ upstreamStreamID: UInt32) {
        guard let credit = unannouncedStreamCredit[upstreamStreamID], credit >= Self.creditAnnouncementThreshold else { return }
        unannouncedStreamCredit.removeValue(forKey: upstreamStreamID)
        delegate?.upstreamLegWriteToOrigin(Codec.windowUpdate(streamID: upstreamStreamID, increment: credit))
    }

    private func resumeAfterScript() {
        guard phase != .torn, phase != .failed else {
            let continuation = parkedContinuation
            parkedContinuation = nil
            continuation?.resume()
            return
        }
        let parked = pump()
        finishPass(parked: parked)
    }

    private func fail(_ message: String) {
        guard transition(to: .failed) else { return }
        receiveBuffer = MITMByteBuffer()
        pending = nil
        refuseAllQueued()
        logger.warning("[MITM] \(host): HTTP/2 upstream: \(message)")
        delegate?.upstreamLegFatalError(message)
    }

    private func handleFrame(_ frame: Codec.RawFrame) -> Bool {
        if let pendingHeaders = pending, frame.typeCode != Codec.FrameType.continuation {
            fail("frame interleaved with pending HEADERS on stream \(pendingHeaders.streamID)")
            return false
        }
        switch frame.typeCode {
        case Codec.FrameType.headers:      return handleHeaders(frame)
        case Codec.FrameType.continuation: return handleContinuation(frame)
        case Codec.FrameType.data:         return handleData(frame)
        case Codec.FrameType.settings:     handleSettings(frame)
        case Codec.FrameType.windowUpdate: handleWindowUpdate(frame)
        case Codec.FrameType.ping:
            if frame.flags & 0x1 == 0 { delegate?.upstreamLegWriteReplyToOrigin(Codec.pingAck(opaque: frame.payload)) }
        case Codec.FrameType.rstStream:    handleUpstreamRST(frame)
        case Codec.FrameType.goaway:       handleGoAway(frame)
        case Codec.FrameType.pushPromise:
            fail("upstream sent PUSH_PROMISE despite ENABLE_PUSH=0")
        default:                           break
        }
        return false
    }

    private func handleSettings(_ frame: Codec.RawFrame) {
        guard frame.streamID == 0 else {
            fail("upstream SETTINGS on non-zero stream")
            return
        }
        if frame.flags & 0x1 != 0 { return }
        let payload = frame.payload
        var i = payload.startIndex
        while i + 6 <= payload.endIndex {
            let identifier = (UInt16(payload[i]) << 8) | UInt16(payload[i + 1])
            let value = (UInt32(payload[i + 2]) << 24) | (UInt32(payload[i + 3]) << 16)
                | (UInt32(payload[i + 4]) << 8) | UInt32(payload[i + 5])
            if identifier == 0x1 { encoder.setPeerMaxTableSize(Int(value)) }
            if identifier == 0x4 { applyServerInitialWindowSize(Int(value)) }
            if identifier == 0x3 { serverMaxConcurrentStreams = Int(value) } // SETTINGS_MAX_CONCURRENT_STREAMS
            i += 6
        }
        firstSettingsSeen = true
        delegate?.upstreamLegWriteReplyToOrigin(Codec.settingsAck())
        drainQueue()
    }

    private func applyServerInitialWindowSize(_ newValue: Int) {
        let delta = flowController.updateServerInitialStreamWindow(newValue)
        guard delta != 0 else { return }
        for id in pendingRequestBodies.keys { pendingRequestBodies[id]?.streamWindow += delta }
        if delta > 0 { distributeServerConnectionWindow() }
    }

    private func handleWindowUpdate(_ frame: Codec.RawFrame) {
        guard let increment = Codec.windowUpdateIncrement(frame.payload), increment > 0 else { return }
        if frame.streamID == 0 {
            flowController.creditServerConnection(increment)
            distributeServerConnectionWindow()
        } else if let clientID = clientStreamIDByUpstream[frame.streamID], pendingRequestBodies[clientID] != nil {
            let current = pendingRequestBodies[clientID]?.streamWindow ?? 0
            pendingRequestBodies[clientID]?.streamWindow = min(MITMHTTP2FlowController.maxWindow, current + increment)
            flushRequestBody(clientID)
        }
    }

    private func handleUpstreamRST(_ frame: Codec.RawFrame) {
        let upstreamStreamID = frame.streamID
        guard upstreamStreamID != 0, let clientID = clientStreamIDByUpstream[upstreamStreamID] else { return }
        releaseStream(clientID: clientID)
        sink?.deliverResponseReset(streamID: clientID, errorCode: Self.rstErrorCode(frame.payload))
    }

    private static func rstErrorCode(_ payload: Data) -> UInt32 {
        guard payload.count >= 4 else { return Codec.ErrorCode.internalError }
        let start = payload.startIndex
        return UInt32(payload[start]) << 24 | UInt32(payload[start + 1]) << 16
            | UInt32(payload[start + 2]) << 8 | UInt32(payload[start + 3])
    }

    private func handleGoAway(_ frame: Codec.RawFrame) {
        guard frame.streamID == 0, frame.payload.count >= 8 else { return }
        let payload = frame.payload
        let start = payload.startIndex
        let lastStreamID = (UInt32(payload[start]) & 0x7F) << 24 | UInt32(payload[start + 1]) << 16 | UInt32(payload[start + 2]) << 8 | UInt32(payload[start + 3])
        let enteredGoingAway = transition(to: .goingAway)
        if enteredGoingAway { refuseAllQueued() }
        for (clientID, upstreamID) in Array(upstreamStreamIDByClient) where upstreamID > lastStreamID {
            releaseStream(clientID: clientID)
            sink?.deliverResponseReset(streamID: clientID, errorCode: Codec.ErrorCode.refusedStream)
        }
        if enteredGoingAway { delegate?.upstreamLegDraining() }
    }

    // MARK: Response HEADERS

    private func handleHeaders(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else {
            fail("HEADERS on stream 0")
            return false
        }
        guard let block = Codec.stripHeadersPadding(payload: frame.payload, flags: frame.flags) else {
            fail("HEADERS with invalid padding")
            return false
        }
        if block.count > Self.maxHeaderBlockBytes {
            fail("HEADERS block over cap")
            return false
        }
        if frame.flags & 0x4 != 0 {
            return finalizeHeaders(streamID: frame.streamID, fragments: block, originalFlags: frame.flags)
        }
        pending = Pending(streamID: frame.streamID, fragments: block, originalFlags: frame.flags)
        return false
    }

    private func handleContinuation(_ frame: Codec.RawFrame) -> Bool {
        guard var pendingHeaders = pending, pendingHeaders.streamID == frame.streamID else {
            fail("stray CONTINUATION")
            return false
        }
        pending = nil
        let isFinal = frame.flags & 0x4 != 0
        if frame.payload.isEmpty && !isFinal {
            fail("zero-length CONTINUATION without END_HEADERS")
            return false
        }
        pendingHeaders.continuationCount += 1
        if pendingHeaders.continuationCount > Self.maxContinuationFrames {
            fail("too many CONTINUATION frames")
            return false
        }
        if pendingHeaders.fragments.count + frame.payload.count > Self.maxHeaderBlockBytes {
            fail("header block over cap")
            return false
        }
        pendingHeaders.fragments.append(frame.payload)
        if isFinal {
            return finalizeHeaders(streamID: pendingHeaders.streamID, fragments: pendingHeaders.fragments, originalFlags: pendingHeaders.originalFlags)
        }
        pending = pendingHeaders
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
        guard let clientID = clientStreamIDByUpstream[streamID] else {
            if streamID >= nextUpstreamStreamID {
                fail("response HEADERS on idle upstream stream \(streamID)")
            } else {
                delegate?.upstreamLegWriteReplyToOrigin(Codec.rstStream(streamID: streamID, errorCode: Codec.ErrorCode.cancel))
            }
            return false
        }

        guard MITMBridgeHeaders.pseudoHeadersValid(decoded, isRequest: false) else {
            fail("malformed response pseudo-header section")
            return false
        }

        if let invalidOctet = HTTPHeader.firstInvalidOctet(decoded) {
            logger.warning("[MITM] \(host): HTTP/2 upstream: Invalid header: \(HTTPHeader.escapedForLog(invalidOctet.name)): \(invalidOctet.reason)")
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        guard MITMBridgeHeaders.h2ConnectionHeadersAbsent(decoded) else {
            logger.warning("[MITM] \(host): HTTP/2 upstream: Connection-specific header")
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        if responseStreams[clientID] != nil {
            guard endStream else {
                logger.warning("[MITM] \(host): HTTP/2 upstream: Trailers without END_STREAM")
                sink?.deliverResponseReset(streamID: clientID)
                releaseStream(clientID: clientID, resetOrigin: true)
                return false
            }
            guard !decoded.contains(where: { $0.name.hasPrefix(":") }) else {
                logger.warning("[MITM] \(host): HTTP/2 upstream: Pseudo-header in trailers")
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
            self.sessionContext.enqueue {
                self.assumeIsolated { leg in
                    guard leg.phase != .torn, leg.phase != .failed else {
                        let continuation = leg.parkedContinuation
                        leg.parkedContinuation = nil
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
        guard frame.streamID != 0 else {
            fail("DATA on stream 0")
            return false
        }
        let onWireLength = frame.payload.count
        guard let body = Codec.stripDataPadding(payload: frame.payload, flags: frame.flags) else {
            fail("DATA with invalid padding")
            return false
        }
        let endStream = frame.flags & 0x1 != 0
        let upstreamStreamID = frame.streamID
        guard let clientID = clientStreamIDByUpstream[upstreamStreamID] else {
            if upstreamStreamID >= nextUpstreamStreamID {
                fail("DATA on idle upstream stream \(upstreamStreamID)")
                return false
            }
            creditConnectionWindow(onWireLength)
            return false
        }

        switch responseStreams[clientID] {
        case .passthrough:
            creditConnectionWindow(onWireLength)
            if drainCoupledStreams.contains(clientID) {
                creditStreamWindow(upstreamStreamID, onWireLength - body.count)
            } else {
                creditStreamWindow(upstreamStreamID, onWireLength)
            }
            sink?.deliverResponseData(streamID: clientID, body, endStream: endStream)
            if endStream { finalizeResponseHalf(clientID: clientID, originEnded: true) }
            return false

        case .buffering:
            ackUpstream(upstreamStreamID: upstreamStreamID, length: onWireLength)
            return appendBufferedResponse(clientID: clientID, body: body, endStream: endStream)

        case .streaming:
            ackUpstream(upstreamStreamID: upstreamStreamID, length: onWireLength)
            return handleStreamingData(streamID: clientID, body: body, endStream: endStream)

        case nil:
            ackUpstream(upstreamStreamID: upstreamStreamID, length: onWireLength)
            return false
        }
    }

    private func appendBufferedResponse(clientID: UInt32, body: Data, endStream: Bool) -> Bool {
        guard case .buffering(var buffer)? = responseStreams.removeValue(forKey: clientID) else { return false }
        buffer.data.append(body)
        if !endStream, buffer.data.count > MITMBodyCodec.maxBufferedBodyBytes {
            responseStreams[clientID] = .passthrough
            sink?.deliverResponseHead(
                streamID: clientID, status: buffer.status,
                headers: buffer.headers.filter { !$0.name.hasPrefix(":") },
                endStream: false,
                neverIndexed: buffer.neverIndexed
            )
            sink?.deliverResponseData(streamID: clientID, buffer.data, endStream: false)
            return false
        }
        responseStreams[clientID] = .buffering(buffer)
        if endStream { return runResponseScripts(clientID) }
        return false
    }

    private func creditConnectionWindow(_ byteCount: Int) {
        guard byteCount > 0 else { return }
        unannouncedConnCredit += byteCount
    }

    private func creditStreamWindow(_ upstreamStreamID: UInt32, _ byteCount: Int) {
        guard byteCount > 0 else { return }
        unannouncedStreamCredit[upstreamStreamID, default: 0] += byteCount
    }

    private func ackUpstream(upstreamStreamID: UInt32, length: Int) {
        creditStreamWindow(upstreamStreamID, length)
        creditConnectionWindow(length)
    }

    func creditDrainedResponse(clientID: UInt32, _ byteCount: Int) {
        guard phase != .torn, byteCount > 0, drainCoupledStreams.contains(clientID), let upstreamStreamID = upstreamStreamIDByClient[clientID] else { return }
        creditStreamWindow(upstreamStreamID, byteCount)
        announceStreamCreditIfDue(upstreamStreamID)
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
        sink?.deliverResponseHead(
            streamID: streamID,
            status: status,
            headers: headers,
            endStream: body.isEmpty && trailers.isEmpty,
            neverIndexed: neverIndexed
        )
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
            originalURL: buffer.originatingRequest?.originalURL,
            status: buffer.status,
            headers: scriptedHeaders.filter { !$0.name.hasPrefix(":") },
            body: plaintext,
            ruleSetID: rewriter.ruleSetID
        )
        let rewriter = self.rewriter
        Task { [weak self] in
            let outcome = await rewriter.applyScripts(message, phase: .httpResponse)
            guard let self else { return }
            self.sessionContext.enqueue {
                self.assumeIsolated { leg in
                    guard leg.phase != .torn else { return }
                    let regular = scriptedHeaders.filter { !$0.name.hasPrefix(":") }
                    let original = buffer.headers.filter { !$0.name.hasPrefix(":") }
                    switch outcome {
                    case .message(let updated) where updated.body == plaintext:
                        leg.deliverFinalResponse(
                            streamID: streamID,
                            status: buffer.status,
                            headers: original,
                            body: buffer.data,
                            trailers: trailers,
                            neverIndexed: buffer.neverIndexed
                        )
                    case .message(let updated):
                        var body = updated.body
                        if body.count > plaintext.count, body.count - plaintext.count > Self.maxBufferedRewriteGrowthBytes {
                            logger.warning("[MITM] \(leg.host): Rewritten body too large")
                            body = plaintext
                        }
                        leg.deliverFinalResponse(
                            streamID: streamID,
                            status: buffer.status,
                            headers: regular,
                            body: body,
                            trailers: trailers,
                            neverIndexed: buffer.neverIndexed
                        )
                    case .synthesizedResponse:
                        leg.deliverFinalResponse(
                            streamID: streamID,
                            status: buffer.status,
                            headers: original,
                            body: buffer.data,
                            trailers: trailers,
                            neverIndexed: buffer.neverIndexed
                        )
                    }
                }
            }
        }
        return false
    }

    // MARK: Streaming-script response rewrite

    private func handleStreamingData(streamID: UInt32, body: Data, endStream: Bool, trailers: [(name: String, value: String)] = []) -> Bool {
        guard case .streaming(let streamingResponse)? = responseStreams[streamID] else { return false }
        if streamingResponse.cursor.mutable.withLock({ $0.isBypassed }) {
            advanceStreaming(streamID)
            deliverStreamingFrame(streamID: streamID, body: body, endStream: endStream, trailers: trailers)
            return false
        }
        let context = MITMScriptEngine.FrameContext(
            phase: .httpResponse,
            method: streamingResponse.originatingRequest?.method,
            url: streamingResponse.originatingRequest?.url,
            originalURL: streamingResponse.originatingRequest?.originalURL,
            status: streamingResponse.status,
            headers: streamingResponse.headers.filter { !$0.name.hasPrefix(":") },
            frameIndex: streamingResponse.frameIndex,
            isLast: endStream,
            ruleSetID: rewriter.ruleSetID
        )
        let cursor = streamingResponse.cursor
        Task { [weak self] in
            let result = await MITMScriptTransform.applyFrame(
                body,
                frameContext: context,
                cursor: cursor
            )
            guard let self else { return }
            self.sessionContext.enqueue {
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
        if growth > Self.maxStreamingRewriteGrowthBytes { streamingResponse.cursor.mutable.withLock { $0.isBypassed = true } }
        responseStreams[streamID] = .streaming(streamingResponse)
    }
}
