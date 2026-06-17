//
//  MITMHTTP2UpstreamLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMHTTP2UpstreamLeg")

/// One multiplexed HTTP/2 upstream connection for the decoupled bridge. Encodes neutral
/// request IR into upstream h2 (HEADERS + flow-controlled DATA) and decodes h2 responses,
/// runs the response-phase rewrite, and delivers protocol-agnostic response events to the
/// client leg's `MITMResponseSink`.
///
/// The connection is dedicated 1:1 to one client connection but assigns its own
/// monotonically-increasing upstream stream IDs (client requests can arrive reordered,
/// and RFC 9113 §5.1.1 forbids opening a lower ID after a higher one). lwIP-queue-confined.
final class MITMHTTP2UpstreamLeg: MITMUpstreamLeg {

    /// Receives response events (the h2 client leg).
    weak var sink: MITMResponseSink?
    /// Emits upstream-bound bytes (the session writes them to the upstream TLS record).
    var onUpstreamBytes: ((Data) -> Void)?
    /// Unrecoverable upstream-leg error; the session tears the connection down.
    var onFatalError: ((String) -> Void)?
    /// Origin sent GOAWAY: ask the client leg to emit its own so the client redials new
    /// requests on a fresh connection instead of stalling them on this draining one.
    var onDraining: (() -> Void)?

    private let host: String
    private let rewriter: MITMHTTP2Rewriter
    private let flowController: MITMHTTP2FlowController
    private let lwipQueue: DispatchQueue
    private let decoder = HPACKDecoder()

    private typealias Codec = MITMHTTP2FrameCodec

    private static let maxHeaderBlockBytes = 256 * 1024

    private var prefaceSent = false
    private var rxBuffer = MITMByteBuffer()
    private var torn = false
    private var parseError = false
    /// Set when the origin sends GOAWAY: no new upstream streams may be opened (RFC 9113 §6.8).
    /// In-flight streams ≤ the GOAWAY's last-stream-id keep running; new requests are refused.
    private var goingAway = false

    /// Held to re-arm the feed after a *streaming-script* (per-frame) hop parks the pump.
    /// Buffered response scripts (`runResponseScripts`) are non-blocking and never set this, so a
    /// slow/async script doesn't stall the other streams multiplexed on this upstream connection.
    private var parkedCompletion: (() -> Void)?

    private struct Pending {
        let streamID: UInt32
        var fragments: Data
        let originalFlags: UInt8
    }
    private var pending: Pending?

    // MARK: Request side (toward upstream)

    private struct PendingRequestBody {
        var remaining: Data
        var streamWindow: Int
        var endStream: Bool
        /// Request trailers (gRPC etc.) to emit as a trailing HEADERS block with END_STREAM once the
        /// body has fully drained under flow control. nil for the common no-trailer case.
        var pendingTrailers: [(name: String, value: String)]? = nil
    }
    private var pendingRequestBodies: [UInt32: PendingRequestBody] = [:]
    private var openRequestStreams: Set<UInt32> = []

    // MARK: Concurrency limit (SETTINGS_MAX_CONCURRENT_STREAMS)

    /// Provisional ceiling on open upstream streams before the origin's first SETTINGS
    /// tells us its real limit (RFC 9113 §5.1.2). Mirrors mitmproxy's pre-SETTINGS guess.
    private static let provisionalMaxConcurrentStreams = 10

    /// Origin's advertised SETTINGS_MAX_CONCURRENT_STREAMS (0x3), once observed; sticky
    /// across later SETTINGS that omit it. nil until the origin first advertises a value.
    private var serverMaxConcurrentStreams: Int?
    /// Set once any non-ACK SETTINGS arrives: an origin that sends SETTINGS without a 0x3
    /// imposes no limit (RFC 9113 §6.5.2 "Initially, there is no limit"), so we lift the guess.
    private var firstSettingsSeen = false

    /// The live cap on concurrently-open upstream streams: the origin's value if advertised,
    /// else unbounded once any SETTINGS arrived, else the provisional guess.
    private var maxConcurrentStreams: Int {
        if let s = serverMaxConcurrentStreams { return s }
        return firstSettingsSeen ? Int.max : Self.provisionalMaxConcurrentStreams
    }

    /// A request held back because opening it would exceed ``maxConcurrentStreams``. Its
    /// HEADERS (and any body/abort that arrive while queued) wait until a stream closes;
    /// the upstream stream ID is assigned at open time so IDs stay monotonic in send order.
    private struct QueuedRequest {
        let head: MITMRequestHead
        let endStreamOnHead: Bool
        var body: [(data: Data, endStream: Bool)] = []
        var bodyBytes = 0
    }
    private var queuedRequests: [UInt32: QueuedRequest] = [:]
    private var queueOrder: [UInt32] = []
    /// Re-entrancy guard: draining can release streams (backlog cap) and re-enter.
    private var draining = false

    /// Client stream IDs can arrive reordered here (a buffered request's HEADERS emit
    /// late), but HTTP/2 forbids opening a stream with a lower ID than one already
    /// opened (RFC 9113 §5.1.1). So each client stream is mapped to a fresh, strictly
    /// increasing upstream stream ID assigned in *send* order, and responses are mapped
    /// back. All internal state (pendingRequestBodies, openRequestStreams, responseStreams)
    /// and the request-log / response-sink boundaries are keyed by the **client** ID; only
    /// the wire frames use the upstream ID.
    private var ourStreamID: [UInt32: UInt32] = [:]   // client → upstream
    private var theirStreamID: [UInt32: UInt32] = [:] // upstream → client
    private var nextUpstreamStreamID: UInt32 = 1

    /// Assigns (or returns) the upstream stream ID for a client stream.
    private func upstreamID(forClient clientID: UInt32) -> UInt32 {
        if let existing = ourStreamID[clientID] { return existing }
        let sid = nextUpstreamStreamID
        nextUpstreamStreamID += 2
        ourStreamID[clientID] = sid
        theirStreamID[sid] = clientID
        return sid
    }

    /// Releases every per-stream record for a finished or reset client stream — including
    /// the upstream stream-ID mapping, which would otherwise accumulate for the life of
    /// this (long-lived, multiplexed) connection.
    private func releaseStream(clientID: UInt32, resetOrigin: Bool = false) {
        // When we abandon a stream the origin still considers open — the response never reached
        // END_STREAM, or our request body never finished — the caller passes `resetOrigin` so we RST
        // it. Otherwise the origin's stream and one of its MAX_CONCURRENT_STREAMS slots leak for the
        // life of this long-lived multiplexed connection. Clean completions and origin-initiated
        // closes (RST/GOAWAY, or a site that already sent its own RST) pass false so we don't
        // re-RST a stream that is already closing.
        if resetOrigin, let sid = ourStreamID[clientID] {
            onUpstreamBytes?(Codec.rstStream(streamID: sid, errorCode: Codec.ErrorCode.cancel))
        }
        responseStreams.removeValue(forKey: clientID)
        drainCoupledStreams.remove(clientID)
        pendingRequestBodies.removeValue(forKey: clientID)
        openRequestStreams.remove(clientID)
        if let sid = ourStreamID.removeValue(forKey: clientID) { theirStreamID.removeValue(forKey: sid) }
        // A concurrency slot may have just freed; open as many queued requests as now fit.
        drainQueue()
    }

    /// Opens queued requests in FIFO order while a concurrency slot is free. The upstream
    /// stream ID is assigned here (at open time), so IDs remain monotonically increasing in
    /// the order HEADERS hit the wire (RFC 9113 §5.1.1) even though requests were reordered.
    private func drainQueue() {
        guard !draining else { return }
        draining = true
        defer { draining = false }
        while ourStreamID.count < maxConcurrentStreams, let clientID = queueOrder.first {
            queueOrder.removeFirst()
            guard let q = queuedRequests.removeValue(forKey: clientID) else { continue }
            openUpstreamStream(q.head, endStream: q.endStreamOnHead)
            for chunk in q.body { sendRequestData(streamID: clientID, chunk.data, endStream: chunk.endStream) }
        }
    }

    private func dropFromQueue(_ clientID: UInt32) {
        guard queuedRequests.removeValue(forKey: clientID) != nil else { return }
        queueOrder.removeAll { $0 == clientID }
    }

    /// Refuses every still-queued (never-sent) request: the origin never saw them, so
    /// REFUSED_STREAM tells the client they're safe to retry (RFC 9113 §6.8 / §8.1.4).
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
        var headers: [(name: String, value: String)]   // regular, post header-rewrite
        let originatingRequest: MITMRequestLog.Record?
        /// Names the upstream marked never-indexed, preserved for the client re-encode (RFC 7541 §7.1.3).
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

    /// Born-passthrough response streams whose per-stream receive credit is **deferred** until
    /// the client drains the bytes (`creditDrainedResponse`), so a slow client backpressures the
    /// origin rather than overflowing the client-bound buffer. Buffered/streaming (rewriting)
    /// streams and the buffer-overflow→passthrough fallback stay eager-credited and are absent here.
    private var drainCoupledStreams: Set<UInt32> = []

    /// Receive-window credit (toward the origin) accumulated during one pass and flushed once at
    /// `finishPass` (and at the end of the out-of-pass `creditDrainedResponse`), so a burst of DATA
    /// frames yields one WINDOW_UPDATE per stream plus one for the connection instead of a pair per
    /// frame. Flushing every pass keeps the window from stalling. Keyed by upstream (wire) stream id.
    private var batchedConnCredit = 0
    private var batchedStreamCredit: [UInt32: Int] = [:]

    private static let maxBufferedRewriteGrowthBytes = 65_535
    private static let maxStreamingRewriteGrowthBytes = 65_535

    /// Upstream-bound request backlog cap. Generous: a draining upstream never approaches
    /// it; only a stalled flow-control window plus a large upload trips it.
    private static let maxUpstreamBufferedBytes = 8 * 1024 * 1024

    /// Receive window the leg advertises to the origin — per-stream via SETTINGS_INITIAL_WINDOW_SIZE
    /// and the connection via an initial WINDOW_UPDATE. The 64 KiB default throttles a single
    /// download to ~64 KiB/RTT (mitmproxy raises it to 2³¹−1 for the same reason); 4 MiB fills a
    /// high bandwidth·delay path while staying under the 8 MiB client-bound cap, so a drain-coupled
    /// stream stalls the origin (backpressure) before it can overflow that buffer.
    private static let receiveWindow = 4 * 1024 * 1024

    init(
        host: String,
        rewriter: MITMHTTP2Rewriter,
        flowController: MITMHTTP2FlowController,
        lwipQueue: DispatchQueue
    ) {
        self.host = host
        self.rewriter = rewriter
        self.flowController = flowController
        self.lwipQueue = lwipQueue
    }

    func markTorn() {
        torn = true
        parkedCompletion = nil
        rxBuffer = MITMByteBuffer()
        pendingRequestBodies.removeAll()
        responseStreams.removeAll()
        drainCoupledStreams.removeAll()
        openRequestStreams.removeAll()
        queuedRequests.removeAll()
        queueOrder.removeAll()
        ourStreamID.removeAll()
        theirStreamID.removeAll()
        batchedConnCredit = 0
        batchedStreamCredit.removeAll()
        pending = nil
    }

    /// Sends the HTTP/2 client connection preface (magic + SETTINGS) once. SETTINGS carries
    /// ENABLE_PUSH=0 (no server push, RFC 9113 §6.5.2) and an enlarged INITIAL_WINDOW_SIZE so a
    /// single download isn't throttled to ~64 KiB/RTT.
    private func ensurePrefaceSent() {
        guard !prefaceSent else { return }
        prefaceSent = true
        var d = Data("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        Codec.appendFrameHeader(typeCode: Codec.FrameType.settings, flags: 0, streamID: 0, payloadLength: 18, into: &d)
        d.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]) // SETTINGS_ENABLE_PUSH = 0
        let w = UInt32(Self.receiveWindow)
        d.append(contentsOf: [0x00, 0x04, // SETTINGS_INITIAL_WINDOW_SIZE (per-stream)
                              UInt8((w >> 24) & 0xFF), UInt8((w >> 16) & 0xFF),
                              UInt8((w >> 8) & 0xFF), UInt8(w & 0xFF)])
        // Bound the decoded response-header list so a conformant origin self-limits (we also enforce
        // it in the HPACK decoder — RFC 9113 §6.5.2).
        let maxHeaderList = UInt32(HPACKDecoder.maxDecodedHeaderListSize)
        d.append(contentsOf: [0x00, 0x06, // SETTINGS_MAX_HEADER_LIST_SIZE
                              UInt8((maxHeaderList >> 24) & 0xFF), UInt8((maxHeaderList >> 16) & 0xFF),
                              UInt8((maxHeaderList >> 8) & 0xFF), UInt8(maxHeaderList & 0xFF)])
        onUpstreamBytes?(d)
        // INITIAL_WINDOW_SIZE doesn't move the connection window (RFC 9113 §6.9.2); raise it
        // explicitly so the connection isn't the ~64 KiB bottleneck either. Direct emit (not the
        // batched path): this enlargement must reach the origin before any DATA pass, or the origin
        // throttles the first response to the 64 KiB default.
        onUpstreamBytes?(Codec.windowUpdate(streamID: 0, increment: Self.receiveWindow - 65_535))
    }

    // MARK: - MITMUpstreamLeg (request IR → upstream h2)

    func sendRequestHead(_ head: MITMRequestHead, endStream: Bool) {
        guard !torn else { return }
        // The origin is going away and won't open new streams; refuse so the client retries on
        // a fresh connection (it already got our GOAWAY) rather than stalling on this one.
        guard !goingAway else {
            sink?.deliverResponseReset(streamID: head.clientStreamID, errorCode: Codec.ErrorCode.refusedStream)
            return
        }
        // Send our preface eagerly even when queueing: it prompts the origin's SETTINGS,
        // which carries the real concurrency limit and lets us drain the queue sooner.
        ensurePrefaceSent()
        // RFC 9113 §5.1.2: never open more concurrent streams than the origin allows. Hold
        // the request back rather than let the origin REFUSED_STREAM it; drained as slots free.
        guard ourStreamID.count < maxConcurrentStreams else {
            queuedRequests[head.clientStreamID] = QueuedRequest(head: head, endStreamOnHead: endStream)
            queueOrder.append(head.clientStreamID)
            return
        }
        openUpstreamStream(head, endStream: endStream)
    }

    /// Assigns the upstream stream ID and emits the request HEADERS. Caller has confirmed a
    /// concurrency slot is free.
    private func openUpstreamStream(_ head: MITMRequestHead, endStream: Bool) {
        // RFC 9113 §5.1.1: client-initiated stream IDs are 31-bit and can't be reused. Past the
        // last one, the connection can't open more — tear down (the client redials with fresh IDs)
        // rather than overflow `nextUpstreamStreamID` into a trap or a masked-ID collision.
        guard nextUpstreamStreamID <= 0x7FFF_FFFF else {
            fail("upstream HTTP/2 stream IDs exhausted")
            return
        }
        let clientID = head.clientStreamID
        let sid = upstreamID(forClient: clientID)
        openRequestStreams.insert(clientID)
        var block: [(name: String, value: String)] = [
            (name: ":method", value: head.method),
            (name: ":scheme", value: head.scheme),
            (name: ":authority", value: head.authority),
            (name: ":path", value: head.path),
        ]
        // RFC 9113 §8.2.1: header field names MUST be lowercase in HTTP/2.
        for (name, value) in head.headers {
            block.append((name: name.lowercased(), value: value))
        }
        onUpstreamBytes?(Codec.emitHeaders(
            streamID: sid,
            block: HPACKEncoder.encodeHeaderBlock(block, neverIndexed: head.neverIndexed),
            endStream: endStream
        ))
        if endStream {
            openRequestStreams.remove(clientID)
        } else {
            // Track the request-body send window from stream open so a WINDOW_UPDATE that lands
            // before the first DATA isn't lost (the origin may grant credit up front, RFC 9113 §6.9.2).
            pendingRequestBodies[clientID] = PendingRequestBody(
                remaining: Data(), streamWindow: flowController.serverInitialStreamWindow, endStream: false)
        }
    }

    func sendRequestData(streamID: UInt32, _ data: Data, endStream: Bool) {
        let clientID = streamID
        // A queued (not-yet-opened) stream buffers its body so it replays after HEADERS. The
        // client's upload window is credited eagerly, so bound this like an open stream's backlog
        // (the queue usually drains in milliseconds; this only guards a pathological client).
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
        guard !torn, openRequestStreams.contains(clientID) else { return }
        var entry = pendingRequestBodies[clientID]
            ?? PendingRequestBody(remaining: Data(), streamWindow: flowController.serverInitialStreamWindow, endStream: false)
        entry.remaining.append(data)
        if endStream { entry.endStream = true }
        pendingRequestBodies[clientID] = entry
        flushRequestBody(clientID)
        // The client leg credits the client's upload window eagerly, so a stalled upstream
        // flow-control window would let the backlog grow without bound. Reset the stream
        // rather than buffer an unbounded body.
        if let backlog = pendingRequestBodies[clientID]?.remaining.count, backlog > Self.maxUpstreamBufferedBytes {
            logger.warning("h2-upstream \(host) stream \(clientID): request backlog \(backlog) B over cap; resetting stream")
            if let sid = ourStreamID[clientID] {
                onUpstreamBytes?(Codec.rstStream(streamID: sid, errorCode: Codec.ErrorCode.internalError))
            }
            releaseStream(clientID: clientID)
            sink?.deliverResponseReset(streamID: clientID)
        }
    }

    func abortRequest(streamID: UInt32) {
        guard !torn else { return }
        let clientID = streamID
        // Still queued ⇒ never opened upstream; just discard it (no RST to send, no slot held).
        if queuedRequests[clientID] != nil {
            dropFromQueue(clientID)
            return
        }
        if openRequestStreams.contains(clientID), let sid = ourStreamID[clientID] {
            onUpstreamBytes?(Codec.rstStream(streamID: sid, errorCode: Codec.ErrorCode.cancel))
        }
        releaseStream(clientID: clientID)
    }

    func sendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard !torn else { return }
        let clientID = streamID
        // Pseudo-headers are never valid in a trailer section (RFC 9113 §8.1); drop them.
        let fields = trailers.filter { !$0.name.hasPrefix(":") }
        guard !fields.isEmpty else {
            // No forwardable trailers — just end the body like a normal close.
            sendRequestData(streamID: clientID, Data(), endStream: true)
            return
        }
        // Still queued (never opened upstream): we have no stream ID to emit a trailing HEADERS on,
        // and threading trailers through the FIFO replay isn't worth this corner — end the body
        // without them so the queued request still completes when it drains.
        if queuedRequests[clientID] != nil {
            logger.warning("h2-upstream \(host) stream \(clientID): request trailers on a still-queued stream; ending without them")
            queuedRequests[clientID]?.body.append((Data(), true))
            return
        }
        guard openRequestStreams.contains(clientID), let sid = ourStreamID[clientID] else { return }
        if var entry = pendingRequestBodies[clientID], !entry.remaining.isEmpty {
            // Body still draining under flow control — emit the trailers once it finishes.
            entry.endStream = true
            entry.pendingTrailers = fields
            pendingRequestBodies[clientID] = entry
            flushRequestBody(clientID)
        } else {
            // Body already drained (or none) — emit the trailing HEADERS with END_STREAM now.
            pendingRequestBodies.removeValue(forKey: clientID)
            emitRequestTrailers(sid: sid, fields)
            openRequestStreams.remove(clientID)
        }
    }

    /// Emits request trailers as a trailing HEADERS block with END_STREAM (RFC 9113 §8.1).
    private func emitRequestTrailers(sid: UInt32, _ trailers: [(name: String, value: String)]) {
        let block = trailers.map { (name: $0.name.lowercased(), value: $0.value) }
        onUpstreamBytes?(Codec.emitHeaders(
            streamID: sid,
            block: HPACKEncoder.encodeHeaderBlock(block),
            endStream: true
        ))
    }

    /// Sends as much of a pending request body as the connection and stream windows allow, up to `cap`
    /// bytes (the round-robin distributor passes a single max-frame cap; direct callers leave it
    /// unbounded). Returns whether it made progress so the distributor knows to keep cycling.
    @discardableResult
    private func flushRequestBody(_ clientID: UInt32, cap: Int = .max) -> Bool {
        guard var entry = pendingRequestBodies[clientID], let sid = ourStreamID[clientID] else { return false }
        let available = max(0, min(flowController.serverConnectionWindow, entry.streamWindow, entry.remaining.count, cap))
        if available > 0 {
            let chunk = entry.remaining.prefix(available)
            entry.remaining.removeFirst(available)
            let bodyDone = entry.endStream && entry.remaining.isEmpty
            // With trailers pending, END_STREAM rides the trailing HEADERS, not the final DATA.
            onUpstreamBytes?(Codec.frameData(streamID: sid, payload: chunk,
                                             endStream: bodyDone && entry.pendingTrailers == nil))
            flowController.debitServerConnection(available)
            entry.streamWindow -= available
            if bodyDone {
                if let trailers = entry.pendingTrailers { emitRequestTrailers(sid: sid, trailers) }
                pendingRequestBodies.removeValue(forKey: clientID)
                openRequestStreams.remove(clientID)
                return true
            }
        } else if entry.remaining.isEmpty, entry.endStream {
            if let trailers = entry.pendingTrailers {
                emitRequestTrailers(sid: sid, trailers)
            } else {
                onUpstreamBytes?(Codec.frameData(streamID: sid, payload: Data(), endStream: true))
            }
            pendingRequestBodies.removeValue(forKey: clientID)
            openRequestStreams.remove(clientID)
            return true
        }
        // Otherwise the upstream's flow-control window is exhausted; resume on its next WINDOW_UPDATE.
        pendingRequestBodies[clientID] = entry
        return available > 0
    }

    /// Distributes the available upstream connection window across pending request bodies by an equal
    /// share each, so a large upload on one stream can't drain it all first and starve its siblings
    /// (mitmproxy distributes evenly). One `flushRequestBody` per stream — same cost as draining them
    /// in turn — but each is capped to its fair slice; window a stream can't use flows to those after.
    private func distributeServerConnectionWindow() {
        // Only streams with unsent body contend for the connection window. Counting idle streams would
        // shrink each share and leave window unused until the next WINDOW_UPDATE — a stall — so a sole
        // sender must see the full window.
        let ready = pendingRequestBodies.keys.filter { !(pendingRequestBodies[$0]?.remaining.isEmpty ?? true) }.sorted()
        var remaining = ready.count
        for id in ready {
            guard flowController.serverConnectionWindow > 0 else { break }
            // Floor at one frame so a stream is never starved to a sub-frame slice; flushRequestBody
            // re-clamps to the true remaining window, so the floor can't overspend it.
            let share = max(Codec.maxFramePayloadSize, flowController.serverConnectionWindow / max(1, remaining))
            flushRequestBody(id, cap: share)
            remaining -= 1
        }
    }

    // MARK: - Upstream h2 → response IR

    func feed(_ data: Data, completion: @escaping () -> Void) {
        guard parkedCompletion == nil else {
            logger.error("h2-upstream \(host): feed re-entered while parked; dropping chunk")
            completion()
            return
        }
        if parseError || torn { completion(); return }
        rxBuffer.append(data)
        parkedCompletion = completion
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
                if parseError { return false }
            }
        }
    }

    private func finishPass(parked: Bool) {
        // Flush every pass (parked or not) so coalesced receive-window credit reaches the origin
        // before it can stall on a depleted window, and never lingers across a script hop.
        flushBatchedCredits()
        if parked { return }
        let c = parkedCompletion; parkedCompletion = nil; c?()
    }

    /// Emits the WINDOW_UPDATEs accumulated this pass — one per credited stream plus one for the
    /// connection — then clears the batch. A stream-level update for a since-released stream is
    /// harmless (the origin ignores WINDOW_UPDATE on a closed stream, RFC 9113 §5.1).
    private func flushBatchedCredits() {
        if batchedConnCredit > 0 {
            onUpstreamBytes?(Codec.windowUpdate(streamID: 0, increment: batchedConnCredit))
            batchedConnCredit = 0
        }
        guard !batchedStreamCredit.isEmpty else { return }
        for (sid, n) in batchedStreamCredit where n > 0 {
            onUpstreamBytes?(Codec.windowUpdate(streamID: sid, increment: n))
        }
        batchedStreamCredit.removeAll(keepingCapacity: true)
    }

    private func resumeAfterScript() {
        guard !torn, !parseError else { let c = parkedCompletion; parkedCompletion = nil; c?(); return }
        let parked = pump()
        finishPass(parked: parked)
    }

    private func fail(_ message: String) {
        guard !parseError else { return }
        parseError = true
        rxBuffer = MITMByteBuffer()
        pending = nil
        logger.warning("h2-upstream \(host): \(message); tearing down")
        onFatalError?(message)
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
            if frame.flags & 0x1 == 0 { onUpstreamBytes?(Codec.pingAck(opaque: frame.payload)) }
        case Codec.FrameType.rstStream:    handleUpstreamRST(frame)
        case Codec.FrameType.goaway:       handleGoAway(frame)
        case Codec.FrameType.pushPromise:
            // We advertise ENABLE_PUSH=0, so a PUSH_PROMISE is a protocol violation (RFC 9113 §6.6);
            // tear down rather than leave the promised stream half-tracked.
            fail("upstream sent PUSH_PROMISE despite ENABLE_PUSH=0")
        default:                           break
        }
        return false
    }

    private func handleSettings(_ frame: Codec.RawFrame) {
        guard frame.streamID == 0 else { fail("upstream SETTINGS on non-zero stream"); return }
        if frame.flags & 0x1 != 0 { return } // ACK of our SETTINGS; nothing to apply
        let payload = frame.payload
        var i = payload.startIndex
        // RFC 9113 §6.5 makes a SETTINGS length not a multiple of 6 a FRAME_SIZE_ERROR. We apply
        // whole 6-byte entries and ignore any trailing remainder instead: tolerating a quirky
        // origin is safer for a transparent MITM than tearing down a working connection.
        while i + 6 <= payload.endIndex {
            let identifier = (UInt16(payload[i]) << 8) | UInt16(payload[i + 1])
            let value = (UInt32(payload[i + 2]) << 24) | (UInt32(payload[i + 3]) << 16)
                | (UInt32(payload[i + 4]) << 8) | UInt32(payload[i + 5])
            if identifier == 0x4 { applyServerInitialWindowSize(Int(value)) }
            if identifier == 0x3 { serverMaxConcurrentStreams = Int(value) } // SETTINGS_MAX_CONCURRENT_STREAMS
            i += 6
        }
        firstSettingsSeen = true
        onUpstreamBytes?(Codec.settingsAck())
        // The limit may have risen (provisional guess → real value, or an increase); open
        // anything now permitted.
        drainQueue()
    }

    private func applyServerInitialWindowSize(_ newValue: Int) {
        let delta = flowController.updateServerInitialStreamWindow(newValue)
        guard delta != 0 else { return }
        for id in pendingRequestBodies.keys { pendingRequestBodies[id]?.streamWindow += delta }
        if delta > 0 { distributeServerConnectionWindow() }
    }

    private func handleWindowUpdate(_ frame: Codec.RawFrame) {
        // RFC 9113 §6.9.1 makes a 0 increment a PROTOCOL_ERROR; we ignore it (and a malformed,
        // non-4-byte payload) rather than reset — there's nothing to credit, and dropping a quirky
        // frame is safer for a MITM than tearing the upstream down. Over-credit past 2^31-1 is
        // clamped in the flow controller, so we simply send less than the origin offered.
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
        // Relay the origin's own error code so the client keeps a retriable REFUSED_STREAM
        // distinct from a fatal reset (RFC 9113 §7) instead of always seeing INTERNAL_ERROR.
        sink?.deliverResponseReset(streamID: clientID, errorCode: Self.rstErrorCode(frame.payload))
    }

    /// The 32-bit error code in an RST_STREAM payload (RFC 9113 §6.4); INTERNAL_ERROR if malformed.
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
        // lastStreamID is in upstream-id space; reset every mapped client stream above it —
        // including requests already sent but not yet answered (in-flight, not in responseStreams),
        // which the upstream is abandoning and would otherwise hang waiting for a response.
        for (clientID, upstreamID) in Array(ourStreamID) where upstreamID > lastStreamID {
            releaseStream(clientID: clientID)
            // Above last-stream-id ⇒ the origin never processed these (RFC 9113 §6.8), so
            // REFUSED_STREAM tells the client they're safe to retry rather than fatal.
            sink?.deliverResponseReset(streamID: clientID, errorCode: Codec.ErrorCode.refusedStream)
        }
        // The origin won't accept new streams now. Stop opening ours, refuse anything still
        // queued (never sent ⇒ retriable), and have the client leg emit its own GOAWAY so the
        // client redials new requests elsewhere. In-flight streams ≤ lastStreamID keep draining;
        // the connection closes naturally when the origin finally drops it (read EOF → teardown).
        if !goingAway {
            goingAway = true
            refuseAllQueued()
            onDraining?()
        }
    }

    // MARK: Response HEADERS

    private func handleHeaders(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else { fail("HEADERS on stream 0"); return false }
        // Invalid padding is a connection error (RFC 9113 §6.1); skipping it would leave the
        // undecoded block out of the persistent HPACK table and desync every later HEADERS.
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
        if p.fragments.count + frame.payload.count > Self.maxHeaderBlockBytes { fail("header block over cap"); return false }
        p.fragments.append(frame.payload)
        if frame.flags & 0x4 != 0 {
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
        // `streamID` is the upstream wire ID; map back to the client stream for all
        // state, request-log, and sink delivery.
        let clientID = theirStreamID[streamID] ?? streamID

        // RFC 9113 §8.3: validate the response pseudo-header section (only :status, leading, no
        // duplicates). A malformed block from the origin is a protocol error — tear down (matching
        // the missing-:status handling below) so a malformed response is never re-encoded to the client.
        guard MITMBridgeHeaders.pseudoHeadersValid(decoded, isRequest: false) else {
            fail("malformed response pseudo-header section")
            return false
        }

        // RFC 9113 §8.2.1/§8.1.1: a response field with CR/LF/NUL or a non-tchar name is malformed.
        // Treat it as a stream error (not a connection teardown — the HPACK table absorbed the block,
        // so the connection stays in sync) and never re-encode the laundered bytes to the client.
        guard http2HeaderOctetsValid(decoded) else {
            logger.warning("h2-upstream \(host) stream \(clientID): response header with CR/LF/NUL or invalid field-name; resetting stream")
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        // A HEADERS on an already-open response stream is a trailer (carries END_STREAM). Relay
        // its fields as the terminal frame once the body finalizes — gRPC puts grpc-status here,
        // so dropping it breaks the call.
        if responseStreams[clientID] != nil {
            // A trailer HEADERS MUST set END_STREAM (RFC 9113 §8.1); a non-final second HEADERS would
            // otherwise truncate the response. Reset the stream rather than mis-finalize it.
            guard endStream else {
                logger.warning("h2-upstream \(host) stream \(clientID): response trailer without END_STREAM; resetting stream")
                sink?.deliverResponseReset(streamID: clientID)
                releaseStream(clientID: clientID, resetOrigin: true)
                return false
            }
            let trailerFields = decoded.filter { !$0.name.hasPrefix(":") }
            return finishResponseStream(streamID: clientID, endStream: true, trailers: trailerFields)
        }

        guard let rawStatus = firstHeaderValue(decoded, name: ":status"),
              let status = parseHTTPStatusCode(rawStatus) else {
            fail("response missing :status")
            return false
        }

        // Interim 1xx (not 101): not the final response, so keep the request-log record for the
        // response that follows. Forward it to the client as its own interim HEADERS — e.g. 103
        // Early Hints, whose preload links are useful before the final response (RFC 9113 §8.1 /
        // RFC 8297). Response header rules target the final response, so the interim's regular
        // fields are relayed as-is.
        let isInterim = (100..<200).contains(status) && status != 101
        let originatingRequest = isInterim
            ? rewriter.requestLog.peekHTTP2(streamID: clientID)
            : rewriter.requestLog.popHTTP2(streamID: clientID)
        if isInterim {
            sink?.deliverResponseInterim(streamID: clientID, status: status, headers: decoded.filter { !$0.name.hasPrefix(":") })
            return false
        }
        if status == 101 {
            // 101 has no place in h2 (it uses extended CONNECT); reset and drop the stream.
            sink?.deliverResponseReset(streamID: clientID)
            releaseStream(clientID: clientID, resetOrigin: true)
            return false
        }

        let responseURL = originatingRequest?.url
        let rewritten = rewriter.transformResponseHeaders(decoded, streamID: clientID, requestURL: responseURL)
        let regular = rewritten.filter { !$0.name.hasPrefix(":") }

        // HEAD responses and 204/304 carry no body.
        let isHead = originatingRequest?.method?.uppercased() == "HEAD"
        if endStream || isHead || status == 204 || status == 304 {
            sink?.deliverResponseHead(streamID: clientID, status: status, headers: regular, endStream: true, neverIndexed: neverIndexed)
            // We tell the client the response is over, but the origin only really ended it if it set
            // END_STREAM; a HEAD/204/304 whose origin omitted it (or a request body still in flight)
            // leaves the origin stream open — RST it so it isn't leaked.
            releaseStream(clientID: clientID, resetOrigin: !endStream || openRequestStreams.contains(clientID))
            return false
        }

        if rewriter.hasStreamScriptRule(phase: .httpResponse, requestURL: responseURL) {
            sink?.deliverResponseHead(streamID: clientID, status: status, headers: MITMBridgeHeaders.droppingContentLength(regular), endStream: false, neverIndexed: neverIndexed)
            responseStreams[clientID] = .streaming(StreamingResponse(
                status: status, headers: rewritten, originatingRequest: originatingRequest,
                cursor: MITMScriptTransform.FrameCursor()
            ))
            return false
        }

        if rewriter.hasBufferedBodyRule(phase: .httpResponse, requestURL: responseURL) {
            let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewritten, name: "content-encoding"))
            responseStreams[clientID] = .buffering(BufferedResponse(
                data: Data(), codec: codec, status: status,
                headers: rewritten, originatingRequest: originatingRequest, neverIndexed: neverIndexed
            ))
            return false
        }

        // Passthrough: stream the body as it arrives. Drain-coupled so a slow client
        // backpressures the origin instead of overflowing the client-bound buffer.
        sink?.deliverResponseHead(streamID: clientID, status: status, headers: regular, endStream: false, neverIndexed: neverIndexed)
        responseStreams[clientID] = .passthrough
        drainCoupledStreams.insert(clientID)
        return false
    }

    // MARK: Response DATA

    private func handleData(_ frame: Codec.RawFrame) -> Bool {
        guard frame.streamID != 0 else { fail("DATA on stream 0"); return false }
        let onWireLength = frame.payload.count
        guard let body = Codec.stripDataPadding(payload: frame.payload, flags: frame.flags) else { return false }
        let endStream = frame.flags & 0x1 != 0
        let sid = frame.streamID
        guard let clientID = theirStreamID[sid] else {
            // DATA on a stream we already released (late frames after a reset/completion). The
            // per-stream window is gone, but the bytes still count against the connection window —
            // credit it or our receive window toward the upstream leaks (RFC 9113 §6.9.1).
            creditConnectionWindow(onWireLength)
            return false
        }

        switch responseStreams[clientID] {
        case .passthrough:
            // Connection window credited eagerly (aggregate stays open). Per-stream credit is the
            // backpressure lever: for a drain-coupled passthrough it waits until the client drains
            // the bytes (`creditDrainedResponse`), so a slow client stalls the origin instead of
            // overflowing the client buffer. Padding never reaches the client, so credit it now.
            creditConnectionWindow(onWireLength)
            if drainCoupledStreams.contains(clientID) {
                creditStreamWindow(sid, onWireLength - body.count) // padding only; body waits for drain
            } else {
                creditStreamWindow(sid, onWireLength) // overflow→passthrough fallback stays eager
            }
            sink?.deliverResponseData(streamID: clientID, body, endStream: endStream)
            // Response done; if the client never finished uploading, the origin's request half is
            // still open — RST so the stream isn't leaked on this multiplexed connection.
            if endStream { releaseStream(clientID: clientID, resetOrigin: openRequestStreams.contains(clientID)) }
            return false

        case .buffering(var buf):
            // We pull the whole body in to rewrite it (bounded by maxBufferedBodyBytes), so credit eagerly.
            ackUpstream(upstreamStreamID: sid, length: onWireLength)
            buf.data.append(body)
            if !endStream, buf.data.count > MITMBodyCodec.maxBufferedBodyBytes {
                // Overflow: emit head + buffered prefix as passthrough, forward the rest. Stays
                // eager-credited (not added to drainCoupledStreams) since the prefix already was.
                sink?.deliverResponseHead(streamID: clientID, status: buf.status,
                                          headers: buf.headers.filter { !$0.name.hasPrefix(":") }, endStream: false,
                                          neverIndexed: buf.neverIndexed)
                sink?.deliverResponseData(streamID: clientID, buf.data, endStream: false)
                responseStreams[clientID] = .passthrough
                return false
            }
            responseStreams[clientID] = .buffering(buf)
            if endStream { return runResponseScripts(clientID) }
            return false

        case .streaming:
            // Per-frame rewrite; credit eagerly (frames are small, the 8 MiB client cap backstops).
            ackUpstream(upstreamStreamID: sid, length: onWireLength)
            return handleStreamingData(streamID: clientID, body: body, endStream: endStream)

        case nil:
            // DATA before HEADERS, or on a closed stream — ignore, but credit so the window doesn't leak.
            ackUpstream(upstreamStreamID: sid, length: onWireLength)
            return false
        }
    }

    /// Credits the origin's connection (stream-0) receive window. Always eager: it keeps the
    /// aggregate window open while per-stream windows do the actual backpressure, and crediting
    /// every received byte exactly once keeps the connection window from leaking shut.
    private func creditConnectionWindow(_ n: Int) {
        guard n > 0 else { return }
        // Accumulate; flushed at `finishPass` (or the end of `creditDrainedResponse` off-pass).
        batchedConnCredit += n
    }

    /// Credits one stream's receive window on the wire.
    private func creditStreamWindow(_ upstreamStreamID: UInt32, _ n: Int) {
        guard n > 0 else { return }
        batchedStreamCredit[upstreamStreamID, default: 0] += n
    }

    /// Eager credit of both windows — used where the leg consumes the bytes itself (buffered/
    /// streaming rewrite, or DATA on a closed stream) rather than passing them through to pace.
    private func ackUpstream(upstreamStreamID: UInt32, length: Int) {
        creditStreamWindow(upstreamStreamID, length)
        creditConnectionWindow(length)
    }

    /// Backpressure callback (client leg → here): `n` passthrough body bytes just drained to the
    /// client, so it's now safe to credit the origin's per-stream window by the same amount (1:1
    /// for passthrough). The connection window was already credited eagerly on receipt.
    func creditDrainedResponse(clientID: UInt32, _ n: Int) {
        guard !torn, n > 0, drainCoupledStreams.contains(clientID), let sid = ourStreamID[clientID] else { return }
        creditStreamWindow(sid, n)
        // This runs off the response pump (driven by the client leg draining), so flush now rather
        // than waiting for a `finishPass` that may not come until the next inbound DATA.
        flushBatchedCredits()
    }

    /// Finalizes a response stream when END_STREAM arrives (on DATA or a trailer HEADERS).
    /// `trailers` is non-empty only for a trailer HEADERS; it is relayed as the terminal
    /// frame after the body finalizes, so gRPC's grpc-status survives across all three modes.
    private func finishResponseStream(streamID: UInt32, endStream: Bool, trailers: [(name: String, value: String)] = []) -> Bool {
        switch responseStreams[streamID] {
        case .passthrough:
            releaseStream(clientID: streamID, resetOrigin: openRequestStreams.contains(streamID))
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

    /// Delivers a finalized response head + body, ending on a trailer when present so a
    /// terminal trailer HEADERS (not END_STREAM-on-DATA) carries the stream close.
    private func deliverFinalResponse(
        streamID: UInt32,
        status: Int,
        headers: [(name: String, value: String)],
        body: Data,
        trailers: [(name: String, value: String)],
        neverIndexed: Set<String>
    ) {
        // The body was re-materialized (script edit / decompression), so correct content-length
        // to the bytes actually delivered rather than emit the stale upstream value.
        let headers = MITMBridgeHeaders.settingContentLength(headers, body.count)
        sink?.deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: body.isEmpty && trailers.isEmpty, neverIndexed: neverIndexed)
        if !body.isEmpty { sink?.deliverResponseData(streamID: streamID, body, endStream: trailers.isEmpty) }
        if !trailers.isEmpty { sink?.deliverResponseTrailers(streamID: streamID, trailers) }
    }

    /// Delivers one streaming frame, ending on a trailer when present: the trailer carries
    /// END_STREAM, so the (possibly script-rewritten) final body goes out non-terminal first.
    private func deliverStreamingFrame(
        streamID: UInt32,
        body: Data,
        endStream: Bool,
        trailers: [(name: String, value: String)]
    ) {
        if endStream, !trailers.isEmpty {
            if !body.isEmpty { sink?.deliverResponseData(streamID: streamID, body, endStream: false) }
            sink?.deliverResponseTrailers(streamID: streamID, trailers)
            releaseStream(clientID: streamID, resetOrigin: openRequestStreams.contains(streamID))
        } else {
            sink?.deliverResponseData(streamID: streamID, body, endStream: endStream)
            if endStream { releaseStream(clientID: streamID, resetOrigin: openRequestStreams.contains(streamID)) }
        }
    }

    // MARK: Buffered response rewrite

    private func runResponseScripts(_ streamID: UInt32, trailers: [(name: String, value: String)] = []) -> Bool {
        guard case .buffering(let buf)? = responseStreams[streamID] else { return false }
        // The body is complete (END_STREAM seen), so the stream is done once the script
        // delivers; release it now — the async completion delivers by client ID, not the maps.
        releaseStream(clientID: streamID, resetOrigin: openRequestStreams.contains(streamID))
        let plaintext: Data
        if buf.codec.requiresDecompression {
            guard let decoded = MITMBodyCodec.decompress(buf.data, plan: buf.codec, host: host) else {
                // Decompression failed: emit head (content-encoding intact) + raw body.
                deliverFinalResponse(streamID: streamID, status: buf.status,
                                     headers: buf.headers.filter { !$0.name.hasPrefix(":") }, body: buf.data,
                                     trailers: trailers, neverIndexed: buf.neverIndexed)
                return false
            }
            plaintext = decoded
        } else {
            plaintext = buf.data
        }
        let scriptedHeaders = buf.codec.requiresDecompression
            ? buf.headers.filter { !$0.name.equalsIgnoringASCIICase("content-encoding") }
            : buf.headers
        let message = HTTPMessage(
            phase: .httpResponse,
            method: buf.originatingRequest?.method,
            url: buf.originatingRequest?.url,
            status: buf.status,
            headers: scriptedHeaders.filter { !$0.name.hasPrefix(":") },
            body: plaintext,
            ruleSetID: rewriter.ruleSetID
        )
        rewriter.applyScripts(message, phase: .httpResponse, resumeOn: lwipQueue) { [weak self] outcome in
            guard let self, !self.torn else { return }
            let regular = scriptedHeaders.filter { !$0.name.hasPrefix(":") }
            switch outcome {
            case .message(let updated):
                var body = updated.body
                if body.count > plaintext.count, body.count - plaintext.count > Self.maxBufferedRewriteGrowthBytes {
                    logger.warning("h2-upstream \(self.host) stream \(streamID): response grew over cap; using original body")
                    body = plaintext
                }
                self.deliverFinalResponse(streamID: streamID, status: buf.status, headers: regular, body: body, trailers: trailers, neverIndexed: buf.neverIndexed)
            case .synthesizedResponse:
                // Anywhere.respond is request-phase only; ignore on response and emit original.
                self.deliverFinalResponse(streamID: streamID, status: buf.status, headers: regular, body: plaintext, trailers: trailers, neverIndexed: buf.neverIndexed)
            }
            // Non-blocking: the stream is already released and the connection pump kept running,
            // so we just deliver here — no re-pump needed. Delivering out of stream order is valid
            // (h2 streams complete independently) and, crucially, keeps a slow/async response
            // script (e.g. one awaiting Anywhere.http) from stalling the *other* streams
            // multiplexed on this one upstream connection.
        }
        // Don't park: a buffered response script runs at END_STREAM, after the stream is released,
        // so sibling streams must keep flowing while it runs. (A per-frame streaming-script still
        // parks — see handleStreamingData — but those are synchronous and short.)
        return false
    }

    // MARK: Streaming-script response rewrite

    /// Runs one response DATA frame through the streaming script and delivers the result.
    /// `frame.end` (isLast) coincides with END_STREAM. `trailers` is set only on the final
    /// (empty) frame of a trailer-terminated stream: the script still sees `isLast`, but the
    /// terminal trailer HEADERS carries END_STREAM instead of the body. Returns true when parked.
    ///
    /// Unlike a buffered response script (`runResponseScripts`, made non-blocking), a streaming
    /// script runs once per DATA frame and must keep per-frame order, so it parks the whole
    /// upstream connection for each frame's script — a residual head-of-line block on sibling
    /// streams. Tolerated because streaming scripts are synchronous and per small frame (they
    /// can't `await Anywhere.http`), so the stall is brief; a full fix needs per-stream frame
    /// queues so siblings keep flowing. See the parked-pump note on `feed`.
    private func handleStreamingData(streamID: UInt32, body: Data, endStream: Bool, trailers: [(name: String, value: String)] = []) -> Bool {
        guard case .streaming(let st)? = responseStreams[streamID] else { return false }
        if st.cursor.bypass {
            advanceStreaming(streamID)
            deliverStreamingFrame(streamID: streamID, body: body, endStream: endStream, trailers: trailers)
            return false
        }
        let ctx = MITMScriptEngine.FrameContext(
            phase: .httpResponse,
            method: st.originatingRequest?.method,
            url: st.originatingRequest?.url,
            status: st.status,
            headers: st.headers.filter { !$0.name.hasPrefix(":") },
            frameIndex: st.frameIndex,
            isLast: endStream,
            ruleSetID: rewriter.ruleSetID
        )
        MITMScriptTransform.applyFrame(
            body,
            rules: rewriter.rules(phase: .httpResponse),
            frameContext: ctx,
            cursor: st.cursor,
            engineProvider: rewriter.scriptEngineProvider,
            resumeOn: lwipQueue
        ) { [weak self] result in
            guard let self, !self.torn else { return }
            self.advanceStreaming(streamID, growth: result.body.count - body.count)
            self.deliverStreamingFrame(streamID: streamID, body: result.body, endStream: endStream, trailers: trailers)
            self.resumeAfterScript()
        }
        return true
    }

    private func advanceStreaming(_ streamID: UInt32, growth: Int = 0) {
        guard case .streaming(var st)? = responseStreams[streamID] else { return }
        st.frameIndex += 1
        // Per-frame growth cap (approximate); a large jump trips bypass for the rest of the stream.
        if growth > Self.maxStreamingRewriteGrowthBytes { st.cursor.bypass = true }
        responseStreams[streamID] = .streaming(st)
    }
}
