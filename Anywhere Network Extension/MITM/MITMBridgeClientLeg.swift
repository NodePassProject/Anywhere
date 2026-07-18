//
//  MITMBridgeClientLeg.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "MITMBridgeClientLeg")

nonisolated protocol MITMBridgeClientLegDelegate: AnyObject {
    /// Session dials (first request) and binds the upstream leg from negotiated ALPN. `url` seeds
    /// the response-phase rewrite correlation.
    func clientLegSendRequestHead(_ head: MITMRequestHead, url: String?, endStream: Bool)
    /// Raw (unframed) request body bytes; the upstream leg applies its own framing.
    func clientLegSendRequestData(streamID: UInt32, _ data: Data, endStream: Bool)
    /// Terminal request trailers (a HEADERS block with no `:method`): h2 forwards a trailing
    /// HEADERS block with END_STREAM, h1 ends the body without them.
    func clientLegSendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    /// Client reset/cancelled the stream: drop its upstream.
    func clientLegAbortRequest(streamID: UInt32)
    /// The response was fully delivered to the client: the session may close the upstream.
    func clientLegResponseComplete(streamID: UInt32)
    /// Write h2 bytes to the client (preface, flow control, responses).
    func clientLegWriteToClient(_ data: Data)
    /// Unrecoverable client-leg error; tear the session down.
    func clientLegFatalError(_ message: String)
}

actor MITMBridgeClientLeg: MITMResponseSink {

    nonisolated var unownedExecutor: UnownedSerialExecutor {
        lwipBridge.executor.asUnownedSerialExecutor()
    }

    weak var delegate: MITMBridgeClientLegDelegate?

    /// Set when the session binds an h2 upstream: as passthrough response bytes drain to the
    /// client, credit the upstream's per-stream flow-control window by the same count so a slow
    /// client backpressures the origin. nil for an h1 upstream (no h2 receive window to credit).
    var onResponseDrainedToClient: ((_ clientStreamID: UInt32, _ byteCount: Int) -> Void)?

    private let host: String
    private let rewriter: MITMHTTP2Rewriter
    private let flowController: MITMHTTP2FlowController
    /// The lwIP concurrency boundary; every queue hop and continuation seam routes through it.
    private let lwipBridge: LWIPConcurrencyBridge
    private let decoder = HPACKDecoder()

    private typealias Codec = MITMHTTP2FrameCodec

    private static let maxHeaderBlockBytes = 256 * 1024
    /// Bounds tracked client streams (each can pin buffers); past it new streams are refused.
    private static let maxTrackedStreams = 256
    /// Advertised SETTINGS_MAX_CONCURRENT_STREAMS. Kept ≤ the session's concurrent-bridge-stream cap
    /// so a conformant client self-throttles below the point we'd answer with REFUSED_STREAM.
    private static let advertisedMaxConcurrentStreams = 128
    /// Client-bound response backlog cap. A draining client never approaches it; a stalled
    /// one (closed or exhausted window) trips it instead of buffering an unbounded response.
    private static let maxClientBufferedBytes = 8 * 1024 * 1024

    /// Receive window advertised to the client (per-stream INITIAL_WINDOW_SIZE + initial connection
    /// WINDOW_UPDATE). The 64 KiB default throttles an upload to ~64 KiB/RTT; 4 MiB fills a high
    /// bandwidth·delay path while staying within the upstream-bound backlog caps.
    private static let receiveWindow = 4 * 1024 * 1024

    // MARK: Connection state

    private var prefaceRemaining = Codec.clientPrefaceLength
    private var rxBuffer = MITMByteBuffer()
    private var serverPrefaceSent = false
    private var torn = false
    private var parseError = false
    private var goAwaySent = false

    /// Held to re-arm the inner pump after a parking script hop. Buffered request scripts are
    /// non-blocking and never set this, so a slow/async script doesn't stall the other streams
    /// multiplexed on this client connection. Resumed exactly once per `feed`.
    private var parkedContinuation: CheckedContinuation<Void, Never>?

    private var highestStreamID: UInt32 = 0

    private struct Pending {
        let streamID: UInt32
        var fragments: Data
        let endStream: Bool
        var continuationCount = 0
    }
    private var pending: Pending?
    /// CONTINUATION-flood guard (CVE-2024-27316 class): bounds CONTINUATION frames per header block,
    /// closing the empty/tiny-CONTINUATION-without-END_HEADERS loop the byte cap alone misses.
    private static let maxContinuationFrames = 1024

    // MARK: Request streams

    private struct BufferedReq {
        var rewrittenHeaders: [(name: String, value: String)] // h2 form, post header-rewrite
        let codec: MITMBodyCodec.Plan
        var data: Data
        /// Names the client marked never-indexed, preserved for the upstream re-encode (RFC 7541 §7.1.3).
        let neverIndexed: Set<String>
        /// True when buffering to run a body script; false when buffering only to frame a
        /// no-declared-length body with Content-Length (no script, no decompression).
        let scripted: Bool
        /// Upstream captured at header-rewrite time, carried through the body-buffering delay so a
        /// concurrent stream's rewrite can't change this dial target.
        let resolvedUpstream: (host: String, port: UInt16?)?
        /// The request URL before the request-phase rewrite, for `ctx.originalUrl` and the request log.
        let originalURL: String?
    }

    private enum RequestStream {
        /// Head emitted; forward raw body bytes (the upstream leg frames them). `remaining` is the
        /// still-unsent declared Content-Length (nil for chunked), enforced so surplus body bytes
        /// can't smuggle a second request.
        case streaming(remaining: Int?)
        /// Accumulating the body for a buffered rewrite; head emitted at END_STREAM.
        case buffering(BufferedReq)
        /// Answered locally (rewrite synth / Anywhere.respond); swallow further DATA.
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
        /// Trailer fields (h2 form) to emit as the terminal HEADERS block once the body drains.
        var pendingTrailers: [(name: String, value: String)]?
    }
    private var paceStates: [UInt32: PaceState] = [:]

    /// Stream-level WINDOW_UPDATE credit that arrived before the stream had a `PaceState`. Folded
    /// into the window when the PaceState is created so the credit isn't lost (RFC 9113 §6.9.2).
    private var pendingStreamCredit: [UInt32: Int] = [:]

    /// Receive-window credit (client uploads) accumulated during one pump pass and flushed at
    /// `finishPass`, coalescing many DATA frames into one WINDOW_UPDATE per stream plus one for the
    /// connection. Safe: the client can't exceed a window's worth before we credit.
    private var batchedConnCredit = 0
    private var batchedStreamCredit: [UInt32: Int] = [:]

    /// Set once the session binds an HTTP/2 upstream: uploads on streams opened from then on are
    /// drain-coupled (see `streamDeferredUpload`). An h1 upstream leaves this false (no origin receive
    /// window to couple to), so those uploads use the eager-credit + buffer-cap path instead.
    var uploadDrainCoupled = false

    /// Streams whose upload stream-window credit is deferred until the h2 upstream drains the body to
    /// the origin (`creditUploadDrained`), so a slow origin backpressures the client instead of filling
    /// the upstream buffer to its reset cap. Only the connection window and DATA padding are eager here;
    /// pre-bind (probe) and buffered→chunked streams stay fully eager and are absent.
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
        torn = true
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
        // Resume any parked feed so its awaiting pump unwinds instead of leaking.
        continuation?.resume()
    }

    func rejectStream(_ streamID: UInt32, errorCode: UInt32) {
        guard !torn else { return }
        rstToClient(streamID, errorCode: errorCode, abortUpstream: false)
    }

    /// Synthesizes a minimal error response for a stream whose upstream couldn't be established,
    /// keeping the h2 connection up for the client's other streams instead of dropping it.
    func failStream(streamID: UInt32, status: Int, message: String) {
        guard !torn else { return }
        let body = Data(message.utf8)
        let headers: [(name: String, value: String)] = [
            (name: "content-type", value: "text/plain; charset=utf-8"),
            (name: "content-length", value: String(body.count)),
        ]
        deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: body.isEmpty)
        if !body.isEmpty { deliverResponseData(streamID: streamID, body, endStream: true) }
    }

    // MARK: - Client → MITM

    /// Parked lwIP-queue seam: hands the continuation to `body` on the lwIP queue; `body` resumes it
    /// inline or stashes it (`parkedContinuation`) for a later script hop to resolve. The continuation
    /// itself lives in ``LWIPConcurrencyBridge``.
    private func onLwipParked<T>(_ body: @escaping (CheckedContinuation<T, Never>) -> Void) async -> T {
        await lwipBridge.runParked(body)
    }

    /// Feeds one inbound chunk; suspends across a parking script hop. lwIP-queue-confined, so it
    /// self-hops onto that queue.
    func feed(_ data: Data) async {
        await onLwipParked { (continuation: CheckedContinuation<Void, Never>) in
            // `runParked`'s body runs on the lwIP queue = this actor's executor, so enter isolation
            // synchronously.
            self.assumeIsolated { $0.feedOnQueue(data, continuation: continuation) }
        }
    }

    private func feedOnQueue(_ data: Data, continuation: CheckedContinuation<Void, Never>) {
        guard parkedContinuation == nil else {
            // Dropping the chunk would desync frame boundaries and leak receive-window
            // credit with the connection alive — fail closed.
            fail("feed re-entered while a script hop is outstanding", code: Codec.ErrorCode.internalError)
            continuation.resume()
            return
        }
        if parseError || torn { continuation.resume(); return }
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
        guard !serverPrefaceSent else { return }
        serverPrefaceSent = true
        var preface = Data()
        // Advertise ENABLE_PUSH=0 (we never push; RFC 9113 §6.5.2) and MAX_CONCURRENT_STREAMS so a
        // conformant client self-throttles instead of opening streams we'd answer with REFUSED_STREAM.
        Codec.appendFrameHeader(typeCode: Codec.FrameType.settings, flags: 0, streamID: 0, payloadLength: 24, into: &preface)
        preface.append(contentsOf: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00]) // SETTINGS_ENABLE_PUSH = 0
        let maxStreams = UInt32(Self.advertisedMaxConcurrentStreams)
        preface.append(contentsOf: [0x00, 0x03, // SETTINGS_MAX_CONCURRENT_STREAMS
                                    UInt8((maxStreams >> 24) & 0xFF), UInt8((maxStreams >> 16) & 0xFF),
                                    UInt8((maxStreams >> 8) & 0xFF), UInt8(maxStreams & 0xFF)])
        // Enlarge our per-stream receive window so client→server uploads aren't throttled to ~64 KiB/RTT.
        let w = UInt32(Self.receiveWindow)
        preface.append(contentsOf: [0x00, 0x04, // SETTINGS_INITIAL_WINDOW_SIZE (per-stream)
                                    UInt8((w >> 24) & 0xFF), UInt8((w >> 16) & 0xFF),
                                    UInt8((w >> 8) & 0xFF), UInt8(w & 0xFF)])
        // Bound the decoded request-header list so a conformant client self-limits; also enforced
        // in the HPACK decoder (RFC 9113 §6.5.2).
        let maxHeaderList = UInt32(HPACKDecoder.maxDecodedHeaderListSize)
        preface.append(contentsOf: [0x00, 0x06, // SETTINGS_MAX_HEADER_LIST_SIZE
                                    UInt8((maxHeaderList >> 24) & 0xFF), UInt8((maxHeaderList >> 16) & 0xFF),
                                    UInt8((maxHeaderList >> 8) & 0xFF), UInt8(maxHeaderList & 0xFF)])
        delegate?.clientLegWriteToClient(preface)
        // INITIAL_WINDOW_SIZE doesn't move the connection window (RFC 9113 §6.9.2); raise it
        // explicitly so the connection isn't the ~64 KiB upload bottleneck.
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
                if parseError { return false }
            }
        }
    }

    private func finishPass(parked: Bool) {
        // Flush every pass so coalesced receive-window credit reaches the client before it can stall
        // on a depleted window, and never lingers across a script hop.
        flushBatchedCredits()
        if parked { return }
        let continuation = parkedContinuation
        parkedContinuation = nil
        continuation?.resume()
    }

    /// Emits the WINDOW_UPDATEs accumulated this pass (one per credited stream plus one for the
    /// connection). A stream-level update for a since-closed stream is harmless (RFC 9113 §5.1).
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
        guard !parseError else { return }
        parseError = true
        rxBuffer = MITMByteBuffer()
        pending = nil
        sendGoAwayToClient(code: code)
        logger.warning("bridge \(host): \(message); tearing down")
        delegate?.clientLegFatalError(message)
    }

    /// Best-effort GOAWAY naming the last processed stream so the client can safely retry anything
    /// above it (RFC 9113 §6.8). Idempotent (first code wins); may race the close.
    func sendGoAwayToClient(code: UInt32) {
        guard !torn, !goAwaySent else { return }
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
        if frame.flags & 0x1 != 0 { return } // ACK of our SETTINGS; nothing to apply
        let payload = frame.payload
        var i = payload.startIndex
        // RFC 9113 §6.5: a SETTINGS length not a multiple of 6 is a FRAME_SIZE_ERROR. We apply whole
        // entries and ignore any remainder rather than tear down a quirky client's connection.
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
        // RFC 9113 §6.9.1: a 0 increment (or malformed, non-4-byte payload) is a PROTOCOL_ERROR;
        // we ignore it rather than reset (nothing to credit). Over-credit past 2^31-1 is clamped
        // in the flow controller.
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

    /// Seeds the send window with the current initial window plus any WINDOW_UPDATE credit that
    /// arrived before the stream had a PaceState.
    private func makePaceState(_ streamID: UInt32) -> PaceState {
        let seed = flowController.clientInitialStreamWindow + (pendingStreamCredit.removeValue(forKey: streamID) ?? 0)
        return PaceState(streamWindow: min(MITMHTTP2FlowController.maxWindow, max(0, seed)))
    }

    private func handleClientRST(_ frame: Codec.RawFrame) {
        let id = frame.streamID
        guard id != 0 else { return }
        // `isLiveResponseStream` also covers the window between forwarding the request head and the
        // response head arriving, where `requestStreams` and `paceStates` are both empty but
        // `streamMethods` still tracks the stream — a client cancel there must still abort upstream.
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
        // Invalid padding is a connection error (RFC 9113 §6.1); skipping it would leave the block
        // out of the persistent HPACK table and desync every later HEADERS.
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
        // Forward-progress guard: empty CONTINUATION frames that never set END_HEADERS never trip
        // the byte cap and would spin the parser indefinitely.
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

        // RFC 9113 §5.1: a HEADERS frame moves an idle stream to "open". Record a brand-new (higher-
        // numbered) stream as the highest opened stream *now*, before the validation guards below can
        // RST it.
        let isNewStream = streamID > highestStreamID
        if isNewStream { highestStreamID = streamID }

        // RFC 9113 §8.3: a malformed pseudo-header section is a smuggling vector once re-serialized
        // to HTTP/1.1. RST the stream; the HPACK table already absorbed the block, so it stays in sync.
        guard MITMBridgeHeaders.pseudoHeadersValid(decoded, isRequest: true) else {
            logger.warning("bridge \(host) stream \(streamID): malformed pseudo-header section; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError,
                        abortUpstream: requestStreams[streamID] != nil)
            return false
        }

        // RFC 9113 §8.2.1: an illegal field-name octet or CR/LF/NUL in a value is a request-splitting
        // vector once re-serialized to HTTP/1.1 (HPACK only checks UTF-8).
        if let bad = HTTPHeader.firstInvalidOctet(decoded) {
            logger.warning("bridge \(host) stream \(streamID): header rejected — \(bad.reason) on \"\(HTTPHeader.escapedForLog(bad.name))\"; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError,
                        abortUpstream: requestStreams[streamID] != nil)
            return false
        }

        // RFC 9113 §8.2.2: HTTP/2 forbids connection-specific header fields (connection,
        // proxy-connection, keep-alive, transfer-encoding, upgrade) and any `te` but `trailers`.
        // RST (not GOAWAY) rather than forwarding stripped, keeping per-stream recovery.
        guard MITMBridgeHeaders.h2ConnectionHeadersAbsent(decoded) else {
            logger.warning("bridge \(host) stream \(streamID): connection-specific header in HTTP/2; RST")
            rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError,
                        abortUpstream: requestStreams[streamID] != nil)
            return false
        }

        // A HEADERS block with no :method is either a request trailer (on an open stream) or a
        // malformed request missing its required pseudo-header (on a stream not yet open).
        if HTTPHeader.firstValue(in: decoded, named: ":method") == nil {
            guard requestStreams[streamID] != nil else {
                // Missing :method on a never-opened stream → malformed (RFC 9113 §8.3.1). RST rather
                // than drop the HEADERS and strand the client.
                logger.warning("bridge \(host) stream \(streamID): request HEADERS missing :method; RST")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: false)
                return false
            }
            // RFC 9113 §8.1: a trailer HEADERS MUST set END_STREAM. A non-final second HEADERS would
            // be treated as a clean end-of-body and truncate the request (dropping later DATA).
            guard endStream else {
                logger.warning("bridge \(host) stream \(streamID): trailer HEADERS without END_STREAM; RST")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                return false
            }
            // RFC 9113 §8.1: a trailer section MUST NOT contain a pseudo-header. A stray
            // :scheme/:authority/:path passes `pseudoHeadersValid`, so reject it explicitly here.
            guard !decoded.contains(where: { $0.name.hasPrefix(":") }) else {
                logger.warning("bridge \(host) stream \(streamID): pseudo-header in request trailer; RST")
                rstToClient(streamID, errorCode: Codec.ErrorCode.protocolError, abortUpstream: true)
                return false
            }
            let trailers = MITMBridgeHeaders.upstreamRequestHeaders(decoded: decoded)
            return endRequestBody(streamID, trailers: trailers)
        }

        // RFC 9113 §5.1.1: a request HEADERS (carries :method) must open a *new* stream.
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

        // RFC 9113 §8.3.1: a non-CONNECT request MUST carry :scheme and a non-empty :path, plus an
        // :authority or Host (byte-equal if both). Only fires on a malformed/hostile peer.
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
        // Resolve the request-head gates before any rewrite/mode decision. Literal/cached gates
        // resolve inline; a regex cache miss parks the pump on the regex bridge and resumes.
        if let gates = rewriter.peekRequestHeadGates(originalPath: path) {
            return applyRequestHead(head, gates: gates)
        }
        return parkForRequestGates(head)
    }

    /// Everything the request-head rewrite + body-mode decision needs past the gate seam.
    private struct PendingRequestHead: Sendable {
        let streamID: UInt32
        let decoded: [(name: String, value: String)]
        let neverIndexed: Set<String>
        let endStream: Bool
        let method: String
        let requestURL: String?
        let originalPath: String?
    }

    /// Applies the request head once its gate verdicts are in hand: synth short-circuit, header
    /// rewrite, body-mode selection. Never parks (returns false).
    private func applyRequestHead(_ head: PendingRequestHead, gates: MITMHTTP2Rewriter.RequestHeadGates) -> Bool {
        let streamID = head.streamID
        let endStream = head.endStream
        let requestURL = head.requestURL
        let neverIndexed = head.neverIndexed

        if let synth = rewriter.requestSynthResponse(gates: gates) {
            answerSynth(streamID: streamID, response: synth)
            return false
        }

        var rewritten = rewriter.transformRequestHeaders(head.decoded, gates: gates)
        // Capture synchronously, while it still reflects this request's rewrite, before a
        // body-buffering hop lets a concurrent stream overwrite the rewriter's shared field.
        let resolvedUpstream = rewriter.resolvedUpstream
        let gateURL = MITMHTTP2Rewriter.requestPath(in: rewritten).map { "https://\(host)\($0)" } ?? requestURL

        // Clamp only when a response body rule will read the reply; a passthrough request keeps
        // the client's `Accept-Encoding` so its negotiation matches a non-intercepted connection.
        if rewriter.hasBodyAccessingRule(phase: .httpResponse, verdicts: gates.responseGates) {
            rewritten = MITMBridgeHeaders.clampingAcceptEncoding(rewritten)
        }

        if rewriter.hasStreamScriptRule(phase: .httpRequest, verdicts: gates.post) {
            logger.warning("bridge \(host) stream \(streamID): request stream-script not supported on the bridge; forwarding body unscripted")
        }

        let hasBufferedRule = rewriter.hasBufferedBodyRule(phase: .httpRequest, verdicts: gates.post)
        let method = head.method
        let willBufferBody = hasBufferedRule && (endStream || shouldBuffer(headers: rewritten))

        // Expect: 100-continue — only intercept it when a rule buffers the whole body locally before
        // the origin sees the request (the origin then can't send its own 100, so synthesize one and
        // strip Expect). On the passthrough/streaming path, forward Expect upstream and relay the
        // origin's own interim 100 / final status, matching a non-intercepted connection where the
        // origin decides whether to accept the body before it is sent. A client that withholds its
        // body then relies on its own Expect timeout if the origin never answers — same as direct.
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

        // A bodyless method streaming a body with no declared length is buffered to frame it with
        // Content-Length, since an h1 origin can refuse a chunked GET.
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
        // Track the unsent declared Content-Length so surplus bytes can't smuggle a second request
        // to an h1 upstream (RFC 9113 §8.1.2.6); chunked self-delimits via END_STREAM, so nil.
        let remaining: Int?
        switch framing {
        case .none: remaining = 0
        case .contentLength(let n): remaining = n
        case .chunked: remaining = nil
        }
        requestStreams[streamID] = .streaming(remaining: remaining)
        // Defer this stream's upload credit to the origin drain (see `streamDeferredUpload`); only for
        // a stream with a body, since an immediate end has nothing to pace.
        if uploadDrainCoupled, !endStream { streamDeferredUpload.insert(streamID) }
        // Correlate the response on the post-rewrite gate URL so one url-pattern matches both.
        delegate?.clientLegSendRequestHead(head, url: gateURL, endStream: endStream)
        if endStream { requestStreams.removeValue(forKey: streamID) }
        return false
    }

    /// Parks the pump while the regex bridge resolves the request-head gates, then resumes on
    /// the lwIP queue: applies the head and continues pumping. Returns true (parked).
    private func parkForRequestGates(_ head: PendingRequestHead) -> Bool {
        let rewriter = self.rewriter
        Task { [weak self] in
            let gates = await rewriter.resolveRequestHeadGates(originalPath: head.originalPath)
            guard let self else { return }
            self.lwipBridge.enqueue {
                // The enqueue body runs on the lwIP queue — this leg's executor — so enter isolation.
                self.assumeIsolated { me in
                    guard !me.torn, !me.parseError else {
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
        // RFC 9113 §10.3: a pseudo-header carrying CR/LF/NUL (or non-token method, or target with
        // whitespace) would split the HTTP/1.1 request line / Host header upstream. Refuse it.
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
        // Invalid padding (pad length >= frame payload) is a connection error (RFC 9113 §6.1).
        // A bare `return false` would also skip `creditClientUpload`, leaking the connection
        // receive window toward a stall.
        guard let body = Codec.stripDataPadding(payload: frame.payload, flags: frame.flags) else {
            fail("DATA with invalid padding")
            return false
        }
        let endStream = frame.flags & 0x1 != 0
        let id = frame.streamID

        switch requestStreams[id] {
        case .streaming(let remaining):
            if streamDeferredUpload.contains(id) {
                // Drain-coupled: credit the connection window (withholding it would stall other
                // streams) and any DATA padding (consumed here, never forwarded) now; defer the body's
                // stream-window credit until the upstream flushes it to the origin (`creditUploadDrained`).
                batchedConnCredit += onWireLength
                let padding = onWireLength - body.count
                if padding > 0 { batchedStreamCredit[id, default: 0] += padding }
            } else {
                creditClientUpload(streamID: id, length: onWireLength)
            }
            // RFC 9113 §8.1.2.6: a request's DATA length must equal its declared Content-Length, or
            // surplus bytes get re-parsed by an h1 upstream as a second, smuggled request.
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
            // Answered locally; the body is discarded but its bytes must still be credited to the
            // connection-level flow window, or it leaks and stalls every stream.
            creditClientUpload(streamID: id, length: onWireLength)
            return false

        case nil:
            // DATA above the highest opened stream is DATA on an idle stream — a connection error
            // (RFC 9113 §5.1), not a late frame.
            if id > highestStreamID {
                fail("DATA on idle stream \(id)")
                return false
            }
            // Otherwise a stream we already finished (client keeps uploading after an early response
            // closed it). The stream window is gone, but the bytes still count against the connection
            // receive window — credit it back or the window leaks and stalls every upload (RFC 9113 §6.9.1).
            if onWireLength > 0 { batchedConnCredit += onWireLength }
            return false
        }
    }

    private func endRequestBody(_ streamID: UInt32, trailers: [(name: String, value: String)] = []) -> Bool {
        switch requestStreams[streamID] {
        case .streaming(let remaining):
            // Trailer ends the body; an unsatisfied declared Content-Length means a short body —
            // malformed (RFC 9113 §8.1.2.6), so reset.
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
            // A buffered request re-emits the body whole with a computed length, incompatible with
            // trailers; finish normally (trailers dropped).
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
        // Chunked framing self-delimits via END_STREAM, so no Content-Length to enforce.
        requestStreams[streamID] = .streaming(remaining: nil)
        return false
    }

    private func creditClientUpload(streamID: UInt32, length: Int) {
        guard length > 0 else { return }
        // Accumulate; `finishPass` emits the coalesced WINDOW_UPDATEs at the end of the pass.
        batchedStreamCredit[streamID, default: 0] += length
        batchedConnCredit += length
    }

    /// Credits a drain-coupled stream's upload window by `n` drained body bytes. Runs between pump
    /// passes, so it emits the WINDOW_UPDATE directly rather than via `finishPass`; a no-op for a
    /// never-deferred or ended stream. Total credit = eager padding + drained body = the on-wire DATA,
    /// so the window neither leaks nor overflows.
    func creditUploadDrained(_ clientStreamID: UInt32, _ n: Int) {
        guard n > 0, streamDeferredUpload.contains(clientStreamID) else { return }
        delegate?.clientLegWriteToClient(Codec.windowUpdate(streamID: clientStreamID, increment: n))
    }

    // MARK: Buffered request script application

    /// Buffered request body complete. Runs body scripts when buffering for a script rule; otherwise
    /// emits the body verbatim with an explicit Content-Length (no script, no decompression).
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
                // Decompression failed: forward verbatim (content-encoding intact).
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
                // The enqueue body runs on the lwIP queue — this leg's executor — so enter isolation.
                self.assumeIsolated { me in
                    guard !me.torn else { return }
                    // The client can RST the stream while the script runs; only `streamMethods` still
                    // tracks it here. If it's gone, drop the result — forwarding would open an origin
                    // stream whose response every sink guard drops, and a synth answer would strand a
                    // dead `.synthAnswered` entry.
                    guard me.streamMethods[streamID] != nil else { return }
                    switch outcome {
                    case .message(let updated):
                        me.emitBufferedRequest(streamID: streamID, headers: scriptedHeaders, body: updated.body, neverIndexed: buffer.neverIndexed, resolvedUpstream: buffer.resolvedUpstream, originalURL: buffer.originalURL)
                    case .synthesizedResponse(let response):
                        me.answerSynth(streamID: streamID, response: response)
                    }
                    // Non-blocking: the stream was already removed and the pump kept running, so emit
                    // without re-pumping. Out-of-order forwarding is fine (the h2 upstream leg reorders to
                    // monotonic IDs; an h1 upstream dials per stream).
                }
            }
        }
        // Don't park: the script runs at END_STREAM after the stream is removed, so sibling streams
        // must keep flowing while it runs.
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

    /// Expect: 100-continue — client asks the server to confirm before sending the body (RFC 9110 §10.1.1).
    private static func expectsContinue(_ headers: [(name: String, value: String)]) -> Bool {
        headers.contains { entry in
            ASCII.equalsIgnoringCase(entry.name, "expect")
                && ASCII.equalsIgnoringCase(
                    entry.value.trimmingCharacters(in: CharacterSet.whitespaces),
                    "100-continue"
                )
        }
    }

    /// Emits an interim `100 Continue` HEADERS. A 1xx precedes the final response and doesn't end
    /// the stream (RFC 9113 §8.1), so no PaceState is created and the real head follows later.
    private func sendInterimContinue(_ streamID: UInt32) {
        let block: [(name: String, value: String)] = [(name: ":status", value: "100")]
        delegate?.clientLegWriteToClient(Codec.emitHeaders(
            streamID: streamID,
            block: HPACKEncoder.encodeHeaderBlock(block),
            endStream: false
        ))
    }

    // MARK: - MITMResponseSink (upstream → client)

    /// Sink entry points guard on this so an upstream event losing the race with a client RST_STREAM
    /// is dropped, not re-materialized onto a closed stream — which would draw STREAM_CLOSED, a
    /// connection error.
    private func isLiveResponseStream(_ streamID: UInt32) -> Bool {
        streamMethods[streamID] != nil || paceStates[streamID] != nil
    }

    // The upstream leg and the h1 IR sink call these synchronously on the shared lwIP executor, so
    // each `MITMResponseSink` method is a `nonisolated` shim that re-enters isolation via
    // `assumeIsolated`; the isolated `…OnQueue` body holds the actual logic.

    nonisolated func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>) {
        assumeIsolated { $0.deliverResponseHeadOnQueue(streamID: streamID, status: status, headers: headers, endStream: endStream, neverIndexed: neverIndexed) }
    }
    private func deliverResponseHeadOnQueue(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>) {
        guard !torn, isLiveResponseStream(streamID) else { return }
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
        guard !torn, isLiveResponseStream(streamID) else { return }
        var block: [(name: String, value: String)] = [(name: ":status", value: String(status))]
        block.append(contentsOf: MITMBridgeHeaders.responseHeadersToH2(headers))
        delegate?.clientLegWriteToClient(Codec.emitHeaders(
            streamID: streamID,
            block: HPACKEncoder.encodeHeaderBlock(block),
            endStream: false
        ))
        // No PaceState, no finalize: a 1xx precedes the final response (RFC 9113 §8.1), so the
        // stream stays open for the real head.
    }

    nonisolated func deliverResponseData(streamID: UInt32, _ data: Data, endStream: Bool) {
        assumeIsolated { $0.deliverResponseDataOnQueue(streamID: streamID, data, endStream: endStream) }
    }
    private func deliverResponseDataOnQueue(streamID: UInt32, _ data: Data, endStream: Bool) {
        guard !torn, isLiveResponseStream(streamID) else { return }
        appendClientBody(streamID: streamID, data: data, endStream: endStream)
    }

    nonisolated func deliverResponseTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        assumeIsolated { $0.deliverResponseTrailersOnQueue(streamID: streamID, trailers) }
    }
    private func deliverResponseTrailersOnQueue(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        guard !torn, isLiveResponseStream(streamID) else { return }
        var paceState = paceStates[streamID] ?? makePaceState(streamID)
        paceState.sawEnd = true
        let normalized = MITMBridgeHeaders.responseHeadersToH2(trailers)
        // Empty after normalization → just end the stream like a trailerless body.
        if !normalized.isEmpty { paceState.pendingTrailers = normalized }
        paceStates[streamID] = paceState
        flushResponse(streamID)
    }

    nonisolated func deliverResponseReset(streamID: UInt32, errorCode: UInt32) {
        assumeIsolated { $0.deliverResponseResetOnQueue(streamID: streamID, errorCode: errorCode) }
    }
    private func deliverResponseResetOnQueue(streamID: UInt32, errorCode: UInt32) {
        // `requestStreams` also catches an upload half still open after the response half finished —
        // an origin RST there must still reach the client. After a client RST every entry is gone,
        // so a late upstream event still no-ops.
        guard !torn, isLiveResponseStream(streamID) || requestStreams[streamID] != nil else { return }
        rstToClient(streamID, errorCode: errorCode, abortUpstream: false)
    }

    // MARK: - HTTP/1.1 upstream response failure

    func acceptResponseAborted(streamID: UInt32) {
        guard !torn else { return }
        deliverResponseReset(streamID: streamID)
    }

    // MARK: Client-bound body pacing

    private func appendClientBody(streamID: UInt32, data: Data, endStream: Bool) {
        var paceState = paceStates[streamID] ?? makePaceState(streamID)
        paceState.pending.append(data)
        if endStream { paceState.sawEnd = true }
        paceStates[streamID] = paceState
        flushResponse(streamID)
        // The upstream is read eagerly, so a client that stops draining would grow the backlog
        // unbounded. Reset the stream (and drop its upstream) rather than buffer unboundedly.
        if let backlog = paceStates[streamID]?.pending.count, backlog > Self.maxClientBufferedBytes {
            logger.warning("bridge \(host) stream \(streamID): client-bound backlog \(backlog) B over cap; resetting stream")
            rstToClient(streamID, errorCode: Codec.ErrorCode.internalError, abortUpstream: true)
        }
    }

    /// Sends as much buffered body as the connection and stream windows allow, up to `cap` bytes (the
    /// distributor passes a fair-share cap; direct callers leave it unbounded). Returns whether it
    /// made progress, so the distributor knows to keep cycling.
    @discardableResult
    private func flushResponse(_ streamID: UInt32, cap: Int = .max) -> Bool {
        guard var paceState = paceStates[streamID] else { return false }
        var progressed = false
        let available = max(0, min(flowController.connectionWindow, paceState.streamWindow, paceState.pending.count, cap))
        if available > 0 {
            let chunk = paceState.pending.prefix(available)
            // A pending trailer is the terminal frame, so body DATA must not carry END_STREAM.
            let bodyDrained = paceState.sawEnd && available == paceState.pending.count
            let endOnData = bodyDrained && paceState.pendingTrailers == nil
            delegate?.clientLegWriteToClient(Codec.frameData(streamID: streamID, payload: chunk, endStream: endOnData))
            flowController.debitConnection(available)
            paceState.streamWindow -= available
            paceState.pending.removeFirst(available)
            if endOnData { paceState.finished = true }
            // These bytes have left for the client, so credit the upstream's receive window
            // (no-op unless an h2 upstream marked this stream drain-coupled).
            onResponseDrainedToClient?(streamID, available)
            progressed = true
        }
        // Body drained and stream ended: emit the terminal frame. A trailer HEADERS block isn't
        // flow-controlled, so it follows the last body DATA directly.
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
        // Otherwise the client's flow-control window is exhausted; resume on its next WINDOW_UPDATE.
        paceStates[streamID] = paceState
        if paceState.finished {
            paceStates.removeValue(forKey: streamID)
            finishClientStream(streamID, notifyUpstream: true)
        }
        return progressed
    }

    /// Distributes the available client connection window across response streams in equal shares, so
    /// a large download can't drain it all and starve its siblings. One `flushResponse` per stream,
    /// each capped to its fair slice; window a stream can't use flows to those after it.
    private func distributeClientConnectionWindow() {
        // Only streams with buffered body contend. Counting idle streams would shrink each share and
        // leave window unused until the next WINDOW_UPDATE, so a sole sender sees the full window.
        let ready = paceStates.keys.filter { (paceStates[$0]?.pending.count ?? 0) > 0 }.sorted()
        var remaining = ready.count
        for id in ready {
            guard flowController.connectionWindow > 0 else { break }
            // Floor at one frame so no stream is starved to a sub-frame slice; flushResponse
            // re-clamps to the true remaining window, so the floor can't overspend.
            let share = max(Codec.maxFramePayloadSize, flowController.connectionWindow / max(1, remaining))
            flushResponse(id, cap: share)
            remaining -= 1
        }
    }

    private func finishClientStream(_ streamID: UInt32, notifyUpstream: Bool) {
        streamMethods.removeValue(forKey: streamID)
        paceStates.removeValue(forKey: streamID)
        pendingStreamCredit.removeValue(forKey: streamID)
        // If the client is still uploading to an h2 upstream, keep the request (upload) half alive so an
        // earlier-finishing response doesn't truncate it (RFC 9113 half-closed streams);
        // `finishRequestUpload` completes teardown when the upload ends. An h1 upstream can't take a
        // continued upload after responding, so it closes here.
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

    /// Called when the request (upload) half finishes. Cleans up its state and, if the response half
    /// already completed (the stream was kept open only for this upload), notifies the upstream that
    /// the stream is fully done.
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
