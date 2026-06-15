//
//  MITMHTTP2Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITMHTTP2Connection")

/// Per-direction HTTP/2 plaintext translator between the MITM session's TLS legs.
/// HPACK is stateful per connection-direction (RFC 7541 §2.2), so header blocks can't
/// be byte-forwarded: each is decoded, optionally rewritten, and re-encoded statelessly.
final class MITMHTTP2Connection {

    /// Which side of the MITM this leg lives on; only the inbound leg consumes the 24-byte preface.
    enum Direction {
        /// Browser → real server.
        case inbound
        /// Real server → browser.
        case outbound
    }

    // MARK: - Frame types we touch

    private enum FrameTypeCode {
        static let data: UInt8         = 0x0
        static let headers: UInt8      = 0x1
        static let priority: UInt8     = 0x2
        static let rstStream: UInt8    = 0x3
        static let settings: UInt8     = 0x4
        static let pushPromise: UInt8  = 0x5
        static let goaway: UInt8       = 0x7
        static let windowUpdate: UInt8 = 0x8
        static let continuation: UInt8 = 0x9
    }

    /// HTTP/2's mandated minimum ``SETTINGS_MAX_FRAME_SIZE`` (RFC 9113 §6.5.2).
    private static let maxFramePayloadSize = 16_384

    /// Cap on a header block plus its CONTINUATION chain — RFC 9113 sets no limit;
    /// 256 KiB fits the largest real-world request heads.
    private static let maxHeaderBlockFragmentBytes: Int = 256 * 1024

    /// Cap on a received frame payload. SETTINGS_MAX_FRAME_SIZE can negotiate ~16 MiB,
    /// which the extension's ~50 MiB budget can't sustain. Overflow flips ``parseError``
    /// (resync to a frame boundary is impossible), so the peer stalls and GOAWAYs.
    private static let maxReceivedFramePayloadSize: Int = 1 * 1024 * 1024

    /// Cap on pre-dial held connection setup; legitimate setup is a few hundred bytes.
    private static let maxPendingUpstreamSetupBytes: Int = 256 * 1024

    // MARK: - Raw frame

    /// Format-preserving frame view; unrecognised frame types pass through unmodified.
    private struct RawFrame {
        var typeCode: UInt8
        var flags: UInt8
        var streamID: UInt32
        var payload: Data
    }

    // MARK: - State

    let direction: Direction
    private let rewriter: MITMHTTP2Rewriter
    /// Shared cross-leg flow-control state.
    private let flowController: MITMHTTP2FlowController
    private let decoder = HPACKDecoder()

    /// Invoked on an observed SETTINGS_HEADER_TABLE_SIZE to bound the *opposing*
    /// leg's HPACK decoder. Called on the lwIP queue.
    var onObservedPeerHeaderTableSize: ((Int) -> Void)?

    /// Hands a buffered-rewrite RESPONSE body exceeding the client's window to the
    /// inbound leg for paced delivery. Outbound leg only; returns false when declined.
    var onPacedResponse: ((_ streamID: UInt32, _ headerBlock: Data, _ body: Data, _ endStream: Bool) -> Bool)?

    /// Hands a buffered-rewrite REQUEST body (HEADERS already emitted) to the
    /// outbound leg for paced delivery. Inbound leg only; returns false when declined.
    var onPacedRequest: ((_ streamID: UInt32, _ body: Data, _ endStream: Bool) -> Bool)?

    /// Tells the outbound leg to drop any paced request body for the stream. Inbound leg only.
    var onUpstreamRequestAborted: ((_ streamID: UInt32) -> Void)?

    /// Last observed peer SETTINGS_HEADER_TABLE_SIZE, retained for a late-created outbound leg.
    private(set) var lastObservedPeerHeaderTableSize: Int?

    /// Bounds this leg's HPACK decoder to the peer-advertised limit (RFC 7541 §4.2). Called on the lwIP queue.
    func configureDecoderTableSize(_ size: Int) {
        decoder.setPeerHeaderTableSize(size)
    }

    private var phase: MITMPhase {
        direction == .inbound ? .httpRequest : .httpResponse
    }

    /// Connection-preface bytes remaining to be forwarded verbatim.
    private var prefaceRemaining: Int

    /// Decrypted plaintext not yet consumed into a complete frame; cursor-style so removeFirst is O(1).
    private var rxBuffer = MITMByteBuffer()

    /// Set while a HEADERS/PUSH_PROMISE awaits its CONTINUATIONs; RFC 9113 §6.10
    /// forbids any other frame until END_HEADERS arrives.
    private var pending: PendingHeaders?

    /// Set on an unrecoverable parse failure; resync is impossible, so the peer stalls and GOAWAYs.
    private var parseError: Bool = false

    /// Highest client-initiated stream ID seen: a HEADERS past it opens a new stream,
    /// at or below is a trailer (RFC 9113 §5.1.1, §8.1). Inbound leg only.
    private var highestInboundStreamID: UInt32 = 0

    private struct PendingHeaders {
        let streamID: UInt32
        var fragments: Data
        /// Original flags; END_STREAM kept, PADDED/PRIORITY/END_HEADERS cleared on re-emit.
        let originalFlags: UInt8
        let kind: Kind

        enum Kind {
            case headers
            case pushPromise(promisedStreamID: UInt32)
        }
    }

    /// Buffered-script stream state: HEADERS deferred and DATA accumulated until
    /// END_STREAM. ``abandoned`` flips when an identity body overflows the cap
    /// mid-flight; deferred HEADERS + prefix go out un-mutated, later DATA verbatim.
    private struct PendingMessage {
        var data: Data
        let codec: MITMBodyCodec.Plan
        var headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        var abandoned: Bool = false
        /// Field names that arrived never-indexed (RFC 7541 §7.1.3), preserved on re-encode.
        var neverIndexed: Set<String> = []
        /// Set when the opening HEADERS were emitted early: streams must open in
        /// stream-ID order (RFC 9113 §5.1.1), so HEADERS can't wait for the buffered body.
        var headersAlreadyEmitted: Bool = false
    }
    private var pendingMessages: [UInt32: PendingMessage] = [:]

    /// Per-stream streaming-script state; mutually exclusive with ``pendingMessages``.
    private struct StreamingState {
        let headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        var frameIndex: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
        /// Cumulative script-introduced byte growth; tripping the cap flips to bypass.
        var cumulativeGrowth: Int = 0
        /// One-frame lookahead so the final script call (``frame.end = true``)
        /// carries the last DATA's bytes, matching HTTP/1 chunked semantics.
        var pendingFrame: Data?
    }
    private var streamingScripts: [UInt32: StreamingState] = [:]

    /// Client-bound bytes injected onto the inner TLS record, bypassing the
    /// outbound translator. Inbound leg only.
    private var pendingClientBytes = Data()

    /// Server-bound bytes emitted out-of-band. Outbound leg only.
    private var pendingServerBytes = Data()

    // MARK: Deferred-dial connection setup (inbound only)
    //
    // The upstream dial waits for the first request: held client setup is flushed
    // ahead of the first forwarded request; a synth-only connection never dials.

    /// Upstream-bound output held until the first request is forwarded.
    private var pendingUpstreamSetup = Data()
    /// True once the held setup has been flushed; afterwards the leg forwards normally.
    private var upstreamSetupForwarded = false
    /// Set when a request needing the upstream has been seen (triggers flush + dial).
    private var didForwardUpstreamRequest = false
    /// Set when a request was actually committed upstream (``didForwardUpstreamRequest``
    /// is set earlier, at HEADERS time); drives the pre-establishment GOAWAY's last-stream-id.
    private var forwardedRequestUpstream = false
    /// First inbound bodied request whose HEADERS are withheld so a request-phase
    /// ``Anywhere.respond`` can short-circuit it; safe only for the first stream (RFC 9113 §5.1.1).
    private var deferredFirstStreamID: UInt32?
    /// Whether the server preface (empty SETTINGS) has been emitted to the client.
    private var serverPrefaceSentToClient = false
    /// Client SETTINGS ACKs to swallow, one per MITM-injected SETTINGS — relaying them
    /// upstream would be an unsolicited SETTINGS ACK (RFC 9113 §6.5.3 PROTOCOL_ERROR).
    private var pendingClientSettingsAckSwallows = 0
    /// Set after a pre-establishment synth emits its GOAWAY; further client frames are swallowed.
    private var inboundClosed = false

    /// Stream IDs answered locally that never reached the upstream. Follow-up client
    /// frames MUST be swallowed — forwarding them on an idle upstream stream triggers
    /// a connection-level PROTOCOL_ERROR. Inbound leg only.
    private var synthRespondedStreams: Set<UInt32> = []
    /// Insertion-order mirror of ``synthRespondedStreams`` for FIFO eviction.
    private var synthRespondedOrder: [UInt32] = []

    /// FIFO cap; sized above the spec-default SETTINGS_MAX_CONCURRENT_STREAMS (100)
    /// so live streams aren't evicted.
    private static let synthRespondedMaxStreams = 256

    /// A client-bound body (synth reply or buffered-rewrite response) paced as the
    /// client grants window; drained by ``flushPendingSynth``.
    private struct PendingSynthBody {
        var remaining: Data
        /// Per-stream window; signed — a SETTINGS_INITIAL_WINDOW_SIZE decrease can
        /// push it negative (RFC 9113 §6.9.2).
        var streamWindow: Int
        /// Pre-establishment one-shot synth: the GOAWAY is deferred until the body flushes.
        let isPreEstablishment: Bool
        /// last-stream-id for the deferred GOAWAY; 0 when a proxy stream was
        /// co-batched ahead (so the client retries it).
        let goAwayLastStreamID: UInt32
    }

    /// Per-stream paced client-bound bodies; removed when fully flushed.
    private var pendingSynthBodies: [UInt32: PendingSynthBody] = [:]

    /// A MITM-buffered REQUEST body paced toward the server. Outbound leg only.
    private struct PendingRequestBody {
        var remaining: Data
        /// Per-stream send window; signed — a SETTINGS_INITIAL_WINDOW_SIZE decrease
        /// can push it negative (RFC 9113 §6.9.2).
        var streamWindow: Int
    }

    /// Per-stream paced server-bound request bodies. Outbound leg only.
    private var pendingRequestBodies: [UInt32: PendingRequestBody] = [:]

    /// Buffered-rewrite REQUEST bodies produced before the outbound leg existed
    /// (HEADERS already on the wire). Inbound leg only.
    private var heldPacedRequests: [UInt32: (body: Data, endStream: Bool)] = [:]

    /// True while a pre-establishment one-shot synth is pacing its body; WINDOW_UPDATEs
    /// are consumed for pacing and dropped — no upstream will ever be dialed.
    private var oneShotSynthPacing = false

    /// Cap on tracked per-stream state (each entry can pin up to 4 MiB); past it new
    /// streams pass through un-MITM'd. Sized above the spec-default concurrency (100).
    private static let maxTrackedStreams = 256

    /// Serial lwIP queue; scripts hop off and resume on it, so all state stays on one queue.
    private let lwipQueue: DispatchQueue

    /// In-flight ``process`` completion, retained while a script hop is outstanding;
    /// the one-read-in-flight discipline ensures at most one exists.
    private var parkedCompletion: ((Data) -> Void)?

    /// Peer-bound bytes produced before the current script hop parked; prepended on resume.
    private var pendingPreParkOutput = Data()

    /// Set on session teardown; a late script resume must not touch dead state.
    private var torn = false

    // MARK: - Init

    init(
        direction: Direction,
        rewriter: MITMHTTP2Rewriter,
        flowController: MITMHTTP2FlowController,
        lwipQueue: DispatchQueue
    ) {
        self.direction = direction
        self.rewriter = rewriter
        self.flowController = flowController
        self.prefaceRemaining = (direction == .inbound) ? 24 : 0
        self.lwipQueue = lwipQueue
    }

    /// Marks the connection torn down. Idempotent; a late script resume bails immediately.
    func markTorn() {
        torn = true
        parkedCompletion = nil
        pendingPreParkOutput = Data()
        // Drop body buffers (up to 4 MiB each) eagerly to spare the extension's memory budget.
        pendingSynthBodies.removeAll()
        pendingRequestBodies.removeAll()
        heldPacedRequests.removeAll()
        pendingMessages.removeAll()
        streamingScripts.removeAll()
        oneShotSynthPacing = false
    }

    // MARK: - Public API

    /// Feeds a decrypted plaintext chunk through the h2 translator. ``completion``
    /// fires exactly once — synchronously, or later on the lwIP queue when a script
    /// parks. Client-bound synth bytes drain separately via ``drainPendingClientBytes()``.
    func process(_ data: Data, completion: @escaping (Data) -> Void) {
        guard parkedCompletion == nil else {
            // One-read-in-flight violated. Overwriting the stashed completion would
            // hang the connection; fail closed and fire only the new completion (empty).
            logger.error("[MITM] HTTP/2 \(rewriter.host): process re-entered while a script hop is outstanding; dropping this chunk to preserve the parked completion (one-read-in-flight invariant violated)")
            completion(Data())
            return
        }
        if parseError { completion(Data()); return }
        var output = Data()
        var input = data

        if prefaceRemaining > 0, !input.isEmpty {
            let take = min(prefaceRemaining, input.count)
            output.append(input.prefix(take))
            input.removeFirst(take)
            prefaceRemaining -= take
        }

        if !input.isEmpty {
            rxBuffer.append(input)
        }

        // The client's first server frame must be SETTINGS, before anything the
        // pump might produce client-bound.
        ensureClientServerPrefaceSent()

        parkedCompletion = completion
        // Two statements: a combined call would copy `output` before pump runs,
        // silently dropping every byte pump produced.
        let parkedAgain = pump(into: &output)
        finishPumpPass(output, parkedAgain: parkedAgain)
    }

    /// Parses and dispatches frames until ``rxBuffer`` drains or a script hop
    /// parks the connection. Returns true when parked.
    private func pump(into output: inout Data) -> Bool {
        let span = PerformanceMonitor.span(.mitmRewrite)
        defer { span.stop() }
        while let frame = parseFrame(from: &rxBuffer) {
            if handleFrame(frame, into: &output) {
                return true
            }
        }
        return false
    }

    /// Tail of every pump pass: parks, or fires the stashed completion exactly once.
    private func finishPumpPass(_ output: Data, parkedAgain: Bool) {
        if parkedAgain {
            pendingPreParkOutput = output
            return
        }
        var finalOutput = output
        // Inbound: gate outgoing bytes on the first upstream request so a
        // synth-only connection never dials.
        if direction == .inbound, !upstreamSetupForwarded {
            if inboundClosed {
                finalOutput = Data()
            } else if didForwardUpstreamRequest {
                // Flush held setup first so the upstream sees a valid h2 start.
                finalOutput = pendingUpstreamSetup + output
                pendingUpstreamSetup = Data()
                upstreamSetupForwarded = true
            } else if pendingUpstreamSetup.count + output.count > Self.maxPendingUpstreamSetupBytes {
                logger.warning("[MITM] HTTP/2 \(rewriter.host): pre-dial setup buffer would exceed \(Self.maxPendingUpstreamSetupBytes) B without a request; marking parseError")
                parseError = true
                pendingUpstreamSetup = Data()
                finalOutput = Data()
            } else {
                pendingUpstreamSetup.append(output)
                finalOutput = Data()
            }
        }
        let completion = parkedCompletion
        parkedCompletion = nil
        completion?(finalOutput)
    }

    /// Drains client-bound synthesized bytes (written directly to the inner TLS record). Inbound leg only.
    func drainPendingClientBytes() -> Data {
        let bytes = pendingClientBytes
        pendingClientBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    /// Drains queued server-bound bytes (written onto the outer TLS record). Outbound leg only.
    func drainPendingServerBytes() -> Data {
        let bytes = pendingServerBytes
        pendingServerBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    // MARK: - Frame dispatch

    private func handleFrame(_ frame: RawFrame, into output: inout Data) -> Bool {
        // One-shot synth already sent response + GOAWAY: swallow further client frames.
        if inboundClosed { return false }
        // One-shot synth still pacing its body: only WINDOW_UPDATE (pacing) and
        // RST_STREAM (abort) are processed; the client retries swallowed streams
        // on a fresh connection after GOAWAY.
        if oneShotSynthPacing {
            switch frame.typeCode {
            case FrameTypeCode.windowUpdate:
                // Pacing side-effects only; this connection never dials.
                _ = handleWindowUpdate(frame)
            case FrameTypeCode.rstStream:
                _ = handleRSTStream(frame) // evict bookkeeping; nothing to forward
            default:
                break
            }
            return false
        }
        // RFC 9113 §6.10: no frame may interleave a header block and its
        // CONTINUATIONs; forwarding one would poison the destination's HPACK table.
        if let p = pending,
           frame.typeCode != FrameTypeCode.continuation {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): frame type \(frame.typeCode) on stream \(frame.streamID) interleaved with pending HEADERS on stream \(p.streamID); marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            pending = nil
            return false
        }
        // Synth-responded streams never reach the upstream: RST_STREAM passes for
        // eviction and WINDOW_UPDATE for pacing; all else is swallowed.
        if frame.streamID != 0,
           synthRespondedStreams.contains(frame.streamID),
           frame.typeCode != FrameTypeCode.rstStream,
           frame.typeCode != FrameTypeCode.windowUpdate {
            // Evict on END_STREAM — pinning the ID only pressures the FIFO cap.
            let endStream = frame.flags & 0x1 != 0
            let endStreamBearing = frame.typeCode == FrameTypeCode.data
                || frame.typeCode == FrameTypeCode.headers
            if endStream, endStreamBearing {
                clearSynthResponded(frame.streamID)
            }
            return false
        }
        switch frame.typeCode {
        case FrameTypeCode.headers:
            return handleHeaders(frame, into: &output)
        case FrameTypeCode.continuation:
            return handleContinuation(frame, into: &output)
        case FrameTypeCode.pushPromise:
            return handlePushPromise(frame, into: &output)
        case FrameTypeCode.data:
            return handleData(frame, into: &output)
        case FrameTypeCode.rstStream:
            output.append(handleRSTStream(frame))
            return false
        case FrameTypeCode.goaway:
            output.append(handleGoAway(frame))
            return false
        case FrameTypeCode.settings:
            output.append(handleSettings(frame))
            return false
        case FrameTypeCode.windowUpdate:
            output.append(handleWindowUpdate(frame))
            return false
        default:
            output.append(serializeFrame(frame))
            return false
        }
    }

    /// Observes SETTINGS_HEADER_TABLE_SIZE (RFC 7541 §4.2) to bound the opposing
    /// leg's HPACK decoder, then forwards the frame (clamped where needed).
    private func handleSettings(_ frame: RawFrame) -> Data {
        // Swallow the client's ACK for the MITM-injected server preface — relaying
        // it would be an unsolicited SETTINGS ACK (RFC 9113 §6.5.3 PROTOCOL_ERROR).
        // ACKs for relayed origin SETTINGS aren't counted and fall through.
        if direction == .inbound, frame.streamID == 0, frame.flags & 0x1 != 0,
           pendingClientSettingsAckSwallows > 0 {
            pendingClientSettingsAckSwallows -= 1
            return Data()
        }
        var frame = frame
        if frame.streamID == 0, frame.flags & 0x1 == 0 {
            var payload = frame.payload
            var clampedMaxFrameSize = false
            var i = payload.startIndex
            while i + 6 <= payload.endIndex {
                let identifier = (UInt16(payload[i]) << 8) | UInt16(payload[i + 1])
                let value = (UInt32(payload[i + 2]) << 24)
                    | (UInt32(payload[i + 3]) << 16)
                    | (UInt32(payload[i + 4]) << 8)
                    | UInt32(payload[i + 5])
                switch identifier {
                case 0x1: // SETTINGS_HEADER_TABLE_SIZE
                    lastObservedPeerHeaderTableSize = Int(value)
                    onObservedPeerHeaderTableSize?(Int(value))
                case 0x4 where direction == .inbound: // SETTINGS_INITIAL_WINDOW_SIZE
                    applyClientInitialWindowSize(Int(value))
                case 0x4 where direction == .outbound: // SETTINGS_INITIAL_WINDOW_SIZE
                    applyServerInitialWindowSize(Int(value))
                case 0x5: // SETTINGS_MAX_FRAME_SIZE
                    // Clamp to our receive cap — a larger advertised value lets the
                    // counterpart send a spec-legal frame we reject at parse time.
                    // Patched in place, so the SETTINGS payload length is unchanged.
                    if Int(value) > Self.maxReceivedFramePayloadSize {
                        let capped = UInt32(Self.maxReceivedFramePayloadSize)
                        payload[i + 2] = UInt8(truncatingIfNeeded: capped >> 24)
                        payload[i + 3] = UInt8(truncatingIfNeeded: capped >> 16)
                        payload[i + 4] = UInt8(truncatingIfNeeded: capped >> 8)
                        payload[i + 5] = UInt8(truncatingIfNeeded: capped)
                        clampedMaxFrameSize = true
                    }
                default:
                    break
                }
                i += 6
            }
            if clampedMaxFrameSize {
                frame.payload = payload
                logger.warning("[MITM] HTTP/2 \(rewriter.host): clamped peer SETTINGS_MAX_FRAME_SIZE down to receive cap \(Self.maxReceivedFramePayloadSize) B")
            }
        }
        return serializeFrame(frame)
    }

    /// Applies a new client SETTINGS_INITIAL_WINDOW_SIZE's retroactive delta to open
    /// synth stream windows (RFC 9113 §6.9.2), flushing any stream it unblocked.
    private func applyClientInitialWindowSize(_ newValue: Int) {
        let delta = flowController.updateInitialStreamWindow(newValue)
        guard delta != 0 else { return }
        for id in pendingSynthBodies.keys {
            pendingSynthBodies[id]?.streamWindow += delta
        }
        if delta > 0, !pendingSynthBodies.isEmpty {
            flushAllPendingSynth()
        }
    }

    /// Evicts per-stream bookkeeping for streams above the GOAWAY's last-stream-id
    /// (RFC 9113 §6.8: they will not be processed), then forwards verbatim.
    private func handleGoAway(_ frame: RawFrame) -> Data {
        // GOAWAY MUST be on stream 0 (§6.8); pass a malformed one through.
        guard frame.streamID == 0, frame.payload.count >= 8 else {
            return serializeFrame(frame)
        }
        let payload = frame.payload
        let start = payload.startIndex
        let lastStreamID =
            (UInt32(payload[start])     & 0x7F) << 24
            | UInt32(payload[start + 1]) << 16
            | UInt32(payload[start + 2]) << 8
            | UInt32(payload[start + 3])
        let abandonedPending = pendingMessages.keys.filter { $0 > lastStreamID }
        for id in abandonedPending {
            pendingMessages.removeValue(forKey: id)
        }
        if let deferred = deferredFirstStreamID, deferred > lastStreamID {
            deferredFirstStreamID = nil
        }
        let abandonedStreaming = streamingScripts.keys.filter { $0 > lastStreamID }
        for id in abandonedStreaming {
            streamingScripts.removeValue(forKey: id)
        }
        let abandonedSynth = synthRespondedOrder.filter { $0 > lastStreamID }
        for id in abandonedSynth {
            _ = clearSynthResponded(id)
        }
        for id in pendingSynthBodies.keys where id > lastStreamID {
            pendingSynthBodies.removeValue(forKey: id)
        }
        for id in pendingRequestBodies.keys where id > lastStreamID {
            pendingRequestBodies.removeValue(forKey: id)
        }
        for id in heldPacedRequests.keys where id > lastStreamID {
            heldPacedRequests.removeValue(forKey: id)
        }
        return serializeFrame(frame)
    }

    /// Drops per-stream bookkeeping for an aborted stream and forwards RST_STREAM verbatim.
    private func handleRSTStream(_ frame: RawFrame) -> Data {
        // RFC 9113 §6.4: RST_STREAM needs streamID != 0 and a 4-byte payload;
        // forwarding a malformed one gives the peer a basis to GOAWAY.
        guard frame.streamID != 0, frame.payload.count == 4 else {
            return Data()
        }
        if pending?.streamID == frame.streamID {
            pending = nil
        }
        pendingMessages.removeValue(forKey: frame.streamID)
        streamingScripts.removeValue(forKey: frame.streamID)
        pendingSynthBodies.removeValue(forKey: frame.streamID)
        pendingRequestBodies.removeValue(forKey: frame.streamID)
        heldPacedRequests.removeValue(forKey: frame.streamID)
        onUpstreamRequestAborted?(frame.streamID)
        _ = rewriter.requestLog.popHTTP2(streamID: frame.streamID)
        // Swallow RST_STREAMs for streams the upstream never saw: resetting an idle
        // stream is a PROTOCOL_ERROR (RFC 9113 §5.4.1) answered with a connection-wide GOAWAY.
        if deferredFirstStreamID == frame.streamID {
            deferredFirstStreamID = nil
            return Data()
        }
        if clearSynthResponded(frame.streamID) {
            return Data()
        }
        return serializeFrame(frame)
    }

    // MARK: - HEADERS

    private func handleHeaders(_ frame: RawFrame, into output: inout Data) -> Bool {
        // RFC 9113 §6.2: HEADERS on stream 0 is a connection error.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): HEADERS on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        // RFC 9113 §5.1.1: client stream IDs MUST be odd; forwarding an even one
        // upstream trips a PROTOCOL_ERROR + GOAWAY that kills every stream.
        if direction == .inbound, frame.streamID % 2 == 0 {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): inbound (client) HEADERS has server (even) parity; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        // §5.1.1: stream IDs strictly increase — a HEADERS past the high-water mark
        // opens a NEW stream; at or below it is a trailer (§8.1).
        if direction == .inbound,
           frame.streamID > highestInboundStreamID,
           isFreshHeadersFrame(streamID: frame.streamID) {
            highestInboundStreamID = frame.streamID
        }

        guard let body = stripHeadersPadding(frame: frame, hasPriority: frame.flags & 0x20 != 0) else {
            // Malformed padding — drop rather than feed garbage to the HPACK decoder.
            return false
        }

        // Single-frame cap matching the CONTINUATION-chain bound.
        if body.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): HEADERS payload \(body.count) B exceeded cap \(Self.maxHeaderBlockFragmentBytes); dropping")
            return false
        }

        if frame.flags & 0x4 != 0 { // END_HEADERS
            return finalizeHeaderBlock(
                streamID: frame.streamID,
                fragments: body,
                originalFlags: frame.flags,
                kind: .headers,
                into: &output
            )
        }

        pending = PendingHeaders(
            streamID: frame.streamID,
            fragments: body,
            originalFlags: frame.flags,
            kind: .headers
        )
        return false
    }

    /// True when this leg holds no per-stream state for ``streamID`` (new stream vs. trailer).
    private func isFreshHeadersFrame(streamID: UInt32) -> Bool {
        return pendingMessages[streamID] == nil
            && streamingScripts[streamID] == nil
            && !synthRespondedStreams.contains(streamID)
    }

    private func handleContinuation(_ frame: RawFrame, into output: inout Data) -> Bool {
        // RFC 9113 §6.10: CONTINUATION on stream 0 is a protocol error.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): CONTINUATION on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        guard var p = pending, p.streamID == frame.streamID else {
            // Stray CONTINUATION: forwarding it would poison the destination HPACK decoder.
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): stray CONTINUATION; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }

        // Check the cap before appending so one large CONTINUATION can't blow through it.
        if p.fragments.count + frame.payload.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): header block fragments would be \(p.fragments.count + frame.payload.count) B, over cap \(Self.maxHeaderBlockFragmentBytes); dropping")
            pending = nil
            return false
        }
        p.fragments.append(frame.payload)

        if frame.flags & 0x4 != 0 { // END_HEADERS
            pending = nil
            return finalizeHeaderBlock(
                streamID: p.streamID,
                fragments: p.fragments,
                originalFlags: p.originalFlags,
                kind: p.kind,
                into: &output
            )
        }

        pending = p
        return false
    }

    private func handlePushPromise(_ frame: RawFrame, into output: inout Data) -> Bool {
        // RFC 9113 §6.6: PUSH_PROMISE is server-to-client only; forwarding one
        // upstream would have it GOAWAY the connection.
        guard direction == .outbound else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): PUSH_PROMISE on inbound leg (client → server); marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        // §6.6: PUSH_PROMISE on stream 0 is a protocol error.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): PUSH_PROMISE on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        guard let (promisedStreamID, body) = stripPushPromisePadding(frame: frame) else {
            return false
        }

        if body.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): PUSH_PROMISE payload \(body.count) B exceeded cap \(Self.maxHeaderBlockFragmentBytes); dropping")
            return false
        }

        if frame.flags & 0x4 != 0 { // END_HEADERS
            return finalizeHeaderBlock(
                streamID: frame.streamID,
                fragments: body,
                originalFlags: frame.flags,
                kind: .pushPromise(promisedStreamID: promisedStreamID),
                into: &output
            )
        }

        pending = PendingHeaders(
            streamID: frame.streamID,
            fragments: body,
            originalFlags: frame.flags,
            kind: .pushPromise(promisedStreamID: promisedStreamID)
        )
        return false
    }

    private func finalizeHeaderBlock(
        streamID: UInt32,
        fragments: Data,
        originalFlags: UInt8,
        kind: PendingHeaders.Kind,
        into output: inout Data
    ) -> Bool {
        guard let decodeResult = decoder.decodeHeaders(from: fragments) else {
            // HPACK decode failure desyncs the dynamic table irrecoverably — later
            // HEADERS would decode silently corrupted. Trip parseError; peer GOAWAYs.
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): HPACK decode failed; marking parseError to prevent table desync")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        let decoded = decodeResult.fields
        let neverIndexed = decodeResult.neverIndexed

        // Classify BEFORE header rules run. No `:method`/`:status` = trailer
        // (RFC 9113 §8.1); 1xx except 101 = interim — the request-log record must
        // stay live for the final response.
        let isTrailer: Bool
        let isInterimResponse: Bool
        if case .headers = kind {
            switch direction {
            case .inbound:
                isTrailer = firstHeaderValue(decoded, name: ":method") == nil
                isInterimResponse = false
            case .outbound:
                if let raw = firstHeaderValue(decoded, name: ":status"),
                   let status = parseHTTPStatusCode(raw) {
                    isTrailer = false
                    isInterimResponse = (100..<200).contains(status) && status != 101
                } else {
                    isTrailer = true
                    isInterimResponse = false
                }
            }
        } else {
            isTrailer = false
            isInterimResponse = false
        }

        // A trailer / follow-on HEADERS on a scripted stream flushes deferred script
        // state first. The flush may park; the continuation processes this block in wire order.
        if case .headers = kind {
            if pendingMessages[streamID] != nil {
                return runScriptsAndFlush(streamID: streamID, endStream: false, into: &output) { [weak self] out in
                    guard let self else { return false }
                    // A request-phase Anywhere.respond on the flushed message
                    // short-circuits the stream; don't process the trailer.
                    if self.synthRespondedStreams.contains(streamID) { return false }
                    return self.processFreshHeaderBlock(
                        streamID: streamID,
                        decoded: decoded,
                        neverIndexed: neverIndexed,
                        originalFlags: originalFlags,
                        kind: kind,
                        isTrailer: isTrailer,
                        isInterimResponse: isInterimResponse,
                        into: &out
                    )
                }
            } else if streamingScripts[streamID] != nil {
                return flushStreamingScript(streamID: streamID, into: &output) { [weak self] out in
                    guard let self else { return false }
                    return self.processFreshHeaderBlock(
                        streamID: streamID,
                        decoded: decoded,
                        neverIndexed: neverIndexed,
                        originalFlags: originalFlags,
                        kind: kind,
                        isTrailer: isTrailer,
                        isInterimResponse: isInterimResponse,
                        into: &out
                    )
                }
            }
        }
        return processFreshHeaderBlock(
            streamID: streamID,
            decoded: decoded,
            neverIndexed: neverIndexed,
            originalFlags: originalFlags,
            kind: kind,
            isTrailer: isTrailer,
            isInterimResponse: isInterimResponse,
            into: &output
        )
    }

    /// Emits the withheld first-request HEADERS before ``streamID`` opens, preserving
    /// stream-ID order (RFC 9113 §5.1.1); ``Anywhere.respond`` can no longer short-circuit it.
    private func commitDeferredFirstRequestIfNeeded(before streamID: UInt32, into output: inout Data) {
        guard let deferred = deferredFirstStreamID, deferred != streamID else { return }
        deferredFirstStreamID = nil
        guard var pending = pendingMessages[deferred],
              !pending.headersAlreadyEmitted, !pending.abandoned else { return }
        var openingHeaders = pending.headers
        if pending.codec.requiresDecompression {
            openingHeaders.removeAll { $0.name.equalsIgnoringASCIICase("content-encoding") }
        }
        logHTTP2Request(streamID: deferred, headers: openingHeaders)
        output.append(emitHeaderBlock(
            streamID: deferred,
            block: HPACKEncoder.encodeHeaderBlock(openingHeaders, neverIndexed: pending.neverIndexed),
            endStream: false,
            kind: .headers
        ))
        pending.headers = openingHeaders
        pending.headersAlreadyEmitted = true
        pendingMessages[deferred] = pending
    }

    /// Runs header rules then dispatches to streaming-script, buffered-script,
    /// or pass-through. Returns true when a script hop parks.
    private func processFreshHeaderBlock(
        streamID: UInt32,
        decoded: [(name: String, value: String)],
        neverIndexed: Set<String>,
        originalFlags: UInt8,
        kind: PendingHeaders.Kind,
        isTrailer: Bool,
        isInterimResponse: Bool,
        into output: inout Data
    ) -> Bool {
        // Pop/peek the originating request before the header transform so the response
        // URL-gate tests the original path; interim 1xx peeks so the record stays live.
        let originatingRequest: MITMRequestLog.Record?
        if case .headers = kind, direction == .outbound, !isTrailer {
            if isInterimResponse {
                originatingRequest = rewriter.requestLog.peekHTTP2(streamID: streamID)
            } else {
                originatingRequest = rewriter.requestLog.popHTTP2(streamID: streamID)
            }
        } else {
            originatingRequest = nil
        }
        let responseURL = (direction == .outbound)
            ? originatingRequest?.url
            : nil

        // Captured before ``didForwardUpstreamRequest`` is set below.
        var isFirstUpstreamRequest = false

        if case .headers = kind, direction == .inbound, !isTrailer {
            isFirstUpstreamRequest = !didForwardUpstreamRequest
            let requestGateURL = MITMHTTP2Rewriter.requestPath(in: decoded)
                .map { "https://\(rewriter.host)\($0)" }
            if let synth = rewriter.requestSynthResponse(requestURL: requestGateURL) {
                queueSynthesizedResponse(streamID: streamID, response: synth)
                return false
            }
            commitDeferredFirstRequestIfNeeded(before: streamID, into: &output)
            didForwardUpstreamRequest = true
        }

        var rewritten: [(name: String, value: String)]
        switch kind {
        case .headers:
            rewritten = (direction == .inbound)
                ? rewriter.transformRequestHeaders(decoded, streamID: streamID)
                : rewriter.transformResponseHeaders(decoded, streamID: streamID, requestURL: responseURL)
        case .pushPromise:
            rewritten = decoded
        }

        let endStreamOnHeaders = originalFlags & 0x1 != 0
        let gateURL = (direction == .inbound)
            ? MITMHTTP2Rewriter.requestPath(in: rewritten).map { "https://\(rewriter.host)\($0)" }
            : responseURL

        // CONNECT (incl. RFC 8441 extended CONNECT) must never enter buffered or
        // streaming mode: buffering would hold tunnel frames until close, and the
        // buffered flush's header rebuild would drop ``:protocol`` and force-synthesize
        // ``:scheme``/``:path``. Pass-through is the only correct handling.
        let isConnectRequest = direction == .inbound
            && firstHeaderValue(decoded, name: ":method") == "CONNECT"

        // ``endStreamOnHeaders`` skips the streaming branch (no DATA for the script
        // to fire on); past the tracked-stream cap the stream passes through un-MITM'd.
        let trackedStreamCapReached: Bool = {
            guard case .headers = kind, !isTrailer, !isInterimResponse,
                  streamingScripts[streamID] == nil, pendingMessages[streamID] == nil
            else { return false }
            return pendingMessages.count + streamingScripts.count >= Self.maxTrackedStreams
        }()
        if trackedStreamCapReached {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): tracked-stream cap \(Self.maxTrackedStreams) reached; passing through without MITM")
        }

        if case .headers = kind, !isTrailer, !isInterimResponse, !isConnectRequest,
           !endStreamOnHeaders, !trackedStreamCapReached,
           rewriter.hasStreamScriptRule(phase: phase, requestURL: gateURL) {
            if rewriter.hasBufferedBodyRule(phase: phase, requestURL: gateURL) {
                logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): Stream Script rule wins over buffered body rule")
            }

            if direction == .inbound {
                logHTTP2Request(streamID: streamID, headers: rewritten)
            }
            streamingScripts[streamID] = StreamingState(
                headers: rewritten,
                originatingRequest: originatingRequest,
                cursor: MITMScriptTransform.FrameCursor()
            )

            let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten, neverIndexed: neverIndexed)
            output.append(emitHeaderBlock(
                streamID: streamID,
                block: reencoded,
                endStream: false,
                kind: kind
            ))
            return false
        }

        // Buffered-script mode: defer HEADERS until the body is complete so body-driven
        // header changes can be reflected and a request-phase Anywhere.respond can still
        // suppress the stream. END_STREAM-on-HEADERS runs the script on an empty body.
        if case .headers = kind, !isTrailer, !isInterimResponse, !isConnectRequest,
           !trackedStreamCapReached,
           rewriter.hasBufferedBodyRule(phase: phase, requestURL: gateURL),
           shouldBufferStream(headers: rewritten, endStream: endStreamOnHeaders) {
            if !endStreamOnHeaders {
                warnIfBufferedScriptDeStreams(streamID: streamID, headers: rewritten)
            }
            let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewritten, name: "content-encoding"))
            // Drop content-length (post-script size is unknown). Keep content-encoding —
            // it's stripped after successful decompression, or kept for the verbatim fallback.
            rewritten.removeAll { $0.name.equalsIgnoringASCIICase("content-length") }

            // Early-open inbound bodied requests to preserve stream-ID order (RFC 9113
            // §5.1.1). Exception: the first upstream request withholds its HEADERS so
            // a request-phase Anywhere.respond can still short-circuit it.
            if direction == .inbound, !endStreamOnHeaders, !isFirstUpstreamRequest {
                var openingHeaders = rewritten
                if codec.requiresDecompression {
                    openingHeaders.removeAll { $0.name.equalsIgnoringASCIICase("content-encoding") }
                }
                logHTTP2Request(streamID: streamID, headers: openingHeaders)
                output.append(emitHeaderBlock(
                    streamID: streamID,
                    block: HPACKEncoder.encodeHeaderBlock(openingHeaders, neverIndexed: neverIndexed),
                    endStream: false,
                    kind: kind
                ))
                pendingMessages[streamID] = PendingMessage(
                    data: Data(),
                    codec: codec,
                    headers: openingHeaders,
                    originatingRequest: originatingRequest,
                    neverIndexed: neverIndexed,
                    headersAlreadyEmitted: true
                )
                return false
            }
            if direction == .inbound, !endStreamOnHeaders, isFirstUpstreamRequest {
                deferredFirstStreamID = streamID
            }
            pendingMessages[streamID] = PendingMessage(
                data: Data(),
                codec: codec,
                headers: rewritten,
                originatingRequest: originatingRequest,
                neverIndexed: neverIndexed
            )

            if endStreamOnHeaders {
                return runScriptsAndFlush(streamID: streamID, endStream: true, into: &output) { _ in false }
            }
            return false
        }

        // Pass-through: log the request so the response side has ctx.method/url.
        // Skip trailers — no pseudo-headers; they'd overwrite the log entry with nils.
        if case .headers = kind, direction == .inbound, !isTrailer {
            logHTTP2Request(streamID: streamID, headers: rewritten)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten, neverIndexed: neverIndexed)
        output.append(emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: endStreamOnHeaders,
            kind: kind
        ))
        return false
    }

    // MARK: - DATA

    private func handleData(_ frame: RawFrame, into output: inout Data) -> Bool {
        // RFC 9113 §6.1: DATA on stream 0 is a connection-level protocol violation.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): DATA on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        guard let body = stripDataPadding(frame: frame) else {
            return false
        }

        let endStream = frame.flags & 0x1 != 0
        let streamID = frame.streamID

        // Streaming-script path: script this single DATA frame and emit immediately —
        // no buffering or decompression, so gRPC and friends stay streaming. May park.
        if streamingScripts[streamID] != nil {
            return handleStreamingData(
                streamID: streamID,
                body: body,
                endStream: endStream,
                into: &output
            )
        }

        // Pass-through: no script for this stream; re-emit with PADDED cleared.
        guard var pending = pendingMessages[streamID] else {
            output.append(emitDataFrames(streamID: streamID, payload: body, endStream: endStream))
            return false
        }

        // Abandoned: HEADERS + buffered prefix already emitted; forward this frame
        // verbatim and clean up at END_STREAM.
        if pending.abandoned {
            if endStream {
                pendingMessages.removeValue(forKey: streamID)
            } else {
                pendingMessages[streamID] = pending
            }
            output.append(emitDataFrames(streamID: streamID, payload: body, endStream: endStream))
            return false
        }

        pending.data.append(body)
        // The receiver emits no WINDOW_UPDATEs while we buffer, so credit the sender
        // directly to keep the windows open. Uses the full on-wire payload length
        // (including padding), matching what the sender debited.
        creditBufferedDataToSender(streamID: streamID, flowControlledLength: frame.payload.count)

        // Mid-stream cap: only reachable for identity bodies (compressed bodies are pre-gated).
        if !endStream, pending.data.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): exceeded cap \(MITMBodyCodec.maxBufferedBodyBytes); abandoning")
            output.append(abandonPending(streamID: streamID, pending: &pending))
            return false
        }

        pendingMessages[streamID] = pending
        if !endStream {
            return false
        }
        return runScriptsAndFlush(streamID: streamID, endStream: true, into: &output) { _ in false }
    }

    /// Closes out a streaming-script stream when END_STREAM lands on a trailer
    /// HEADERS: emits the held final DATA with ``frame.end = true`` (the wire
    /// END_STREAM stays on the trailer). Parks while the final script runs;
    /// ``continuation`` processes the trailing HEADERS.
    private func flushStreamingScript(
        streamID: UInt32,
        into output: inout Data,
        then continuation: @escaping (inout Data) -> Bool
    ) -> Bool {
        guard var streaming = streamingScripts[streamID] else {
            return continuation(&output)
        }
        let body = streaming.pendingFrame ?? Data()
        streaming.pendingFrame = nil
        streamingScripts[streamID] = streaming
        return processStreamingFrame(
            streamID: streamID,
            body: body,
            isLast: true,
            wireEndStream: false,
            into: &output
        ) { [weak self] out in
            self?.streamingScripts.removeValue(forKey: streamID)
            return continuation(&out)
        }
    }

    /// Streaming-script per-DATA-frame handler; manages the one-frame lookahead so
    /// ``frame.end = true`` always coincides with the last DATA's bytes.
    private func handleStreamingData(
        streamID: UInt32,
        body: Data,
        endStream: Bool,
        into output: inout Data
    ) -> Bool {
        // Release the held frame as non-final; both frames chain via continuations
        // to preserve wire order across a park.
        guard let streaming = streamingScripts[streamID] else {
            return handleStreamingCurrentFrame(streamID: streamID, body: body, endStream: endStream, into: &output)
        }
        if let held = streaming.pendingFrame {
            var cleared = streaming
            cleared.pendingFrame = nil
            streamingScripts[streamID] = cleared
            return processStreamingFrame(
                streamID: streamID,
                body: held,
                isLast: false,
                wireEndStream: false,
                into: &output
            ) { [weak self] out in
                guard let self else { return false }
                return self.handleStreamingCurrentFrame(streamID: streamID, body: body, endStream: endStream, into: &out)
            }
        }
        return handleStreamingCurrentFrame(streamID: streamID, body: body, endStream: endStream, into: &output)
    }

    /// On END_STREAM emits as final and clears the stream entry; otherwise stashes as lookahead.
    private func handleStreamingCurrentFrame(
        streamID: UInt32,
        body: Data,
        endStream: Bool,
        into output: inout Data
    ) -> Bool {
        if endStream {
            return processStreamingFrame(
                streamID: streamID,
                body: body,
                isLast: true,
                wireEndStream: true,
                into: &output
            ) { [weak self] _ in
                self?.streamingScripts.removeValue(forKey: streamID)
                return false
            }
        }
        if var streaming = streamingScripts[streamID] {
            streaming.pendingFrame = body
            streamingScripts[streamID] = streaming
        }
        return false
    }

    /// Runs one DATA frame through the streaming-script chain. ``isLast`` is the
    /// script's ``ctx.frame.end``; ``wireEndStream`` is the emitted END_STREAM bit —
    /// they diverge on trailer flush. Scripted streams park and resume via continuation.
    private func processStreamingFrame(
        streamID: UInt32,
        body: Data,
        isLast: Bool,
        wireEndStream: Bool,
        into output: inout Data,
        then continuation: @escaping (inout Data) -> Bool
    ) -> Bool {
        guard var streaming = streamingScripts[streamID] else {
            return continuation(&output)
        }
        if streaming.cursor.bypass {
            streaming.frameIndex += 1
            streamingScripts[streamID] = streaming
            // Don't emit an empty non-terminal DATA; end-of-stream still needs a
            // frame to carry the flag.
            if !(body.isEmpty && !wireEndStream) {
                output.append(emitDataFrames(streamID: streamID, payload: body, endStream: wireEndStream))
            }
            return continuation(&output)
        }
        let ctx = MITMScriptEngine.FrameContext(
            phase: phase,
            method: streaming.originatingRequest?.method
                ?? firstHeaderValue(streaming.headers, name: ":method"),
            url: streamingURL(streaming),
            status: parseStatus(streaming.headers),
            headers: streaming.headers.filter { !$0.name.hasPrefix(":") },
            frameIndex: streaming.frameIndex,
            isLast: isLast,
            ruleSetID: rewriter.ruleSetID
        )
        MITMScriptTransform.applyFrame(
            body,
            rules: rewriter.rules(phase: phase),
            frameContext: ctx,
            cursor: streaming.cursor,
            engineProvider: rewriter.scriptEngineProvider,
            resumeOn: lwipQueue
        ) { [weak self] result in
            guard let self else { return }
            guard !self.torn else { return }
            var resumed = self.pendingPreParkOutput
            self.pendingPreParkOutput = Data()
            self.emitStreamFrameResult(
                result: result,
                streamID: streamID,
                body: body,
                wireEndStream: wireEndStream,
                into: &resumed
            )
            var parkedAgain = continuation(&resumed)
            if !parkedAgain {
                parkedAgain = self.pump(into: &resumed)
            }
            self.finishPumpPass(resumed, parkedAgain: parkedAgain)
        }
        return true
    }

    /// Applies a streaming frame's script result: enforces the cumulative growth cap
    /// (bypass on overflow), advances the frame index, and emits the resulting DATA.
    private func emitStreamFrameResult(
        result: MITMScriptTransform.StreamFrameResult,
        streamID: UInt32,
        body: Data,
        wireEndStream: Bool,
        into output: inout Data
    ) {
        guard var streaming = streamingScripts[streamID] else {
            // Stream removed during the hop (shouldn't happen while parked); emit best-effort.
            if !(result.body.isEmpty && !wireEndStream) {
                output.append(emitDataFrames(streamID: streamID, payload: result.body, endStream: wireEndStream))
            }
            return
        }
        // Cap cumulative wire growth — the receiver's window budgets only the original
        // sender's bytes. Clamp to zero instead of banking headroom from a shrink.
        let emitted: Data
        let growth = result.body.count - body.count
        let projected = max(0, streaming.cumulativeGrowth + growth)
        if projected > Self.maxStreamingRewriteGrowthBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): streamScript projected growth \(projected) B exceeded cap \(Self.maxStreamingRewriteGrowthBytes) B; bypassing this frame and remaining frames")
            streaming.cursor.bypass = true
            emitted = body
        } else {
            streaming.cumulativeGrowth = projected
            emitted = result.body
        }
        streaming.frameIndex += 1
        streamingScripts[streamID] = streaming
        if !(emitted.isEmpty && !wireEndStream) {
            output.append(emitDataFrames(streamID: streamID, payload: emitted, endStream: wireEndStream))
        }
    }

    /// URL for streaming-script ``ctx.url``; uses the connection's destination host
    /// (not the rewritten ``:authority``) on request phase, consistent with HTTP/1.
    private func streamingURL(_ streaming: StreamingState) -> String? {
        if phase == .httpResponse {
            return streaming.originatingRequest?.url
        }
        guard let path = firstHeaderValue(streaming.headers, name: ":path") else {
            return nil
        }
        return "https://\(rewriter.host)\(path)"
    }

    private func parseStatus(_ headers: [(name: String, value: String)]) -> Int? {
        guard phase == .httpResponse,
              let raw = firstHeaderValue(headers, name: ":status"),
              let code = parseHTTPStatusCode(raw)
        else { return nil }
        return code
    }

    /// Emits deferred HEADERS + buffered prefix without scripts and marks the message
    /// ``abandoned``; called when the body overflows the buffer cap mid-stream.
    private func abandonPending(streamID: UInt32, pending: inout PendingMessage) -> Data {
        if deferredFirstStreamID == streamID {
            deferredFirstStreamID = nil
        }
        let prefix = pending.data
        pending.data = Data()
        pending.abandoned = true
        if pending.headersAlreadyEmitted {
            if pending.codec.requiresDecompression {
                // HEADERS announced identity but the body is still compressed; emitting
                // it would contradict the declared framing. Reset both legs instead.
                pendingMessages.removeValue(forKey: streamID)
                markSynthResponded(streamID)
                pendingClientBytes.append(rstStreamFrame(streamID: streamID, errorCode: Self.errorCodeInternal))
                return rstStreamFrame(streamID: streamID, errorCode: Self.errorCodeInternal)
            }
            pendingMessages[streamID] = pending
            return emitBufferedDataFrames(streamID: streamID, payload: prefix, endStream: false)
        }
        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: pending.headers)
        }
        let reencoded = HPACKEncoder.encodeHeaderBlock(pending.headers, neverIndexed: pending.neverIndexed)
        var out = emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: false,
            kind: .headers
        )
        out.append(emitBufferedDataFrames(streamID: streamID, payload: prefix, endStream: false))
        pendingMessages[streamID] = pending
        return out
    }

    /// Emits deferred HEADERS + raw buffered body without scripts; used when
    /// decompression fails (content-encoding is still on the headers).
    private func emitPassthroughDeferred(
        streamID: UInt32,
        pending: PendingMessage,
        endStream: Bool
    ) -> Data {
        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: pending.headers)
        }
        let reencoded = HPACKEncoder.encodeHeaderBlock(pending.headers, neverIndexed: pending.neverIndexed)
        let body = pending.data
        let headersHaveEndStream = endStream && body.isEmpty
        var out = emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: headersHaveEndStream,
            kind: .headers
        )
        if !body.isEmpty {
            out.append(emitBufferedDataFrames(streamID: streamID, payload: body, endStream: endStream))
        }
        return out
    }

    /// Runs the script chain on the buffered message and emits the final HEADERS +
    /// rewritten body. Parks off-queue and runs ``continuation`` from the resume;
    /// no-pending/abandoned/decompression-failure cases run it inline.
    private func runScriptsAndFlush(
        streamID: UInt32,
        endStream: Bool,
        into output: inout Data,
        then continuation: @escaping (inout Data) -> Bool
    ) -> Bool {
        guard let pending = pendingMessages.removeValue(forKey: streamID) else {
            return continuation(&output)
        }
        if deferredFirstStreamID == streamID {
            deferredFirstStreamID = nil
        }
        if pending.abandoned {
            return continuation(&output)
        }
        let plaintext: Data
        if pending.codec.requiresDecompression {
            // On decompression failure, emit deferred HEADERS + raw bytes verbatim
            // (``pending.headers`` still carries content-encoding).
            guard let decoded = MITMBodyCodec.decompress(pending.data, plan: pending.codec, host: rewriter.host) else {
                if pending.headersAlreadyEmitted {
                    // HEADERS already announced identity; emitting compressed bytes
                    // would contradict the framing. Reset both legs instead.
                    output.append(rstStreamFrame(streamID: streamID, errorCode: Self.errorCodeInternal))
                    pendingClientBytes.append(rstStreamFrame(streamID: streamID, errorCode: Self.errorCodeInternal))
                    markSynthResponded(streamID)
                } else {
                    output.append(emitPassthroughDeferred(streamID: streamID, pending: pending, endStream: endStream))
                }
                return continuation(&output)
            }
            plaintext = decoded
        } else {
            plaintext = pending.data
        }
        // Strip content-encoding on successful decompression — we're emitting identity.
        let scriptedHeaders: [(name: String, value: String)]
        if pending.codec.requiresDecompression {
            scriptedHeaders = pending.headers.filter { !$0.name.equalsIgnoringASCIICase("content-encoding") }
        } else {
            scriptedHeaders = pending.headers
        }
        let inputMessage = buildMessage(
            headers: scriptedHeaders,
            body: plaintext,
            originatingRequest: pending.originatingRequest
        )
        rewriter.applyScripts(inputMessage, phase: phase, resumeOn: lwipQueue) { [weak self] outcome in
            guard let self, !self.torn else { return }
            var resumed = self.pendingPreParkOutput
            self.pendingPreParkOutput = Data()
            self.emitFlushResult(
                outcome: outcome,
                streamID: streamID,
                endStream: endStream,
                pending: pending,
                plaintext: plaintext,
                into: &resumed
            )
            var parkedAgain = continuation(&resumed)
            // Drain frames already in rxBuffer — otherwise they're stranded until
            // the next receive, potentially deadlocking.
            if !parkedAgain {
                parkedAgain = self.pump(into: &resumed)
            }
            self.finishPumpPass(resumed, parkedAgain: parkedAgain)
        }
        return true
    }

    /// Applies a buffered-message flush result: synth short-circuit, passthrough
    /// fallback on excessive growth, or rewritten HEADERS + body.
    private func emitFlushResult(
        outcome: MITMScriptTransform.Outcome,
        streamID: UInt32,
        endStream: Bool,
        pending: PendingMessage,
        plaintext: Data,
        into output: inout Data
    ) {
        // Early-open path: HEADERS are already on the wire; only the body can change.
        if pending.headersAlreadyEmitted {
            let body: Data
            switch outcome {
            case .message(let updated):
                if updated.body.count > plaintext.count,
                   updated.body.count - plaintext.count > Self.maxBufferedRewriteGrowthBytes {
                    logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): script grew body by \(updated.body.count - plaintext.count) B (cap \(Self.maxBufferedRewriteGrowthBytes) B); emitting original body")
                    body = plaintext
                } else {
                    body = updated.body
                }
            case .synthesizedResponse:
                logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): Anywhere.respond ignored on an already-opened request stream; forwarding original body")
                body = plaintext
            }
            let serverPacingWindow = Swift.max(0, Swift.min(flowController.serverConnectionWindow, flowController.serverInitialStreamWindow))
            if direction == .inbound, endStream, !body.isEmpty, body.count > serverPacingWindow {
                output.append(paceUpstreamRequestBody(streamID: streamID, body: body, endStream: endStream))
                return
            }
            output.append(emitBufferedDataFrames(streamID: streamID, payload: body, endStream: endStream))
            return
        }

        let result: HTTPMessage
        switch outcome {
        case .message(let updated):
            result = updated
        case .synthesizedResponse(let response):
            // Request-phase short-circuit: the upstream never saw HEADERS, so nothing to RST.
            queueSynthesizedResponse(streamID: streamID, response: response)
            return
        }

        // Script-introduced growth is unaccounted in the receiver's window and can
        // cause FLOW_CONTROL_ERROR. Baseline is the decompressed plaintext —
        // decompression is not "growth", and compressed size would wrongly trip
        // the cap for any script on a gzip body.
        let originalIdentityBytes = plaintext.count
        let rewrittenWireBytes = result.body.count
        if rewrittenWireBytes > originalIdentityBytes,
           rewrittenWireBytes - originalIdentityBytes > Self.maxBufferedRewriteGrowthBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): script grew body by \(rewrittenWireBytes - originalIdentityBytes) B (cap \(Self.maxBufferedRewriteGrowthBytes) B); emitting original payload")
            output.append(emitPassthroughDeferred(streamID: streamID, pending: pending, endStream: endStream))
            return
        }

        let finalHeaders = rebuildHeaders(from: result, fallback: pending.headers)

        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: finalHeaders)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(finalHeaders, neverIndexed: pending.neverIndexed)
        // RFC 9110 §15.2: HEAD responses carry no body; drop any script-written bytes.
        let isHeadResponse = phase == .httpResponse
            && pending.originatingRequest?.method?.uppercased() == "HEAD"
        let body = isHeadResponse ? Data() : result.body
        let headersHaveEndStream = endStream && body.isEmpty
        // Pace a buffered RESPONSE body against the client's windows (still at initial
        // values while buffered; a decompressed body can far exceed them). Gated on
        // ``endStream`` so a trailer can't race ahead of a still-draining paced body.
        let pacingWindow = Swift.max(0, Swift.min(flowController.connectionWindow, flowController.clientInitialStreamWindow))
        if direction == .outbound, endStream, !body.isEmpty, body.count > pacingWindow,
           let onPacedResponse,
           onPacedResponse(streamID, reencoded, body, endStream) {
            return
        }
        // Mirror for a buffered REQUEST body: same overflow risk, same gating.
        let serverPacingWindow = Swift.max(0, Swift.min(flowController.serverConnectionWindow, flowController.serverInitialStreamWindow))
        if direction == .inbound, endStream, !body.isEmpty, body.count > serverPacingWindow {
            output.append(emitHeaderBlock(
                streamID: streamID,
                block: reencoded,
                endStream: false,
                kind: .headers
            ))
            output.append(paceUpstreamRequestBody(streamID: streamID, body: body, endStream: endStream))
            return
        }
        output.append(emitHeaderBlock(
            streamID: streamID,
            block: reencoded,
            endStream: headersHaveEndStream,
            kind: .headers
        ))
        if !body.isEmpty {
            output.append(emitBufferedDataFrames(streamID: streamID, payload: body, endStream: endStream))
        }
    }

    // MARK: - Deferral policy

    /// Decides at HEADERS time whether a stream enters buffered-script mode;
    /// END_STREAM-on-HEADERS defers unconditionally so a script can mutate head fields.
    private func shouldBufferStream(
        headers: [(name: String, value: String)],
        endStream: Bool
    ) -> Bool {
        if endStream { return true }
        let codec = MITMBodyCodec.plan(for: firstHeaderValue(headers, name: "content-encoding"))
        guard codec.supported else { return false }
        if let raw = firstHeaderValue(headers, name: "content-length"),
           let length = Int(raw.trimmingCharacters(in: .whitespaces)) {
            return length <= MITMBodyCodec.maxBufferedBodyBytes
        }
        // Without content-length, only identity bodies can recover from a mid-stream
        // overflow; unbounded compressed bodies can't be buffered safely.
        return !codec.requiresDecompression
    }

    /// Warns when a buffered script will hold a streaming response (SSE etc.) until END_STREAM.
    private func warnIfBufferedScriptDeStreams(streamID: UInt32, headers: [(name: String, value: String)]) {
        let contentType = firstHeaderValue(headers, name: "content-type")
        guard phase == .httpResponse,
              MITMScriptTransform.isStreamingMediaType(contentType) else { return }
        logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): buffered Script on a streaming response. Switch to Stream Script to rewrite frames as they arrive.")
    }

    /// Max bytes a buffered script may add to the original body — growth eats into the
    /// receiver's window unaccounted. One spec-default initial window (RFC 9113 §6.9.2);
    /// scripts that grow further fall back to the original payload.
    private static let maxBufferedRewriteGrowthBytes: Int = 65_535

    /// Cumulative cap on streaming-script wire growth, same rationale as
    /// ``maxBufferedRewriteGrowthBytes``; overflow flips bypass for the rest of the stream.
    private static let maxStreamingRewriteGrowthBytes: Int = 65_535

    /// Serializes a request-phase ``Anywhere.respond`` reply as HEADERS + paced DATA
    /// into ``pendingClientBytes``. HEADERS go out immediately (not flow-controlled,
    /// RFC 9113 §6.9.1); the body drains as the client grants window. Inbound leg only.
    private func queueSynthesizedResponse(
        streamID: UInt32,
        response: MITMScriptEngine.SynthesizedResponse
    ) {
        var headers: [(name: String, value: String)] = [
            (name: ":status", value: String(response.status))
        ]
        headers.append(contentsOf: response.sanitizedHeaders(lowercaseNames: true) { name in
            logger.warning("[MITM][JS] HTTP/2 \(rewriter.host): Anywhere.respond dropping invalid header: \(name)")
        })
        let block = HPACKEncoder.encodeHeaderBlock(headers)

        // Cap the body to the per-message budget; wire delivery is paced separately.
        let body = response.truncatedBody(cap: MITMBodyCodec.maxBufferedBodyBytes) { size in
            logger.warning("[MITM][JS] HTTP/2 \(rewriter.host): Anywhere.respond body \(size) B exceeds memory cap \(MITMBodyCodec.maxBufferedBodyBytes) B; truncating")
        }

        let out = emitHeaderBlock(
            streamID: streamID,
            block: block,
            endStream: body.isEmpty,
            kind: .headers
        )
        let isPreEstablishment = !upstreamSetupForwarded
        if isPreEstablishment, !serverPrefaceSentToClient {
            // Inject the server preface; no upstream will relay one (won't dial).
            pendingClientBytes.append(serverConnectionPreface())
            serverPrefaceSentToClient = true
        }
        pendingClientBytes.append(out)

        // Record before any DATA so client follow-up frames are swallowed rather
        // than forwarded upstream on an idle stream.
        markSynthResponded(streamID)

        guard !body.isEmpty else {
            // No body — for a pre-establishment one-shot the GOAWAY goes now.
            if isPreEstablishment {
                pendingClientBytes.append(goAwayFrame(lastStreamID: forwardedRequestUpstream ? 0 : streamID))
                inboundClosed = true
            }
            return
        }

        pendingSynthBodies[streamID] = PendingSynthBody(
            remaining: body,
            streamWindow: flowController.clientInitialStreamWindow,
            isPreEstablishment: isPreEstablishment,
            goAwayLastStreamID: forwardedRequestUpstream ? 0 : streamID
        )
        flushPendingSynth(streamID: streamID)
    }

    /// Cap on total bytes held for client-bound pacing (a slow client can hold many
    /// concurrent bodies); 8 MiB is 2× the per-body cap.
    private static let maxPacedClientBufferBytes: Int = 2 * MITMBodyCodec.maxBufferedBodyBytes

    /// Accepts a buffered-rewrite RESPONSE body from the outbound leg and paces it to
    /// the client's windows. Does NOT ``markSynthResponded`` — the upstream opened this
    /// stream, so client RST_STREAM/trailer must still reach it. Inbound leg only.
    @discardableResult
    func queuePacedClientResponse(streamID: UInt32, headerBlock: Data, body: Data, endStream: Bool) -> Bool {
        let held = pendingSynthBodies.values.reduce(0) { $0 + $1.remaining.count }
        guard held + body.count <= Self.maxPacedClientBufferBytes else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): paced client buffer would reach \(held + body.count) B over cap \(Self.maxPacedClientBufferBytes) B; emitting response inline (unpaced)")
            return false
        }
        pendingClientBytes.append(emitHeaderBlock(
            streamID: streamID,
            block: headerBlock,
            endStream: endStream && body.isEmpty,
            kind: .headers
        ))
        guard !body.isEmpty else { return true }
        pendingSynthBodies[streamID] = PendingSynthBody(
            remaining: body,
            streamWindow: flowController.clientInitialStreamWindow,
            isPreEstablishment: false,
            goAwayLastStreamID: 0
        )
        flushPendingSynth(streamID: streamID)
        return true
    }

    /// Emits as much of the stream's buffered synth body as the windows allow;
    /// END_STREAM on the last frame, deferred GOAWAY for pre-establishment one-shots.
    private func flushPendingSynth(streamID: UInt32) {
        guard var entry = pendingSynthBodies[streamID] else { return }
        let available = max(0, min(flowController.connectionWindow, entry.streamWindow, entry.remaining.count))
        if available > 0 {
            let chunkEnd = entry.remaining.startIndex + available
            let chunk = entry.remaining.subdata(in: entry.remaining.startIndex..<chunkEnd)
            let didFinish = available == entry.remaining.count
            // Cross-direction: inbound leg emitting client-bound DATA, so debit
            // the client connection window explicitly.
            pendingClientBytes.append(frameData(streamID: streamID, payload: chunk, endStream: didFinish))
            flowController.debitConnection(available)
            entry.streamWindow -= available
            // Record synth debt so these bytes are withheld from the upstream relay;
            // pre-establishment one-shots never dial, so nothing to record.
            if !entry.isPreEstablishment {
                flowController.addSynthDebt(available)
            }
            entry.remaining.removeFirst(available)
            if didFinish {
                completeSynthStream(streamID: streamID, entry: entry)
                return
            }
        }
        pendingSynthBodies[streamID] = entry
        if entry.isPreEstablishment {
            oneShotSynthPacing = true
        }
    }

    /// Flushes all buffered client-bound bodies in stream-ID order until the shared
    /// connection window is exhausted; keys are snapshotted so mid-iteration removal is safe.
    private func flushAllPendingSynth() {
        guard !pendingSynthBodies.isEmpty else { return }
        for streamID in pendingSynthBodies.keys.sorted() {
            if flowController.connectionWindow <= 0 { break }
            if pendingSynthBodies[streamID] != nil {
                flushPendingSynth(streamID: streamID)
            }
        }
    }

    /// Finalizes a fully-delivered synth stream; pre-establishment one-shots emit the deferred GOAWAY.
    private func completeSynthStream(streamID: UInt32, entry: PendingSynthBody) {
        pendingSynthBodies.removeValue(forKey: streamID)
        if entry.isPreEstablishment {
            pendingClientBytes.append(goAwayFrame(lastStreamID: entry.goAwayLastStreamID))
            inboundClosed = true
            oneShotSynthPacing = false
        }
    }

    // MARK: - Upstream request-body pacing (mirror of the synth/response pacing)

    /// Cap on bytes held for server-bound request-body pacing. Past this the
    /// inbound leg emits inline instead.
    private static let maxPacedServerBufferBytes: Int = 2 * MITMBodyCodec.maxBufferedBodyBytes

    /// Routes a stream-ending buffered REQUEST body (HEADERS already on the wire)
    /// through upstream pacing: hands it to the outbound leg's pacer, or pre-dial
    /// holds it for the session to transfer. Returns inline frames when declined.
    /// Inbound leg only.
    private func paceUpstreamRequestBody(streamID: UInt32, body: Data, endStream: Bool) -> Data {
        if let onPacedRequest {
            if onPacedRequest(streamID, body, endStream) {
                return Data()
            }
            return emitBufferedDataFrames(streamID: streamID, payload: body, endStream: endStream)
        }
        // Pre-dial hold. Enforce the same cap as the live pacer so the transfer
        // can't be declined, silently dropping a body and hanging its stream.
        let held = heldPacedRequests.values.reduce(0) { $0 + $1.body.count }
        guard held + body.count <= Self.maxPacedServerBufferBytes else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): pre-dial held request buffer would reach \(held + body.count) B over cap \(Self.maxPacedServerBufferBytes) B; emitting request inline (unpaced)")
            return emitBufferedDataFrames(streamID: streamID, payload: body, endStream: endStream)
        }
        heldPacedRequests[streamID] = (body: body, endStream: endStream)
        return Data()
    }

    /// Accepts a buffered REQUEST body and paces it against the server's windows,
    /// emitting to ``pendingServerBytes``; declines when at budget. Outbound leg only.
    @discardableResult
    func queuePacedServerRequest(streamID: UInt32, body: Data, endStream: Bool) -> Bool {
        let held = pendingRequestBodies.values.reduce(0) { $0 + $1.remaining.count }
        guard held + body.count <= Self.maxPacedServerBufferBytes else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): paced server buffer would reach \(held + body.count) B over cap \(Self.maxPacedServerBufferBytes) B; emitting request inline (unpaced)")
            return false
        }
        guard !body.isEmpty else {
            // HEADERS went out without END_STREAM; send the marker now.
            if endStream {
                pendingServerBytes.append(frameData(streamID: streamID, payload: Data(), endStream: true))
            }
            return true
        }
        pendingRequestBodies[streamID] = PendingRequestBody(
            remaining: body,
            streamWindow: flowController.serverInitialStreamWindow
        )
        flushPendingRequest(streamID: streamID)
        return true
    }

    /// Emits as much of the stream's buffered request body as the server's windows allow.
    private func flushPendingRequest(streamID: UInt32) {
        guard var entry = pendingRequestBodies[streamID] else { return }
        let available = max(0, min(flowController.serverConnectionWindow, entry.streamWindow, entry.remaining.count))
        if available > 0 {
            let chunkEnd = entry.remaining.startIndex + available
            let chunk = entry.remaining.subdata(in: entry.remaining.startIndex..<chunkEnd)
            let didFinish = available == entry.remaining.count
            // Cross-direction: debit the server connection window explicitly and record
            // client-request debt so the server's eventual credit is withheld from the relay.
            pendingServerBytes.append(frameData(streamID: streamID, payload: chunk, endStream: didFinish))
            flowController.debitServerConnection(available)
            flowController.addClientRequestDebt(available)
            entry.streamWindow -= available
            entry.remaining.removeFirst(available)
            if didFinish {
                pendingRequestBodies.removeValue(forKey: streamID)
                return
            }
        }
        pendingRequestBodies[streamID] = entry
    }

    /// Drains all buffered request bodies in stream-ID order until the server
    /// connection window is exhausted.
    private func flushAllPendingRequests() {
        guard !pendingRequestBodies.isEmpty else { return }
        for streamID in pendingRequestBodies.keys.sorted() {
            if flowController.serverConnectionWindow <= 0 { break }
            if pendingRequestBodies[streamID] != nil {
                flushPendingRequest(streamID: streamID)
            }
        }
    }

    /// Drops the paced request body for an aborted stream. Outbound leg only.
    func dropPacedRequest(_ streamID: UInt32) {
        pendingRequestBodies.removeValue(forKey: streamID)
    }

    /// Returns and clears pre-dial held request bodies in stream-ID order. Inbound leg only.
    func takeHeldPacedRequests() -> [(streamID: UInt32, body: Data, endStream: Bool)] {
        guard !heldPacedRequests.isEmpty else { return [] }
        let ordered = heldPacedRequests.keys.sorted().map { sid -> (streamID: UInt32, body: Data, endStream: Bool) in
            let held = heldPacedRequests[sid]!
            return (streamID: sid, body: held.body, endStream: held.endStream)
        }
        heldPacedRequests.removeAll()
        return ordered
    }

    /// Applies a new server SETTINGS_INITIAL_WINDOW_SIZE's retroactive delta to open
    /// paced request streams (RFC 9113 §6.9.2).
    private func applyServerInitialWindowSize(_ newValue: Int) {
        let delta = flowController.updateServerInitialStreamWindow(newValue)
        guard delta != 0 else { return }
        for id in pendingRequestBodies.keys {
            pendingRequestBodies[id]?.streamWindow += delta
        }
        if delta > 0, !pendingRequestBodies.isEmpty {
            flushAllPendingRequests()
        }
    }

    /// Handles a WINDOW_UPDATE (RFC 9113 §6.9). Stream-0 frames credit the shared
    /// window and forward minus debt (a fully-withheld increment is dropped — zero
    /// increment is a PROTOCOL_ERROR, §6.9.1); frames on MITM-owned streams drive
    /// pacing and are swallowed; real streams forward verbatim.
    private func handleWindowUpdate(_ frame: RawFrame) -> Data {
        if direction == .outbound {
            let increment = Self.windowUpdateIncrement(frame.payload)
            if frame.streamID == 0 {
                if let increment, increment > 0 {
                    flowController.creditServerConnection(increment)
                    flushAllPendingRequests()
                }
                guard let increment, increment > 0 else {
                    return serializeFrame(frame)
                }
                let forwarded = flowController.withholdClientRequestDebt(from: increment)
                if forwarded == increment { return serializeFrame(frame) }
                if forwarded == 0 { return Data() }  // fully withheld → drop (zero WU is a PROTOCOL_ERROR)
                return windowUpdateFrame(streamID: 0, increment: forwarded)
            }
            // MITM-owned paced-request streams are never relayed to the client
            // (would double-credit); real streams forward verbatim.
            if pendingRequestBodies[frame.streamID] != nil {
                if let increment, increment > 0,
                   let current = pendingRequestBodies[frame.streamID]?.streamWindow {
                    // Clamp to 2^31-1 (§6.9.1); a legitimately negative window stays negative.
                    pendingRequestBodies[frame.streamID]?.streamWindow = min(MITMHTTP2FlowController.maxWindow, current + increment)
                    flushPendingRequest(streamID: frame.streamID)
                }
                return Data()
            }
            return serializeFrame(frame)
        }
        let increment = Self.windowUpdateIncrement(frame.payload)

        if frame.streamID == 0 {
            // Capture before flushing — ``flushAllPendingSynth`` may clear the flag,
            // but this frame still belongs to the never-dialing connection.
            let wasOneShotPacing = oneShotSynthPacing
            if let increment, increment > 0 {
                flowController.creditConnection(increment)
            }
            flushAllPendingSynth()
            if wasOneShotPacing { return Data() }
            guard let increment, increment > 0 else { return serializeFrame(frame) }
            let forwarded = flowController.withholdSynthDebt(from: increment)
            if forwarded == increment { return serializeFrame(frame) }
            if forwarded == 0 { return Data() }
            return windowUpdateFrame(streamID: 0, increment: forwarded)
        }

        let isSynthStream = pendingSynthBodies[frame.streamID] != nil
            || synthRespondedStreams.contains(frame.streamID)
        if isSynthStream {
            if let increment, increment > 0, let current = pendingSynthBodies[frame.streamID]?.streamWindow {
                // Clamp to 2^31-1 (RFC 9113 §6.9.1).
                pendingSynthBodies[frame.streamID]?.streamWindow = min(MITMHTTP2FlowController.maxWindow, current + increment)
                flushPendingSynth(streamID: frame.streamID)
            }
            return Data()
        }
        return serializeFrame(frame)
    }

    /// Decodes a WINDOW_UPDATE's 31-bit increment (RFC 9113 §6.9.1); nil for a
    /// non-4-byte payload so the caller forwards it verbatim.
    private static func windowUpdateIncrement(_ payload: Data) -> Int? {
        guard payload.count == 4 else { return nil }
        let s = payload.startIndex
        let b0 = UInt32(payload[s]) & 0x7F
        let b1 = UInt32(payload[s + 1])
        let b2 = UInt32(payload[s + 2])
        let b3 = UInt32(payload[s + 3])
        let value: UInt32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
        return Int(value)
    }

    private func windowUpdateFrame(streamID: UInt32, increment: Int) -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameTypeCode.windowUpdate, flags: 0, streamID: streamID, payloadLength: 4, into: &d)
        let v = UInt32(truncatingIfNeeded: increment) & 0x7FFF_FFFF
        d.append(UInt8((v >> 24) & 0xFF))
        d.append(UInt8((v >> 16) & 0xFF))
        d.append(UInt8((v >> 8) & 0xFF))
        d.append(UInt8(v & 0xFF))
        return d
    }

    /// A single empty SETTINGS frame; unlike ``serverConnectionPreface`` it carries
    /// no bundled SETTINGS ACK — the relayed origin ACK handles that.
    private func serverSettingsPreface() -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameTypeCode.settings, flags: 0, streamID: 0, payloadLength: 0, into: &d)
        return d
    }

    /// Emits the MITM's server SETTINGS preface to the client once — a client-bound
    /// frame ahead of the server SETTINGS triggers a PROTOCOL_ERROR GOAWAY (RFC 9113
    /// §3.4). The client's ACK is swallowed. Idempotent; inbound leg only.
    private func ensureClientServerPrefaceSent() {
        guard direction == .inbound, !serverPrefaceSentToClient else { return }
        pendingClientBytes.append(serverSettingsPreface())
        serverPrefaceSentToClient = true
        pendingClientSettingsAckSwallows += 1
    }

    private func serverConnectionPreface() -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameTypeCode.settings, flags: 0, streamID: 0, payloadLength: 0, into: &d)
        appendFrameHeader(typeCode: FrameTypeCode.settings, flags: 0x1, streamID: 0, payloadLength: 0, into: &d)
        return d
    }

    /// A GOAWAY (NO_ERROR) naming ``lastStreamID`` so the client retries higher
    /// streams on a fresh connection.
    private func goAwayFrame(lastStreamID: UInt32) -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameTypeCode.goaway, flags: 0, streamID: 0, payloadLength: 8, into: &d)
        let sid = lastStreamID & 0x7FFFFFFF
        d.append(UInt8((sid >> 24) & 0xFF))
        d.append(UInt8((sid >> 16) & 0xFF))
        d.append(UInt8((sid >> 8) & 0xFF))
        d.append(UInt8(sid & 0xFF))
        d.append(contentsOf: [0, 0, 0, 0]) // error code: NO_ERROR
        return d
    }

    /// INTERNAL_ERROR (RFC 9113 §7): reset a stream the MITM can no longer relay.
    private static let errorCodeInternal: UInt32 = 0x2

    /// RST_STREAM (RFC 9113 §6.4) so both peers release the stream without tearing
    /// down the connection.
    private func rstStreamFrame(streamID: UInt32, errorCode: UInt32) -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameTypeCode.rstStream, flags: 0, streamID: streamID, payloadLength: 4, into: &d)
        d.append(UInt8((errorCode >> 24) & 0xFF))
        d.append(UInt8((errorCode >> 16) & 0xFF))
        d.append(UInt8((errorCode >> 8) & 0xFF))
        d.append(UInt8(errorCode & 0xFF))
        return d
    }

    /// Inserts ``streamID`` into ``synthRespondedStreams`` and the FIFO, evicting the
    /// oldest settled entry at the cap. Eviction is best-effort — a late RST for an
    /// evicted ID may trigger an upstream GOAWAY, but the risk is bounded and rare.
    private func markSynthResponded(_ streamID: UInt32) {
        guard synthRespondedStreams.insert(streamID).inserted else { return }
        synthRespondedOrder.append(streamID)
        guard synthRespondedOrder.count > Self.synthRespondedMaxStreams else { return }
        // Evict the oldest *settled* stream — evicting one that still owes DATA would
        // orphan a half-delivered response. Exclude the stream just appended: its
        // ``pendingSynthBodies`` entry is set after this returns, so it looks settled.
        guard let evictIdx = synthRespondedOrder.firstIndex(where: {
            $0 != streamID && pendingSynthBodies[$0] == nil
        }) else {
            // Every tracked synth stream still owes a paced body; evicting any would
            // risk a connection-wide GOAWAY, so keep all.
            return
        }
        let evicted = synthRespondedOrder.remove(at: evictIdx)
        synthRespondedStreams.remove(evicted)
        pendingSynthBodies.removeValue(forKey: evicted)
    }

    /// Removes ``streamID`` from the set and FIFO; returns true if present.
    @discardableResult
    private func clearSynthResponded(_ streamID: UInt32) -> Bool {
        guard synthRespondedStreams.remove(streamID) != nil else { return false }
        if let idx = synthRespondedOrder.firstIndex(of: streamID) {
            synthRespondedOrder.remove(at: idx)
        }
        return true
    }

    // MARK: - Message build / header rebuild

    /// Builds the ``HTTPMessage`` the script chain receives: pseudo-headers stripped
    /// and projected into the scalar method/url/status fields.
    private func buildMessage(
        headers: [(name: String, value: String)],
        body: Data,
        originatingRequest: MITMRequestLog.Record?
    ) -> HTTPMessage {
        var method: String?
        var url: String?
        var status: Int?
        switch phase {
        case .httpRequest:
            method = firstHeaderValue(headers, name: ":method")
            if let path = firstHeaderValue(headers, name: ":path") {
                // Destination host, not the possibly-rewritten ``:authority``, so
                // ``ctx.url`` matches what the client requested (consistent with HTTP/1).
                url = "https://\(rewriter.host)\(path)"
            }
        case .httpResponse:
            if let raw = firstHeaderValue(headers, name: ":status"),
               let code = parseHTTPStatusCode(raw) {
                status = code
            }
            method = originatingRequest?.method
            url = originatingRequest?.url
        }
        let regularHeaders = headers.filter { !$0.name.hasPrefix(":") }
        return HTTPMessage(
            phase: phase,
            method: method,
            url: url,
            status: status,
            headers: regularHeaders,
            body: body,
            ruleSetID: rewriter.ruleSetID
        )
    }

    /// Re-assembles the wire header block from a possibly-mutated message:
    /// pseudo-headers are rebuilt from message fields (script-added ones dropped),
    /// and ``fallback`` supplies values the message lacks (e.g. ``:scheme``).
    private func rebuildHeaders(
        from message: HTTPMessage,
        fallback: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        var pseudos: [(name: String, value: String)] = []
        switch phase {
        case .httpRequest:
            let method = message.method ?? firstHeaderValue(fallback, name: ":method") ?? "GET"
            pseudos.append((name: ":method", value: method))
            let scheme = firstHeaderValue(fallback, name: ":scheme") ?? "https"
            pseudos.append((name: ":scheme", value: scheme))
            let authority: String
            let path: String
            if let url = message.url, let components = URLComponents(string: url) {
                authority = components.host.map { host in
                    if let port = components.port { return "\(host):\(port)" }
                    return host
                } ?? firstHeaderValue(fallback, name: ":authority") ?? rewriter.host
                // RFC 9113 §8.3.1: ``:path`` MUST start with ``/`` — a script-written
                // relative URL would otherwise trip PROTOCOL_ERROR on strict stacks.
                var rawPath = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
                if !rawPath.hasPrefix("/") { rawPath = "/" + rawPath }
                path = components.percentEncodedQuery.map { "\(rawPath)?\($0)" } ?? rawPath
            } else {
                authority = firstHeaderValue(fallback, name: ":authority") ?? rewriter.host
                path = firstHeaderValue(fallback, name: ":path") ?? "/"
            }
            pseudos.append((name: ":authority", value: authority))
            pseudos.append((name: ":path", value: path))
        case .httpResponse:
            let status = message.status.map(String.init)
                ?? firstHeaderValue(fallback, name: ":status")
                ?? "200"
            pseudos.append((name: ":status", value: status))
        }
        let regular = message.headers.filter { !$0.name.hasPrefix(":") }
        return pseudos + regular
    }

    /// Records the request method/URL for the outbound leg's ``ctx``. Inbound HEADERS only.
    private func logHTTP2Request(streamID: UInt32, headers: [(name: String, value: String)]) {
        guard direction == .inbound else { return }
        forwardedRequestUpstream = true
        let method = firstHeaderValue(headers, name: ":method")
        var url: String?
        if let path = firstHeaderValue(headers, name: ":path") {
            url = "https://\(rewriter.host)\(path)"
        }
        rewriter.requestLog.recordHTTP2(streamID: streamID, method: method, url: url)
    }

    // MARK: - Padding helpers

    /// Strips PADDED + PRIORITY prefixes from a HEADERS payload; nil for invalid padding.
    private func stripHeadersPadding(frame: RawFrame, hasPriority: Bool) -> Data? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 { // PADDED
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        if hasPriority {
            // 5-byte priority block: stream dep (4) + weight (1).
            guard payload.count >= 5 else { return nil }
            payload = payload.subdata(in: (payload.startIndex + 5)..<payload.endIndex)
        }
        return payload
    }

    /// Strips PADDED and extracts the Promised Stream ID from a PUSH_PROMISE payload.
    private func stripPushPromisePadding(frame: RawFrame) -> (UInt32, Data)? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 {
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        guard payload.count >= 4 else { return nil }
        let s = payload.startIndex
        let promised = (UInt32(payload[s]) << 24
                      | UInt32(payload[s + 1]) << 16
                      | UInt32(payload[s + 2]) << 8
                      | UInt32(payload[s + 3])) & 0x7FFFFFFF
        let block = payload.subdata(in: (s + 4)..<payload.endIndex)
        return (promised, block)
    }

    /// Strips PADDED from a DATA payload. Returns nil for invalid padding.
    private func stripDataPadding(frame: RawFrame) -> Data? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 {
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        return payload
    }

    /// Removes the leading pad-length byte and trailing padding; returns the inner content.
    private func stripPadding(_ payload: inout Data) -> Data? {
        guard !payload.isEmpty else { return nil }
        let padLen = Int(payload[payload.startIndex])
        guard payload.count >= 1 + padLen else { return nil }
        return payload.subdata(in: (payload.startIndex + 1)..<(payload.endIndex - padLen))
    }

    // MARK: - Frame parser / serializer

    /// Reads one complete frame, consuming the bytes; nil when more are needed.
    private func parseFrame(from buffer: inout MITMByteBuffer) -> RawFrame? {
        guard buffer.count >= 9 else { return nil }
        let length = (Int(buffer[0]) << 16) | (Int(buffer[1]) << 8) | Int(buffer[2])
        if length > Self.maxReceivedFramePayloadSize {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): frame length \(length) B exceeded receive cap \(Self.maxReceivedFramePayloadSize); breaking connection state")
            parseError = true
            buffer.removeAll(keepingCapacity: false)
            return nil
        }
        let total = 9 + length
        guard buffer.count >= total else { return nil }

        let type = buffer[3]
        let flags = buffer[4]
        let streamID = (UInt32(buffer[5]) << 24
                      | UInt32(buffer[6]) << 16
                      | UInt32(buffer[7]) << 8
                      | UInt32(buffer[8])) & 0x7FFFFFFF

        let payload = buffer.subdata(in: 9..<total)
        buffer.removeFirst(total)

        return RawFrame(typeCode: type, flags: flags, streamID: streamID, payload: payload)
    }

    /// Credits the DATA sender directly while the MITM buffers a message — the
    /// receiver sees nothing until END_STREAM, so its WINDOW_UPDATEs never come and
    /// the sender would stall at its initial window. The connection-level credit is
    /// later withheld from the relay (no double-credit); the per-stream over-credit
    /// is benign (stream half-closed by then, bounded by the 4 MiB cap).
    private func creditBufferedDataToSender(streamID: UInt32, flowControlledLength: Int) {
        guard flowControlledLength > 0 else { return }
        let streamCredit = windowUpdateFrame(streamID: streamID, increment: flowControlledLength)
        let connectionCredit = windowUpdateFrame(streamID: 0, increment: flowControlledLength)
        switch direction {
        case .inbound:
            pendingClientBytes.append(streamCredit)
            pendingClientBytes.append(connectionCredit)
        case .outbound:
            pendingServerBytes.append(streamCredit)
            pendingServerBytes.append(connectionCredit)
        }
    }

    /// ``emitDataFrames`` for DATA from the MITM's buffer; records the byte count as
    /// debt so the relay credit is withheld (the sender was already credited while buffering).
    private func emitBufferedDataFrames(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        if !payload.isEmpty {
            switch direction {
            case .outbound: flowController.addSynthDebt(payload.count)
            case .inbound:  flowController.addClientRequestDebt(payload.count)
            }
        }
        return emitDataFrames(streamID: streamID, payload: payload, endStream: endStream)
    }

    /// Emits DATA frames for same-direction paths, debiting the receiver's connection
    /// window; cross-direction pacers call ``frameData`` and debit directly instead.
    private func emitDataFrames(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        switch direction {
        case .outbound: flowController.debitConnection(payload.count)        // client-bound response DATA
        case .inbound:  flowController.debitServerConnection(payload.count)  // server-bound request DATA
        }
        return frameData(streamID: streamID, payload: payload, endStream: endStream)
    }

    /// Pure DATA framing, no flow-control accounting; an empty payload still yields
    /// one zero-length DATA so the END_STREAM signal survives.
    private func frameData(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        if payload.isEmpty {
            var output = Data(capacity: 9)
            var flags: UInt8 = 0
            if endStream { flags |= 0x1 }
            appendFrameHeader(
                typeCode: FrameTypeCode.data,
                flags: flags,
                streamID: streamID,
                payloadLength: 0,
                into: &output
            )
            return output
        }
        let frameCount = (payload.count + Self.maxFramePayloadSize - 1) / Self.maxFramePayloadSize
        var output = Data(capacity: payload.count + frameCount * 9)
        var offset = payload.startIndex
        while offset < payload.endIndex {
            let end = min(payload.endIndex, offset + Self.maxFramePayloadSize)
            let isLast = end == payload.endIndex
            var flags: UInt8 = 0
            if isLast && endStream { flags |= 0x1 }
            let length = end - offset
            appendFrameHeader(
                typeCode: FrameTypeCode.data,
                flags: flags,
                streamID: streamID,
                payloadLength: length,
                into: &output
            )
            output.append(payload[offset..<end])
            offset = end
        }
        return output
    }

    /// Emits a HEADERS/PUSH_PROMISE frame plus CONTINUATIONs as needed (RFC 9113
    /// §6.2/§6.10); END_HEADERS on the final frame, END_STREAM on the first.
    private func emitHeaderBlock(
        streamID: UInt32,
        block: Data,
        endStream: Bool,
        kind: PendingHeaders.Kind
    ) -> Data {
        let firstType: UInt8
        let firstPrefixSize: Int
        let promisedStreamID: UInt32
        switch kind {
        case .headers:
            firstType = FrameTypeCode.headers
            firstPrefixSize = 0
            promisedStreamID = 0
        case .pushPromise(let p):
            firstType = FrameTypeCode.pushPromise
            firstPrefixSize = 4
            promisedStreamID = p & 0x7FFFFFFF
        }

        let firstChunkSize = min(block.count, Self.maxFramePayloadSize - firstPrefixSize)
        let firstChunkEnd = block.startIndex + firstChunkSize
        let needsContinuation = firstChunkEnd < block.endIndex

        var firstFlags: UInt8 = 0
        if !needsContinuation { firstFlags |= 0x4 }  // END_HEADERS
        if endStream { firstFlags |= 0x1 }           // END_STREAM

        let continuationCount: Int
        if needsContinuation {
            let rest = block.count - firstChunkSize
            continuationCount = (rest + Self.maxFramePayloadSize - 1) / Self.maxFramePayloadSize
        } else {
            continuationCount = 0
        }
        let totalCapacity = (9 + firstPrefixSize) + firstChunkSize
            + continuationCount * 9 + (block.count - firstChunkSize)
        var output = Data(capacity: totalCapacity)

        appendFrameHeader(
            typeCode: firstType,
            flags: firstFlags,
            streamID: streamID,
            payloadLength: firstPrefixSize + firstChunkSize,
            into: &output
        )
        if firstPrefixSize == 4 {
            output.append(UInt8((promisedStreamID >> 24) & 0xFF))
            output.append(UInt8((promisedStreamID >> 16) & 0xFF))
            output.append(UInt8((promisedStreamID >> 8) & 0xFF))
            output.append(UInt8(promisedStreamID & 0xFF))
        }
        output.append(block[block.startIndex..<firstChunkEnd])

        var offset = firstChunkEnd
        while offset < block.endIndex {
            let end = min(block.endIndex, offset + Self.maxFramePayloadSize)
            let isLast = end == block.endIndex
            let flags: UInt8 = isLast ? 0x4 : 0
            appendFrameHeader(
                typeCode: FrameTypeCode.continuation,
                flags: flags,
                streamID: streamID,
                payloadLength: end - offset,
                into: &output
            )
            output.append(block[offset..<end])
            offset = end
        }
        return output
    }

    /// Writes a 9-byte frame header into ``out``, avoiding an intermediate ``Data`` copy.
    private func appendFrameHeader(
        typeCode: UInt8,
        flags: UInt8,
        streamID: UInt32,
        payloadLength: Int,
        into out: inout Data
    ) {
        out.append(UInt8((payloadLength >> 16) & 0xFF))
        out.append(UInt8((payloadLength >> 8) & 0xFF))
        out.append(UInt8(payloadLength & 0xFF))
        out.append(typeCode)
        out.append(flags)
        let sid = streamID & 0x7FFFFFFF
        out.append(UInt8((sid >> 24) & 0xFF))
        out.append(UInt8((sid >> 16) & 0xFF))
        out.append(UInt8((sid >> 8) & 0xFF))
        out.append(UInt8(sid & 0xFF))
    }

    /// Serializes a ``RawFrame`` for verbatim pass-through.
    private func serializeFrame(_ frame: RawFrame) -> Data {
        var out = Data(capacity: 9 + frame.payload.count)
        appendFrameHeader(
            typeCode: frame.typeCode,
            flags: frame.flags,
            streamID: frame.streamID,
            payloadLength: frame.payload.count,
            into: &out
        )
        out.append(frame.payload)
        return out
    }
}

// MARK: - MITMMessageRewriter

extension MITMHTTP2Connection: MITMMessageRewriter {

    func feed(_ data: Data, completion: @escaping (Data) -> Void) {
        process(data, completion: completion)
    }

    var resolvedUpstream: (host: String, port: UInt16?)? { rewriter.resolvedUpstream }
}
