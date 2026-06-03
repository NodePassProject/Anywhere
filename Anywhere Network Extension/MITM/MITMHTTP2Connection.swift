//
//  MITMHTTP2Connection.swift
//  Anywhere
//
//  Created by NodePassProject on 5/3/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// Per-direction HTTP/2 plaintext translator wired between
/// ``TLSRecordConnection`` legs in ``MITMSession``.
///
/// The h2 protocol is HPACK-stateful (RFC 7541 §2.2: dynamic table is
/// shared per-connection-per-direction), so byte-forwarding HEADERS
/// fragments would desync the receiver's decoder. Instead, every
/// HPACK-bearing frame is decoded with this leg's decoder, optionally
/// rewritten via ``MITMHTTP2Rewriter``, and re-encoded statelessly with
/// literal-without-indexing — keeping the peer's decoder in lockstep
/// without us having to track an outgoing dynamic table.
///
/// Unknown / control frames (SETTINGS, WINDOW_UPDATE, PING, GOAWAY,
/// RST_STREAM, PRIORITY, future frame types) are passed through
/// verbatim. PADDED / PRIORITY flags are stripped on re-emit since
/// neither MITM endpoint requires them.
final class MITMHTTP2Connection {

    /// Which side of the MITM this leg lives on. The connection preface
    /// (24 bytes "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") is only ever sent
    /// by the client, so only the inbound leg needs to consume it.
    enum Direction {
        /// Browser → real server. The plaintext stream begins with a
        /// 24-byte preface followed by frames.
        case inbound
        /// Real server → browser. Frames only.
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

    /// Cap on cumulative bytes accumulated in
    /// ``PendingHeaders.fragments`` across a HEADERS / PUSH_PROMISE
    /// frame plus its CONTINUATION chain. RFC 9113 has no spec-level
    /// limit, so a peer can chain CONTINUATIONs without bound and
    /// exhaust the Network Extension's ~50 MiB memory budget. 256 KiB
    /// fits the largest real-world request heads (JWT-bearing tokens,
    /// multi-kilobyte cookies) with margin while leaving no
    /// per-stream pressure path open. On overflow the pending state
    /// is dropped and no HEADERS reach the peer's decoder — the same
    /// failure mode as an HPACK decode error, which the connection
    /// recovers from by GOAWAY.
    private static let maxHeaderBlockFragmentBytes: Int = 256 * 1024

    /// Cap on the wire-level payload of a single received frame.
    /// ``SETTINGS_MAX_FRAME_SIZE`` (RFC 9113 §6.5.2) allows up to
    /// 2^24-1 (~16 MiB) via SETTINGS negotiation, but the MITM does
    /// not track either peer's setting and the Network Extension's
    /// ~50 MiB budget cannot sustain a single 16 MiB allocation.
    /// 1 MiB sits well above the 16 KiB default that nginx, Apache,
    /// and Chrome stick to in practice while keeping the worst-case
    /// per-frame allocation bounded. A frame exceeding this cap flips
    /// ``parseError`` and stops further processing — recovering
    /// requires finding the next valid frame boundary in a stream of
    /// arbitrary bytes, which is undecidable, so the peer sees a
    /// stalled half of the connection and eventually GOAWAYs.
    private static let maxReceivedFramePayloadSize: Int = 1 * 1024 * 1024

    /// Cap on ``pendingUpstreamSetup`` — the inbound connection-management
    /// output (preface + SETTINGS + WINDOW_UPDATE …) held while the upstream
    /// dial is deferred until the first request resolves its destination.
    /// Legitimate setup is a few hundred bytes; the cap exists so a client
    /// that floods connection-management frames without ever opening a stream
    /// can't grow this buffer against the Network Extension's ~50 MiB budget.
    /// On overflow the leg flips ``parseError`` and stops processing — the
    /// same stalled-half failure mode the other frame caps rely on the peer
    /// to GOAWAY out of. 256 KiB is far above any real h2 start.
    private static let maxPendingUpstreamSetupBytes: Int = 256 * 1024

    // MARK: - Raw frame

    /// Format-preserving frame view — keeps the wire-level type byte so
    /// frame types we don't recognise pass through unmodified.
    private struct RawFrame {
        var typeCode: UInt8
        var flags: UInt8
        var streamID: UInt32
        var payload: Data
    }

    // MARK: - State

    let direction: Direction
    private let rewriter: MITMHTTP2Rewriter
    /// Shared (cross-leg) tracker of the client's flow-control windows. The
    /// outbound leg debits the connection window for the real DATA it forwards;
    /// the inbound leg observes the client's SETTINGS/WINDOW_UPDATEs and paces
    /// synth (`Anywhere.respond`) bodies against the windows. See
    /// ``MITMHTTP2FlowController``.
    private let flowController: MITMHTTP2FlowController
    private let decoder = HPACKDecoder()

    /// Invoked when this leg observes a ``SETTINGS_HEADER_TABLE_SIZE`` in a
    /// passed-through SETTINGS frame. The value advertises the dynamic-table
    /// limit *this* endpoint imposes on its peer's encoder — which is the
    /// encoder the *opposing* leg decodes — so ``MITMSession`` wires this to
    /// the opposing leg's ``configureDecoderTableSize(_:)``. Always invoked
    /// synchronously on the shared serial lwIP queue, from the frame pump
    /// (``process(_:)`` or a parked script's resume).
    var onObservedPeerHeaderTableSize: ((Int) -> Void)?

    /// The most recent value passed to ``onObservedPeerHeaderTableSize``,
    /// retained so it can be replayed to the opposing leg when that leg is
    /// created late — the deferred dial means the inbound leg may observe the
    /// client's SETTINGS before the outbound leg exists. nil until the peer
    /// advertises a non-default header-table size.
    private(set) var lastObservedPeerHeaderTableSize: Int?

    /// Bounds this leg's HPACK decoder to the dynamic-table limit the peer
    /// advertised to the encoder we mirror (RFC 7541 §4.2). Called via the
    /// opposing leg's ``onObservedPeerHeaderTableSize`` on the shared serial
    /// queue, so it never races ``process(_:)``.
    func configureDecoderTableSize(_ size: Int) {
        decoder.setPeerHeaderTableSize(size)
    }

    /// Phase this connection rewrites. Inbound client-to-server traffic is
    /// the request half; outbound server-to-client traffic is the response
    /// half. See RFC 9113 section 8.1.
    private var phase: MITMPhase {
        direction == .inbound ? .httpRequest : .httpResponse
    }

    /// Bytes of the connection preface still to be forwarded verbatim.
    private var prefaceRemaining: Int

    /// Buffer of decrypted plaintext that hasn't yet yielded a complete
    /// frame. Cursor-style so per-frame ``removeFirst`` is O(1); on a
    /// high-throughput stream that ships hundreds of DATA frames the
    /// ``Data.removeFirst`` shift cost would otherwise quadratic with
    /// the buffer occupancy.
    private var rxBuffer = MITMByteBuffer()

    /// Set while a HEADERS / PUSH_PROMISE without END_HEADERS is being
    /// followed by CONTINUATION frames. RFC 9113 §6.10 forbids any
    /// other frame on the connection until END_HEADERS arrives.
    private var pending: PendingHeaders?

    /// Sticky flag set when ``parseFrame`` rejects a frame whose wire
    /// length exceeds ``maxReceivedFramePayloadSize``. Once set,
    /// ``process(_:)`` returns nothing and ``rxBuffer`` stays cleared
    /// — resuming parse would require finding the next valid frame
    /// boundary in a stream of arbitrary bytes, which is undecidable.
    /// The peer sees a stalled half of the connection and GOAWAYs
    /// after its timeout.
    private var parseError: Bool = false

    /// Highest client-initiated stream ID this (inbound) leg has opened
    /// via a fresh HEADERS, or zero before any. RFC 9113 §5.1.1 requires
    /// client streams to use odd, strictly-increasing IDs; a HEADERS
    /// whose ID advances past this value opens a new stream and is
    /// validated for parity, while a HEADERS at or below it is a trailer
    /// on an already-opened stream (§8.1) and skips validation. Only
    /// meaningful on the inbound leg — outbound responses/pushes arrive
    /// on already-open streams in arbitrary order, so this stays zero
    /// there and is never consulted.
    private var highestInboundStreamID: UInt32 = 0

    private struct PendingHeaders {
        let streamID: UInt32
        var fragments: Data
        /// Flags from the original HEADERS/PUSH_PROMISE frame; we keep
        /// END_STREAM and clear PADDED/PRIORITY/END_HEADERS on re-emit.
        let originalFlags: UInt8
        let kind: Kind

        enum Kind {
            case headers
            case pushPromise(promisedStreamID: UInt32)
        }
    }

    /// Per-stream pending message used when at least one script rule
    /// applies for the current direction. Missing entry means
    /// pass-through (HEADERS already emitted, DATA forwarded verbatim);
    /// present entry means we deferred HEADERS emission and are
    /// accumulating DATA so the script chain can mutate the whole
    /// message (headers + body + pseudo-headers) before re-encoding.
    ///
    /// ``data`` holds the raw (possibly compressed) body bytes seen so
    /// far. ``headers`` is the rewritten header block from
    /// ``MITMHTTP2Rewriter`` and is what the script ctx is built from.
    /// ``abandoned`` flips when an identity stream overflows the body
    /// cap mid-flight: the deferred HEADERS + buffered DATA prefix are
    /// emitted un-mutated, and subsequent DATA is forwarded verbatim.
    /// ``originatingRequest`` is the request method/url recorded by the
    /// inbound leg, populated only on outbound (response) streams.
    private struct PendingMessage {
        var data: Data
        let codec: MITMBodyCodec.Plan
        var headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        var abandoned: Bool = false
        /// Set when this stream's opening HEADERS were already emitted to
        /// the destination at HEADERS time — the early-open path for inbound
        /// bodied requests (see ``processFreshHeaderBlock``). A request
        /// stream must open on the server in stream-ID order, but deferring
        /// its HEADERS until the body is buffered and the script runs lets
        /// later streams open first (RFC 9113 §5.1.1 regression →
        /// PROTOCOL_ERROR GOAWAY). So we open the stream in order up front
        /// and buffer only the body; the flush then emits just the
        /// script-rewritten body. Script mutations to method/url/headers and
        /// ``Anywhere.respond`` can't take effect once the stream is open and
        /// are ignored on this path.
        var headersAlreadyEmitted: Bool = false
    }
    private var pendingMessages: [UInt32: PendingMessage] = [:]

    /// Per-stream state for streaming-script mode. Set at HEADERS time
    /// when a ``streamScript`` rule matches the request-target;
    /// drives per-DATA-frame script invocation. Mutually exclusive
    /// with ``pendingMessages`` — a stream is either buffered (full
    /// script) or streamed (per-frame script), never both.
    private struct StreamingState {
        let headers: [(name: String, value: String)]
        let originatingRequest: MITMRequestLog.Record?
        var frameIndex: Int = 0
        let cursor: MITMScriptTransform.FrameCursor
        /// Running `emitted - consumed` byte total for the script's
        /// effect on this stream. Tripping ``maxStreamingRewriteGrowthBytes``
        /// flips the cursor to ``bypass`` so subsequent frames pass
        /// through unchanged. See the flow-control note on the
        /// constant for why we cap.
        var cumulativeGrowth: Int = 0
        /// Single-frame lookahead so the script's ``frame.end = true``
        /// call coincides with the body of the actual last DATA
        /// frame. Without it, an h2 stream that terminates via
        /// trailer HEADERS (END_STREAM on trailer, not on the last
        /// DATA) would deliver the last DATA payload with
        /// ``frame.end = false`` and then a separate empty-body call
        /// with ``frame.end = true``, breaking scripts written
        /// against HTTP/1 semantics where the final call always
        /// carries the last chunk's bytes. The held frame is
        /// released as non-final when the next DATA arrives (we know
        /// it wasn't last), and as final on END_STREAM-bearing DATA
        /// or by ``flushStreamingScript`` on trailer arrival.
        var pendingFrame: Data?
    }
    private var streamingScripts: [UInt32: StreamingState] = [:]

    /// Bytes synthesized by request-phase scripts that called
    /// `Anywhere.respond(...)` and need to be written straight back to
    /// the client (i.e. injected onto the inner TLS record). Populated
    /// on the inbound leg only; the outbound leg never touches it.
    /// Drained by the session pump via ``drainPendingClientBytes()``
    /// immediately after each ``process(_:)`` call.
    private var pendingClientBytes = Data()

    /// Sender-bound flow-control credit (WINDOW_UPDATE frames) the MITM issues
    /// to the **upstream** while buffering a response for a rewrite rule, so the
    /// server keeps sending instead of stalling at its initial window on a body
    /// the client hasn't seen yet (see ``creditBufferedDataToSender``). The
    /// outbound (response) leg's analogue of ``pendingClientBytes``: populated
    /// on the outbound leg only and drained by the session's outbound pump via
    /// ``drainPendingServerBytes()`` immediately after each ``process(_:)``,
    /// written straight onto the outer TLS record toward the server.
    private var pendingServerBytes = Data()

    // MARK: Deferred-dial connection setup (inbound only)
    //
    // The upstream dial is deferred until the first request resolves its
    // destination, so the inbound leg must not forward the client's h2
    // connection setup (preface + SETTINGS + WINDOW_UPDATE …) until it knows a
    // request actually needs the upstream. It holds that output here and either
    // flushes it ahead of the first forwarded request, or — when the first
    // request is answered locally (a 302 / reject ``rewrite`` synth) — never
    // forwards it, so a synth-only connection never dials.

    /// Held upstream-bound output produced before the first request was
    /// forwarded (the connection preface and any connection-management frames).
    private var pendingUpstreamSetup = Data()
    /// True once the held setup has been flushed ahead of the first forwarded
    /// request; afterwards the leg forwards normally.
    private var upstreamSetupForwarded = false
    /// Set when a request that needs the upstream has been seen this connection
    /// (so the held setup is flushed and the dial is triggered).
    private var didForwardUpstreamRequest = false
    /// Set when a request has actually been committed upstream (via
    /// ``logHTTP2Request``). Distinct from ``didForwardUpstreamRequest``, which
    /// is set at HEADERS time before a buffered request might instead resolve to
    /// a synthesized reply. Drives a pre-establishment synth's GOAWAY
    /// last-stream-id so a co-batched proxy stream that the one-shot close drops
    /// is reported as un-processed and retried rather than assumed handled.
    private var forwardedRequestUpstream = false
    /// Whether a server connection preface (empty SETTINGS + a SETTINGS ACK for
    /// the client's SETTINGS) has been emitted to the client. Only used for a
    /// pre-establishment synth reply, where no upstream relays one.
    private var serverPrefaceSentToClient = false
    /// Set after a pre-establishment synth has emitted its GOAWAY: the
    /// connection is one-shot, so further client frames are swallowed and
    /// nothing is dialed.
    private var inboundClosed = false

    /// Stream IDs whose request was synthesized via
    /// `Anywhere.respond(...)` and never reached the upstream. The
    /// outer leg has no record of these stream IDs, so the inner
    /// client's follow-up frames on them (trailers, DATA, WINDOW_UPDATE,
    /// or typically a RST_STREAM after consuming the response) MUST be
    /// swallowed here rather than forwarded. The upstream sees the
    /// stream as idle, so forwarding stream frames can trigger a
    /// connection-level PROTOCOL_ERROR and take down every other
    /// in-flight stream on the same h2 connection. Inbound leg only.
    ///
    /// Eviction: RST_STREAM clears the entry, the swallow path clears
    /// it when it sees an END_STREAM on a DATA / HEADERS frame, and a
    /// FIFO cap (see ``synthRespondedMaxStreams``) evicts the oldest
    /// entry when neither happens. Clients are not required to RST
    /// after consuming a synthesized response — most just stop sending
    /// — so without the cap the set would grow unbounded for the
    /// connection's lifetime on every script that fires
    /// ``Anywhere.respond``.
    private var synthRespondedStreams: Set<UInt32> = []
    /// Insertion order mirror of ``synthRespondedStreams`` so the cap's
    /// eviction picks the oldest streamID without losing the O(1)
    /// membership test on the hot frame-dispatch path.
    private var synthRespondedOrder: [UInt32] = []

    /// Upper bound on ``synthRespondedStreams`` per connection. Sized
    /// well above the spec-default ``SETTINGS_MAX_CONCURRENT_STREAMS``
    /// (100) so a fully-saturated h2 connection doesn't trip eviction
    /// against streams that may still be live. Worst-case memory cost
    /// is ~1 KiB of UInt32s + array overhead.
    private static let synthRespondedMaxStreams = 256

    /// A request-phase `Anywhere.respond` body that did not fit the client's
    /// flow-control windows in one shot and is being paced out as the client
    /// grants more window via WINDOW_UPDATE. Inbound leg only; keyed by stream
    /// ID. Created by ``queueSynthesizedResponse`` when a remainder is left
    /// after the first emission and drained by ``flushPendingSynth``. The
    /// entry's presence means "this stream still owes the client DATA".
    private struct PendingSynthBody {
        /// Body bytes not yet emitted to the client.
        var remaining: Data
        /// This stream's remaining per-stream window (RFC 9113 §6.9.1). Signed:
        /// a client SETTINGS_INITIAL_WINDOW_SIZE decrease (§6.9.2) can push it
        /// negative, which simply withholds emission until a WINDOW_UPDATE
        /// brings it positive.
        var streamWindow: Int
        /// True for a pre-establishment one-shot synth (no upstream dialed):
        /// the terminating GOAWAY + ``inboundClosed`` are deferred until the
        /// body fully flushes (see ``oneShotSynthPacing``).
        let isPreEstablishment: Bool
        /// last-stream-id for the deferred pre-establishment GOAWAY, fixed at
        /// queue time — it reports 0 when a proxy stream was co-batched ahead of
        /// this synth (so the client retries that stream), which is knowable
        /// only at the moment the synth is queued.
        let goAwayLastStreamID: UInt32
    }

    /// Per-stream paced synth bodies (see ``PendingSynthBody``). A streamID is
    /// present only while it still owes the client bytes; the entry is removed
    /// the moment its body fully flushes (END_STREAM emitted).
    private var pendingSynthBodies: [UInt32: PendingSynthBody] = [:]

    /// True while a pre-establishment one-shot synth is mid-pacing — its body
    /// is buffered in ``pendingSynthBodies`` and the terminating GOAWAY is
    /// deferred. While set, connection-level WINDOW_UPDATEs are consumed for
    /// pacing and dropped rather than emitted: this connection will never dial
    /// an upstream to forward them to, and letting them accumulate in
    /// ``pendingUpstreamSetup`` (via ``finishPumpPass``) would trip
    /// ``maxPendingUpstreamSetupBytes``. Cleared when the body completes.
    private var oneShotSynthPacing = false

    /// Upper bound on the number of streams this connection tracks with
    /// per-stream MITM state (``pendingMessages`` + ``streamingScripts``). Each
    /// ``pendingMessages`` entry can buffer up to
    /// ``MITMBodyCodec/maxBufferedBodyBytes`` (4 MiB), so without a cap a peer
    /// opening many script/buffered streams it never closes (no END_STREAM /
    /// RST) would grow these maps until the NE is OOM-killed. Past the cap a
    /// fresh stream is passed through un-MITM'd — it still works, it just isn't
    /// rewritten/scripted. Sized well above the spec-default
    /// SETTINGS_MAX_CONCURRENT_STREAMS (100).
    private static let maxTrackedStreams = 256

    /// The session's serial lwIP queue. Script execution hops off it onto
    /// ``MITMScriptTransform/scriptQueue`` and the engine result is delivered
    /// back here, so the parked frame pump resumes on the same queue all
    /// connection state is touched on.
    private let lwipQueue: DispatchQueue

    /// The in-flight ``process`` completion, retained only while a script hop
    /// is outstanding. nil otherwise. The pump's one-read-in-flight discipline
    /// guarantees at most one is ever outstanding.
    private var parkedCompletion: ((Data) -> Void)?

    /// Peer-bound bytes produced earlier in the current ``process`` pass, held
    /// while a script hop is outstanding. The resume prepends them so the
    /// single completion carries every byte of the pass in wire order.
    private var pendingPreParkOutput = Data()

    /// Set when the owning session tears down. A resume that fires afterwards
    /// bails without touching connection state or a dead leg.
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

    /// Marks the connection torn down (session cancelled). Any in-flight
    /// script resume that fires afterwards bails immediately. Idempotent.
    func markTorn() {
        torn = true
        parkedCompletion = nil
        pendingPreParkOutput = Data()
        // Drop any buffered (un-paced) synth bodies proactively — they can hold
        // up to 4 MiB each against the extension's memory budget until ARC
        // releases the connection.
        pendingSynthBodies.removeAll()
        oneShotSynthPacing = false
    }

    // MARK: - Public API

    /// Feeds one chunk of decrypted plaintext from the source TLS record
    /// connection through the h2 translator. The peer-bound plaintext for
    /// the destination TLS leg is delivered via ``completion``, invoked
    /// **exactly once**: synchronously, inline when no script runs (the
    /// common case), or later on the lwIP queue when a script rule parks the
    /// connection while its JavaScript runs off-queue. Streaming-safe:
    /// callers may invoke this with arbitrarily small or large chunks.
    ///
    /// Client-bound synth bytes (from a request-phase `Anywhere.respond`) are
    /// not part of this completion; the pump drains them via
    /// ``drainPendingClientBytes()`` right after the completion fires.
    func process(_ data: Data, completion: @escaping (Data) -> Void) {
        assert(parkedCompletion == nil, "process re-entered while a script hop is outstanding")
        // Once an oversized frame has broken the parse state, stay
        // broken — dropping further bytes on the floor is strictly
        // safer than misparsing them as a new frame's preamble.
        if parseError { completion(Data()); return }
        var output = Data()
        var input = data

        // Forward the connection preface verbatim. If the chunk
        // happens to span the preface/frame boundary the second half
        // falls through into rxBuffer below.
        if prefaceRemaining > 0, !input.isEmpty {
            let take = min(prefaceRemaining, input.count)
            output.append(input.prefix(take))
            input.removeFirst(take)
            prefaceRemaining -= take
        }

        if !input.isEmpty {
            rxBuffer.append(input)
        }

        parkedCompletion = completion
        // NB: sequence these as two statements. As a single
        // `finishPumpPass(output, parkedAgain: pump(into: &output))` call,
        // Swift evaluates the `output` argument (a `Data` value copy) BEFORE
        // running `pump`, so finishPumpPass would receive the pre-pump empty
        // buffer and silently drop every byte the pump produced.
        let parkedAgain = pump(into: &output)
        finishPumpPass(output, parkedAgain: parkedAgain)
    }

    /// Parses and handles frames until ``rxBuffer`` drains or a script hop
    /// parks the connection. Returns true when parked (a resume continues the
    /// pump); false when the buffer drained with no hop outstanding.
    private func pump(into output: inout Data) -> Bool {
        while let frame = parseFrame(from: &rxBuffer) {
            if handleFrame(frame, into: &output) {
                return true
            }
        }
        return false
    }

    /// Tail of every pump pass — the synchronous one in ``process`` and each
    /// resumed one. If a hop parked the connection, holds the bytes produced
    /// so far (the matching resume prepends them); otherwise fires the stashed
    /// completion exactly once with the accumulated output.
    private func finishPumpPass(_ output: Data, parkedAgain: Bool) {
        if parkedAgain {
            pendingPreParkOutput = output
            return
        }
        var finalOutput = output
        // Deferred-dial gating for the inbound leg: hold the client's
        // connection setup until a request actually needs the upstream, so a
        // synth-only first request never dials (and a host-changing rewrite
        // dials the rewritten host, not the original).
        if direction == .inbound, !upstreamSetupForwarded {
            if inboundClosed {
                // One-shot synth is terminating; nothing goes upstream.
                finalOutput = Data()
            } else if didForwardUpstreamRequest {
                // First upstream request: send the held setup (preface +
                // SETTINGS + any pre-request connection-management frames)
                // ahead of it so the upstream sees a well-formed h2 start.
                finalOutput = pendingUpstreamSetup + output
                pendingUpstreamSetup = Data()
                upstreamSetupForwarded = true
            } else if pendingUpstreamSetup.count + output.count > Self.maxPendingUpstreamSetupBytes {
                // A client flooding connection-management frames without ever
                // opening a stream would otherwise grow this buffer without
                // bound. Give up safely — like the other frame caps, stop
                // processing and let the stalled half time out / GOAWAY.
                logger.warning("[MITM] HTTP/2 \(rewriter.host): pre-dial setup buffer would exceed \(Self.maxPendingUpstreamSetupBytes) B without a request; marking parseError")
                parseError = true
                pendingUpstreamSetup = Data()
                finalOutput = Data()
            } else {
                // No upstream request yet — hold connection-management output.
                pendingUpstreamSetup.append(output)
                finalOutput = Data()
            }
        }
        let completion = parkedCompletion
        parkedCompletion = nil
        completion?(finalOutput)
    }

    /// Drains and returns any client-bound bytes synthesized by
    /// request-phase scripts that called `Anywhere.respond(...)` since
    /// the last call. The session pump writes these directly to the
    /// inner TLS record, bypassing the outbound translator entirely
    /// (the HPACK encoder is stateless, so a fresh header block decodes
    /// cleanly on the client side without disturbing either dynamic
    /// table). The outbound leg never populates this — call sites
    /// guard with ``direction == .inbound``.
    func drainPendingClientBytes() -> Data {
        let bytes = pendingClientBytes
        pendingClientBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    /// Drains and returns any upstream-bound flow-control credit the outbound
    /// leg issued for buffered response DATA (see ``creditBufferedDataToSender``
    /// / ``pendingServerBytes``). The session's outbound pump writes these onto
    /// the outer TLS record toward the server right after each ``process(_:)``.
    /// The inbound leg never populates this — call sites guard with
    /// ``direction == .outbound``.
    func drainPendingServerBytes() -> Data {
        let bytes = pendingServerBytes
        pendingServerBytes.removeAll(keepingCapacity: false)
        return bytes
    }

    // MARK: - Frame dispatch

    private func handleFrame(_ frame: RawFrame, into output: inout Data) -> Bool {
        // One-shot synth (302 / reject before any upstream): we've sent the
        // response + GOAWAY on the inner leg, so swallow every further client
        // frame — nothing more goes upstream and the client will close.
        if inboundClosed { return false }
        // A pre-establishment one-shot synth whose body is still being paced to
        // the client (the terminating GOAWAY is deferred until it finishes,
        // ``queueSynthesizedResponse``). Only the frames that drive or cancel
        // the in-flight synth stream are processed; any new request stream is
        // swallowed because this connection is closing and will never dial an
        // upstream — the client retries those on a fresh connection after the
        // GOAWAY. WINDOW_UPDATE drives pacing; RST_STREAM lets the client abort.
        if oneShotSynthPacing {
            switch frame.typeCode {
            case FrameTypeCode.windowUpdate:
                // Consume for pacing side-effects only; this connection never
                // dials, so nothing is ever forwarded upstream.
                _ = handleWindowUpdate(frame)
            case FrameTypeCode.rstStream:
                _ = handleRSTStream(frame) // evict bookkeeping; nothing to forward
            default:
                break
            }
            return false
        }
        // RFC 9113 §6.10: between a HEADERS/PUSH_PROMISE without
        // END_HEADERS and its terminating CONTINUATION, the peer is
        // forbidden from sending any other frame type — including
        // unrelated DATA, RST_STREAM, even SETTINGS. A peer that does
        // so is performing a protocol violation. Forwarding the
        // out-of-band frame would leak the pending header block into
        // the destination's HPACK decoder out of order (because the
        // header block's CONTINUATION never arrives), poisoning the
        // dynamic table. Stop processing — the peer will GOAWAY.
        if let p = pending,
           frame.typeCode != FrameTypeCode.continuation {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): frame type \(frame.typeCode) on stream \(frame.streamID) interleaved with pending HEADERS on stream \(p.streamID); marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            pending = nil
            return false
        }
        // Synth-responded short-circuit: frames on streams whose
        // request was answered by ``Anywhere.respond`` never reach the
        // upstream. RST_STREAM is allowed through so the eviction
        // logic in ``handleRSTStream`` can run, and WINDOW_UPDATE so
        // ``handleWindowUpdate`` can drive synth pacing; every other
        // frame type is swallowed.
        if frame.streamID != 0,
           synthRespondedStreams.contains(frame.streamID),
           frame.typeCode != FrameTypeCode.rstStream,
           frame.typeCode != FrameTypeCode.windowUpdate {
            // Evict the streamID when the swallowed frame carries
            // END_STREAM (bit 0x1 of DATA or HEADERS flags). The
            // client is done with the stream on its side, so pinning
            // the ID in the set for the connection's lifetime is
            // wasted memory and pressures the FIFO cap.
            let endStream = frame.flags & 0x1 != 0
            let endStreamBearing = frame.typeCode == FrameTypeCode.data
                || frame.typeCode == FrameTypeCode.headers
            if endStream, endStreamBearing {
                clearSynthResponded(frame.streamID)
            }
            return false
        }
        // Only the HEADERS/CONTINUATION (→ finalizeHeaderBlock) and DATA paths
        // can run a script and therefore park; every other frame type is
        // handled synchronously and appended.
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

    /// Observes ``SETTINGS_HEADER_TABLE_SIZE`` (identifier 0x1, RFC 9113
    /// §6.5.2) then forwards the SETTINGS frame verbatim. The MITM does not
    /// alter either peer's settings — it only needs the value to bound the
    /// opposing leg's HPACK decoder (RFC 7541 §4.2). SETTINGS is
    /// connection-level (stream 0); an ACK (flag 0x1) carries no payload.
    /// A length that isn't a multiple of the 6-byte entry size is a frame
    /// error the receiver will catch; we parse whole entries and ignore any
    /// trailing remainder rather than re-deriving that error here.
    private func handleSettings(_ frame: RawFrame) -> Data {
        if frame.streamID == 0, frame.flags & 0x1 == 0 {
            let payload = frame.payload
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
                    // The client's per-stream receive-window initializer governs
                    // synth DATA the inbound leg sends back; observe it so synth
                    // pacing starts from the right window (and adjusts open
                    // synth streams when it changes mid-connection).
                    applyClientInitialWindowSize(Int(value))
                default:
                    break
                }
                i += 6
            }
        }
        return serializeFrame(frame)
    }

    /// Records a new client ``SETTINGS_INITIAL_WINDOW_SIZE`` on the shared flow
    /// controller and applies the RFC 9113 §6.9.2 retroactive adjustment — the
    /// delta `(new - old)` is added to every open synth stream's window — then
    /// flushes any stream the change just unblocked. The controller always
    /// records the new value (future synth streams start from it) even when no
    /// stream is currently open.
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

    /// Cleans up per-stream bookkeeping for streams above the GOAWAY's
    /// last-stream-id and forwards the frame verbatim. RFC 9113 §6.8:
    /// "any streams with identifiers higher than the included
    /// last-stream-id … will not be processed". Without this, pending
    /// HEADERS / DATA accumulators for those streams would never
    /// receive END_STREAM and leak for the connection's lifetime.
    private func handleGoAway(_ frame: RawFrame) -> Data {
        // GOAWAY MUST be sent on stream 0 (§6.8). A non-zero streamID
        // here is a protocol violation; pass through so the receiver
        // can detect.
        guard frame.streamID == 0, frame.payload.count >= 8 else {
            return serializeFrame(frame)
        }
        // First 4 bytes: R | Last-Stream-ID (31). Parse the 31-bit ID
        // with the reserved high bit masked off.
        let payload = frame.payload
        let start = payload.startIndex
        let lastStreamID =
            (UInt32(payload[start])     & 0x7F) << 24
            | UInt32(payload[start + 1]) << 16
            | UInt32(payload[start + 2]) << 8
            | UInt32(payload[start + 3])
        // Evict per-stream pending state for any stream above the
        // last-stream-id — the GOAWAY-sender guarantees those streams
        // will not be processed, so their END_STREAM trigger never
        // arrives and the entries would otherwise pin memory.
        let abandonedPending = pendingMessages.keys.filter { $0 > lastStreamID }
        for id in abandonedPending {
            pendingMessages.removeValue(forKey: id)
        }
        let abandonedStreaming = streamingScripts.keys.filter { $0 > lastStreamID }
        for id in abandonedStreaming {
            streamingScripts.removeValue(forKey: id)
        }
        let abandonedSynth = synthRespondedOrder.filter { $0 > lastStreamID }
        for id in abandonedSynth {
            _ = clearSynthResponded(id)
        }
        // Drop any paced synth body for an abandoned stream — the peer
        // guarantees it won't process the stream, so we'll never see the
        // WINDOW_UPDATEs that would drain it.
        for id in pendingSynthBodies.keys where id > lastStreamID {
            pendingSynthBodies.removeValue(forKey: id)
        }
        return serializeFrame(frame)
    }

    /// Drops per-stream bookkeeping for an aborted stream and forwards
    /// the RST_STREAM frame verbatim. Without this, a long-lived
    /// connection that frequently RSTs (e.g. background sync apps that
    /// cancel and retry) would accumulate dead entries in
    /// ``pendingMessages`` and ``streamingScripts`` until the
    /// connection closes. The shared ``MITMRequestLog`` entry is also
    /// dropped so the cross-leg method/url map doesn't pin a record
    /// for a stream that will never produce a response. Each leg
    /// clears independently — the other leg's matching clear is a
    /// no-op.
    private func handleRSTStream(_ frame: RawFrame) -> Data {
        // RFC 9113 §6.4: RST_STREAM MUST be associated with a stream
        // (streamID != 0) and its payload MUST be exactly 4 bytes
        // (the error code). Forwarding a malformed RST_STREAM gives
        // the peer a basis to GOAWAY the connection on an otherwise
        // recoverable error; drop here.
        guard frame.streamID != 0, frame.payload.count == 4 else {
            return Data()
        }
        // Clear any in-flight HEADERS accumulator for the aborted
        // stream so a follow-on CONTINUATION can't surface fragments
        // belonging to the dead stream into the next HEADERS that
        // reuses the slot.
        if pending?.streamID == frame.streamID {
            pending = nil
        }
        pendingMessages.removeValue(forKey: frame.streamID)
        streamingScripts.removeValue(forKey: frame.streamID)
        // Abort pacing of a synth body the client cancelled mid-stream.
        pendingSynthBodies.removeValue(forKey: frame.streamID)
        _ = rewriter.requestLog.popHTTP2(streamID: frame.streamID)
        // Swallow RST_STREAMs for streams the upstream never saw — the
        // request was synthesized on the inner leg via Anywhere.respond
        // and no HEADERS / DATA ever went on the wire upstream.
        // Forwarding the RST in that case is a PROTOCOL_ERROR per RFC
        // 9113 §5.4.1 (RST_STREAM on an idle stream → connection-level
        // error), which the upstream answers with GOAWAY and kills
        // every other stream on the connection.
        if clearSynthResponded(frame.streamID) {
            return Data()
        }
        return serializeFrame(frame)
    }

    // MARK: - HEADERS

    private func handleHeaders(_ frame: RawFrame, into output: inout Data) -> Bool {
        // RFC 9113 §6.2: HEADERS MUST be associated with a stream — a
        // streamID of zero is a connection-level protocol violation.
        // Routing the frame through the script chain at the zero slot
        // would collide with future stream-zero frames; mark
        // parseError so the peer GOAWAYs.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): HEADERS on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        // RFC 9113 §5.1.1: client-initiated stream IDs MUST be odd and
        // strictly monotonically increasing. Only the inbound leg
        // carries that invariant — outbound responses/pushes arrive on
        // already-open streams in arbitrary order. A HEADERS frame opens
        // a NEW stream only when its ID advances past the highest opened
        // on this leg; a HEADERS at or below that high-water mark is a
        // trailer on a previously-opened stream (§8.1), which is legal
        // and MUST skip new-stream validation. (Trailers on streams we
        // still track never reach here — they take the
        // follow-on-HEADERS flush path in finalizeHeaderBlock. A
        // backwards or reused ID on an untracked stream collides with no
        // state, since pass-through streams hold none, so we let it
        // through for the peer/upstream to reject.)
        if direction == .inbound,
           frame.streamID > highestInboundStreamID,
           isFreshHeadersFrame(streamID: frame.streamID) {
            guard frame.streamID % 2 == 1 else {
                logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): client-initiated HEADERS has server (even) parity; marking parseError")
                parseError = true
                rxBuffer = MITMByteBuffer()
                return false
            }
            highestInboundStreamID = frame.streamID
        }

        guard let body = stripHeadersPadding(frame: frame, hasPriority: frame.flags & 0x20 != 0) else {
            // Malformed padding — drop the frame to avoid feeding
            // garbage into the HPACK decoder. The peer will GOAWAY.
            return false
        }

        // Single-frame HEADERS cap. ``handleContinuation`` enforces
        // the same bound on chained CONTINUATIONs; without this check
        // a peer can put the entire ``maxHeaderBlockFragmentBytes``
        // budget into one frame and bypass the chain-side guard.
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

    /// True when this leg holds no per-stream state for ``streamID``
    /// (not buffering a message, not streaming a script, not synth-
    /// responded). The caller combines this with a high-water-mark
    /// comparison to distinguish a brand-new inbound stream — which is
    /// validated for parity — from a trailer on an already-opened
    /// stream we happen not to track (e.g. a pass-through request),
    /// which must be left alone. Trailers on streams we DO track never
    /// reach the validation path; they take the follow-on-HEADERS flush
    /// path in ``finalizeHeaderBlock``.
    private func isFreshHeadersFrame(streamID: UInt32) -> Bool {
        return pendingMessages[streamID] == nil
            && streamingScripts[streamID] == nil
            && !synthRespondedStreams.contains(streamID)
    }

    private func handleContinuation(_ frame: RawFrame, into output: inout Data) -> Bool {
        // RFC 9113 §6.10: CONTINUATION MUST be associated with a
        // stream. A streamID-zero CONTINUATION is a protocol error.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): CONTINUATION on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        guard var p = pending, p.streamID == frame.streamID else {
            // Stray CONTINUATION (no matching pending HEADERS, or
            // matching a different stream). Forwarding it would
            // poison the destination peer's HPACK decoder: the wire
            // bytes are encoded under the SOURCE leg's dynamic table
            // (we re-encode every header block we forward with
            // literal-without-indexing, so the source-side table is
            // ahead of the destination-side table for any indexed
            // references). A stray CONTINUATION's indexed slots
            // wouldn't exist in the destination decoder's table → it
            // raises COMPRESSION_ERROR and GOAWAYs the connection.
            // Drop and stop processing to keep both decoders in
            // sync.
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): stray CONTINUATION; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }

        // Project the post-append size and reject *before* allocating.
        // Otherwise a single 16 MiB CONTINUATION blows through the cap
        // on the append itself; the existing variable ``p`` shares
        // ``pending``'s storage by COW until the first mutation.
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
        // RFC 9113 §6.6: PUSH_PROMISE is server-to-client only. A
        // PUSH_PROMISE arriving on the inbound leg (client→server) is
        // a client-side protocol violation; re-encoding and
        // forwarding it would have the upstream raise PROTOCOL_ERROR
        // and GOAWAY the connection, killing every other in-flight
        // stream. Drop and mark parseError instead.
        guard direction == .outbound else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): PUSH_PROMISE on inbound leg (client → server); marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        // §6.6: PUSH_PROMISE MUST be associated with an existing,
        // peer-initiated stream — streamID 0 is a protocol error.
        guard frame.streamID != 0 else {
            logger.warning("[MITM] HTTP/2 \(rewriter.host): PUSH_PROMISE on stream 0; marking parseError")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }
        // PUSH_PROMISE payload (§6.6):
        //   [Pad Length? (8)]
        //   R | Promised Stream ID (31)
        //   Header Block Fragment
        //   [Padding]
        guard let (promisedStreamID, body) = stripPushPromisePadding(frame: frame) else {
            return false
        }

        if body.count > Self.maxHeaderBlockFragmentBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(frame.streamID): PUSH_PROMISE payload \(body.count) B exceeded cap \(Self.maxHeaderBlockFragmentBytes); dropping")
            return false
        }

        if frame.flags & 0x4 != 0 { // END_HEADERS
            // PUSH_PROMISE never enters a script branch in
            // ``finalizeHeaderBlock`` (those are gated on `.headers`), so
            // this never parks.
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
        guard let decoded = decoder.decodeHeaders(from: fragments) else {
            // HPACK decode failure desyncs this leg's dynamic table
            // irrecoverably — partial decode may have advanced the
            // dynamic-table state past the failing instruction, so
            // every subsequent HEADERS on this leg will decode
            // against a poisoned table and emit silently-corrupted
            // header values to the destination peer.
            //
            // Returning ``Data()`` and letting the connection keep
            // processing would hit exactly the failure mode parseError
            // exists to prevent. Trip parseError so ``process(_:)``
            // short-circuits and the peer GOAWAYs after its idle
            // timeout.
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): HPACK decode failed; marking parseError to prevent table desync")
            parseError = true
            rxBuffer = MITMByteBuffer()
            return false
        }

        // Classify the HEADERS frame against the raw decoded block,
        // BEFORE user header rules run (those can't fake a fresh
        // response shape onto an actual trailer). A HEADERS without
        // the primary pseudo-header — `:method` for requests,
        // `:status` for responses — is a trailer (RFC 9113 §8.1) and
        // gets emitted verbatim through the pass-through path without
        // popping the request log or entering script mode. An
        // outbound HEADERS with `:status` in the 1xx range (except
        // 101) is an interim informational response (100 Continue,
        // 103 Early Hints, …): more HEADERS follow on the same stream
        // so the request-log record must stay live for the final
        // response.
        let isTrailer: Bool
        let isInterimResponse: Bool
        if case .headers = kind {
            switch direction {
            case .inbound:
                isTrailer = firstHeaderValue(decoded, name: ":method") == nil
                isInterimResponse = false
            case .outbound:
                if let raw = firstHeaderValue(decoded, name: ":status"),
                   let status = Int(raw.trimmingCharacters(in: .whitespaces)) {
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

        // Flush deferred script state when a trailer or follow-on
        // HEADERS arrives on a stream that previously entered scripted
        // mode. For buffered mode we run scripts on the accumulated
        // body and emit deferred HEADERS + DATA (without END_STREAM —
        // the trailer carries it). For streaming mode we give the
        // script one final invocation with an empty body and
        // ``frame.end = true`` so it can flush any per-stream state;
        // non-empty output goes on the wire as a final DATA frame
        // before the trailer HEADERS.
        //
        // The flush runs a script and so may park; when it does, the
        // fresh-block processing (``processFreshHeaderBlock``) runs in the
        // resume via the continuation, preserving wire order.
        if case .headers = kind {
            if pendingMessages[streamID] != nil {
                return runScriptsAndFlush(streamID: streamID, endStream: false, into: &output) { [weak self] out in
                    guard let self else { return false }
                    // A request-phase ``Anywhere.respond`` on the flushed
                    // message short-circuits the stream; the trailer /
                    // follow-on HEADERS must not be processed.
                    if self.synthRespondedStreams.contains(streamID) { return false }
                    return self.processFreshHeaderBlock(
                        streamID: streamID,
                        decoded: decoded,
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
            originalFlags: originalFlags,
            kind: kind,
            isTrailer: isTrailer,
            isInterimResponse: isInterimResponse,
            into: &output
        )
    }

    /// Processes a freshly-arrived header block once any deferred script
    /// state for the stream has been flushed. Pops/peeks the originating
    /// request, runs header rules, and either enters streaming-script mode,
    /// enters buffered-script mode (parking when END_STREAM-on-HEADERS runs a
    /// script immediately), or emits the block on the pass-through path.
    /// Returns true when a script hop parked the connection.
    private func processFreshHeaderBlock(
        streamID: UInt32,
        decoded: [(name: String, value: String)],
        originalFlags: UInt8,
        kind: PendingHeaders.Kind,
        isTrailer: Bool,
        isInterimResponse: Bool,
        into output: inout Data
    ) -> Bool {
        // Pop or peek the originating request once per outbound
        // response head, before the header transform (so a response
        // rule's URL gate can be tested against the originating
        // request's path) and before any script-mode dispatch. Doing
        // it here (rather than inside each script branch) ensures the
        // streamID→record map drains for pass-through responses too —
        // without this it leaks until connection close. Interim 1xx
        // responses peek so the record stays live for the matching
        // final response that follows on the same stream.
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
        // Response headers carry no ``:path``, so response-phase rules
        // gate on the originating request's whole URL. Request-phase rules
        // read the live ``:path`` inside the rewriter instead.
        let responseURL = (direction == .outbound)
            ? originatingRequest?.url
            : nil

        // Native 302 / reject ``MITMOperation/rewrite``: synthesize the
        // response on the inner leg and short-circuit before the stream is
        // opened upstream. Gates on the original request URL; the transparent
        // sub-mode (which rewrites ``:path`` in ``transformRequestHeaders``) is
        // mutually exclusive with synth — first matching rewrite rule wins.
        // Reuses the same machinery as a request-phase ``Anywhere.respond``.
        if case .headers = kind, direction == .inbound, !isTrailer {
            let requestGateURL = MITMHTTP2Rewriter.requestPath(in: decoded)
                .map { "https://\(rewriter.host)\($0)" }
            if let synth = rewriter.requestSynthResponse(requestURL: requestGateURL) {
                queueSynthesizedResponse(streamID: streamID, response: synth)
                return false
            }
            // Not a native synth: the connection may need the upstream, so let
            // the held setup flush and the dial proceed. (A buffered-script
            // request that later calls Anywhere.respond is handled as a synth,
            // which suppresses the flush via ``inboundClosed``.)
            didForwardUpstreamRequest = true
        }

        var rewritten: [(name: String, value: String)]
        switch kind {
        case .headers:
            // RFC 9113 section 8.1: client-to-server is a request and
            // server-to-client is a response. Pick the matching hook.
            rewritten = (direction == .inbound)
                ? rewriter.transformRequestHeaders(decoded, streamID: streamID)
                : rewriter.transformResponseHeaders(decoded, streamID: streamID, requestURL: responseURL)
        case .pushPromise:
            // PUSH_PROMISE carries the synthesized request that goes
            // with the soon-to-be-pushed response. The rewriter has no
            // dedicated hook; just pass the headers through.
            rewritten = decoded
        }

        let endStreamOnHeaders = originalFlags & 0x1 != 0
        // Whole URL the script preflights gate on: built from the live
        // (post-rewrite) ``:path`` on inbound requests; the originating
        // request's URL on outbound responses.
        let gateURL = (direction == .inbound)
            ? MITMHTTP2Rewriter.requestPath(in: rewritten).map { "https://\(rewriter.host)\($0)" }
            : responseURL

        // Streaming-script mode wins over buffered-script mode when
        // both apply. The trade-off: stream rules see DATA frames
        // one-at-a-time without HTTP-level decompression, so the body
        // never stalls — but they can't touch HEADERS, which we emit
        // immediately below. Trailers and interim responses skip
        // scripting entirely: trailers have no real "head" to mutate,
        // and interim responses precede the actual final headers.
        //
        // ``endStreamOnHeaders`` skips this branch even when a stream
        // script matches: there will be no DATA frame for the script
        // to fire on, so the right behaviour is to fall through to the
        // buffered-script path (which handles an empty body) or to
        // pass-through. Without this gate, a request/response with no
        // body would silently bypass any buffered script that also
        // matched.
        // Bound the number of streams tracked with per-stream MITM state (see
        // ``maxTrackedStreams``). The flag is computed only for a fresh HEADERS
        // (a stream not already tracked); past the cap both the streaming-script
        // and buffered blocks below are skipped, so the stream falls through to
        // verbatim pass-through instead of growing the maps without bound.
        let trackedStreamCapReached: Bool = {
            guard case .headers = kind, !isTrailer, !isInterimResponse,
                  streamingScripts[streamID] == nil, pendingMessages[streamID] == nil
            else { return false }
            return pendingMessages.count + streamingScripts.count >= Self.maxTrackedStreams
        }()
        if trackedStreamCapReached {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): tracked-stream cap \(Self.maxTrackedStreams) reached; passing through without MITM")
        }

        if case .headers = kind, !isTrailer, !isInterimResponse,
           !endStreamOnHeaders, !trackedStreamCapReached,
           rewriter.hasStreamScriptRule(phase: phase, requestURL: gateURL) {
            if rewriter.hasBufferedBodyRule(phase: phase, requestURL: gateURL) {
                logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): Stream Script rule wins over buffered body rule")
            }

            // Inbound HEADERS still need to land in the request log so
            // the response-side scripts can read method/url.
            if direction == .inbound {
                logHTTP2Request(streamID: streamID, headers: rewritten)
            }

            // Track per-stream state so DATA frames know to run the
            // script chain. No body buffering, no decompression. The
            // originating request was popped once at the top of this
            // function for outbound streams.
            streamingScripts[streamID] = StreamingState(
                headers: rewritten,
                originatingRequest: originatingRequest,
                cursor: MITMScriptTransform.FrameCursor()
            )

            let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten)
            output.append(emitHeaderBlock(
                streamID: streamID,
                block: reencoded,
                endStream: false,
                kind: kind
            ))
            return false
        }

        // Buffered-script mode: defer HEADERS emission. The script may
        // mutate any field on the message, including pseudo-headers,
        // so the wire HEADERS frame waits until scripts have run. For
        // bodied streams the deferral also drives body buffering; for
        // END_STREAM-on-HEADERS streams the script runs inline against
        // an empty body. Skipped for trailers and interim responses
        // for the same reasons as streaming-script above.
        if case .headers = kind, !isTrailer, !isInterimResponse, !trackedStreamCapReached,
           rewriter.hasBufferedBodyRule(phase: phase, requestURL: gateURL),
           shouldBufferStream(headers: rewritten, endStream: endStreamOnHeaders) {
            if !endStreamOnHeaders {
                warnIfBufferedScriptDeStreams(streamID: streamID, headers: rewritten)
            }
            let codec = MITMBodyCodec.plan(for: firstHeaderValue(rewritten, name: "content-encoding"))
            // Drop content-length: the post-script body size is
            // unknown at HEADERS-defer time and HTTP/2 doesn't require
            // it. Keep content-encoding intact for now —
            // ``runScriptsAndFlush`` strips it on a successful
            // decompression and, on decode failure, emits the deferred
            // HEADERS + raw bytes verbatim so the receiver can still
            // try to decode the original payload.
            rewritten.removeAll { $0.name.equalsIgnoringASCIICase("content-length") }

            // Inbound bodied request: open the stream now, in stream-ID
            // order, instead of deferring HEADERS until the body is buffered.
            // See ``PendingMessage/headersAlreadyEmitted`` for why the order
            // matters and the trade-off it costs. Only the body is buffered
            // for the script; content-encoding is dropped from the opening
            // block because that body is re-emitted as identity. A no-body
            // request falls through to the deferred path below, which can
            // still rewrite the head.
            if direction == .inbound, !endStreamOnHeaders {
                var openingHeaders = rewritten
                if codec.requiresDecompression {
                    openingHeaders.removeAll { $0.name.equalsIgnoringASCIICase("content-encoding") }
                }
                logHTTP2Request(streamID: streamID, headers: openingHeaders)
                output.append(emitHeaderBlock(
                    streamID: streamID,
                    block: HPACKEncoder.encodeHeaderBlock(openingHeaders),
                    endStream: false,
                    kind: kind
                ))
                pendingMessages[streamID] = PendingMessage(
                    data: Data(),
                    codec: codec,
                    headers: openingHeaders,
                    originatingRequest: originatingRequest,
                    headersAlreadyEmitted: true
                )
                return false
            }

            // ``originatingRequest`` was popped once at the top of
            // this function for outbound streams; pass-through and
            // PUSH_PROMISE cases see nil and ignore it.
            pendingMessages[streamID] = PendingMessage(
                data: Data(),
                codec: codec,
                headers: rewritten,
                originatingRequest: originatingRequest
            )

            if endStreamOnHeaders {
                // No DATA will follow — run scripts immediately on an
                // empty body. ``runScriptsAndFlush`` emits the deferred
                // HEADERS plus any body the script populated, and parks
                // while the script runs off-queue.
                return runScriptsAndFlush(streamID: streamID, endStream: true, into: &output) { _ in false }
            }
            return false
        }

        // Pass-through path: no script applies, this is a trailer or
        // interim response, or this is a PUSH_PROMISE. Inbound request
        // HEADERS get logged so the response side can populate
        // ctx.method/ctx.url even when no script touched the request —
        // but trailer HEADERS, which carry no pseudo-headers, must be
        // skipped here. Without this gate a request trailer would
        // overwrite the streamID→record map with nils and the
        // matching response-side script would lose its originating
        // request context.
        if case .headers = kind, direction == .inbound, !isTrailer {
            logHTTP2Request(streamID: streamID, headers: rewritten)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(rewritten)

        // Encoded block emission drops PADDED and PRIORITY but preserves
        // END_STREAM. END_HEADERS lands on the final emitted frame, which
        // ``emitHeaderBlock`` picks based on whether splitting is required.
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
        // RFC 9113 §6.1: DATA MUST be associated with a stream. A
        // DATA frame on stream 0 is a connection-level protocol
        // violation and would otherwise route into the script chain
        // keyed at slot 0, colliding with any other stream-0
        // bookkeeping.
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

        // Streaming-script path: run the script chain on this single
        // DATA frame and emit immediately. No buffering, no
        // decompression — gRPC and other framed-stream payloads stay
        // streaming. May park while a frame's script runs off-queue.
        if streamingScripts[streamID] != nil {
            return handleStreamingData(
                streamID: streamID,
                body: body,
                endStream: endStream,
                into: &output
            )
        }

        // Pass-through path: no script for this stream. Re-emit the
        // DATA frame with the original body and END_STREAM flag, with
        // PADDED cleared.
        guard var pending = pendingMessages[streamID] else {
            output.append(emitDataFrames(streamID: streamID, payload: body, endStream: endStream))
            return false
        }

        // Abandoned path: a previous DATA frame on this stream blew
        // through the buffer cap. HEADERS + buffered prefix were
        // already emitted by the abandon transition; forward this frame
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

        // Buffering path: accumulate until END_STREAM.
        pending.data.append(body)
        // Nothing reaches the receiver until END_STREAM, so the receiver won't
        // emit the WINDOW_UPDATEs a relay would forward back to the sender —
        // credit the sender ourselves so it keeps sending instead of stalling
        // at its initial window (which would wedge this stream and, via the
        // shared connection window, others). ``emitBufferedDataFrames`` records
        // the matching debt when the buffered body is emitted. The full on-wire
        // payload length (incl. any padding) is what the sender debited.
        creditBufferedDataToSender(streamID: streamID, flowControlledLength: frame.payload.count)

        // Mid-stream cap check. Only reachable for identity bodies
        // (compressed streams are pre-gated when content-length is
        // missing or already over the cap). We've withheld the HEADERS
        // frame so far, so the abandon transition emits the deferred
        // HEADERS (without script mutations) plus the buffered prefix
        // as DATA, then continues to forward subsequent DATA verbatim.
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

    /// Closes out a streaming-script stream when END_STREAM lands on
    /// a trailer HEADERS frame rather than on a DATA frame. Emits
    /// the held-back final DATA frame (if any) with
    /// ``frame.end = true`` so the script's last invocation carries
    /// the actual last frame's bytes — matching HTTP/1's chunked
    /// streaming contract. When no frame was held (no DATA on the
    /// stream at all), the script still gets one empty-body
    /// ``isLast=true`` call as a flush opportunity. The wire
    /// END_STREAM bit lives on the upcoming trailer HEADERS, so the
    /// DATA frame we emit here carries ``endStream=false``.
    ///
    /// Parks while the final frame's script runs off-queue; ``continuation``
    /// runs once the flush is emitted (it processes the trailing HEADERS).
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

    /// Streaming-script path. ``Anywhere.done`` / ``Anywhere.exit``
    /// flip the cursor's ``bypass`` flag so subsequent frames on the
    /// stream pass through unchanged. The streaming entry is cleared
    /// on END_STREAM regardless of bypass state so a follow-up
    /// message on the same stream ID (rare under HTTP/2 stream-ID
    /// rules but possible with PUSH_PROMISE) gets a fresh cursor.
    ///
    /// Lookahead: each DATA frame is held for one event so the script
    /// call with ``frame.end = true`` always carries the last frame's
    /// actual bytes, rather than firing on an empty body after the last
    /// DATA already went out. This matches HTTP/1 chunked semantics.
    /// When the next DATA arrives, the held one is released as non-final;
    /// when this frame's END_STREAM bit is set, the held one is released
    /// as non-final and the current one is processed as final.
    private func handleStreamingData(
        streamID: UInt32,
        body: Data,
        endStream: Bool,
        into output: inout Data
    ) -> Bool {
        // Release the previously held frame, if any. Its mere
        // presence here means the stream did not end on it (a
        // subsequent DATA frame has arrived), so the script's
        // ``frame.end`` is false. Bypass is honoured inside
        // ``processStreamingFrame``: held frames are still emitted,
        // just verbatim. The held frame and the current frame each run
        // their own (possibly off-queue) script, so they chain via
        // continuations to keep wire order across any park.
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

    /// Handles the current DATA frame of a streaming-script stream once any
    /// held lookahead frame has been released. On END_STREAM the frame is
    /// final (``isLast=true``, wire END_STREAM) and the stream entry drops;
    /// otherwise it is stashed as the lookahead for the next event.
    private func handleStreamingCurrentFrame(
        streamID: UInt32,
        body: Data,
        endStream: Bool,
        into output: inout Data
    ) -> Bool {
        if endStream {
            // END_STREAM on this DATA frame: this IS the last frame
            // on the stream, no trailers can follow. ``isLast=true`` so
            // the script sees the actual last-frame bytes (HTTP/1 chunked
            // parity); drop the stream entry once emitted.
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
        // Defer: we don't yet know whether this is the last DATA (a
        // trailer HEADERS could follow). Stash it; the next event — another
        // DATA frame or trailer — releases it with the right ``frame.end``.
        if var streaming = streamingScripts[streamID] {
            streaming.pendingFrame = body
            streamingScripts[streamID] = streaming
        }
        return false
    }

    /// Runs one buffered frame through the streaming-script chain and
    /// serializes the (possibly mutated) bytes as DATA frames.
    /// ``isLast`` is what the script sees on ``ctx.frame.end``;
    /// ``wireEndStream`` is the END_STREAM bit on the emitted DATA
    /// frame — the two diverge for the held frame released on
    /// trailer flush (``isLast=true`` so the script knows it's the
    /// last call, ``wireEndStream=false`` because the trailer
    /// HEADERS will carry END_STREAM on the wire).
    ///
    /// Reads the stream's state from ``streamingScripts`` (the source of
    /// truth across an async hop). When the stream is bypassed, emits
    /// synchronously and runs ``continuation`` inline. Otherwise dispatches
    /// the frame's script off-queue, parks, and runs ``continuation`` from
    /// the resume once ``emitStreamFrameResult`` has emitted the frame.
    private func processStreamingFrame(
        streamID: UInt32,
        body: Data,
        isLast: Bool,
        wireEndStream: Bool,
        into output: inout Data,
        then continuation: @escaping (inout Data) -> Bool
    ) -> Bool {
        guard var streaming = streamingScripts[streamID] else {
            // Stream entry gone (e.g. already removed); nothing to script.
            return continuation(&output)
        }
        if streaming.cursor.bypass {
            streaming.frameIndex += 1
            streamingScripts[streamID] = streaming
            // Skip emitting an empty mid-stream DATA frame so a swallowed
            // frame stays swallowed; END_STREAM still needs a frame to carry
            // the flag, so empty + endStream collapses to one zero-length
            // DATA frame.
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
            // Drain frames that followed the parked one (see the matching
            // note in runScriptsAndFlush). Skipped when the continuation
            // re-parked.
            if !parkedAgain {
                parkedAgain = self.pump(into: &resumed)
            }
            self.finishPumpPass(resumed, parkedAgain: parkedAgain)
        }
        return true
    }

    /// Applies a streaming frame's script result: enforces the cumulative
    /// wire-growth cap (flipping the stream to ``bypass`` on overflow),
    /// advances the frame index, and emits the resulting DATA frame(s).
    /// State is threaded through ``streamingScripts``; the ``cursor`` was
    /// already mutated in place by ``applyFrame`` on the script queue.
    private func emitStreamFrameResult(
        result: MITMScriptTransform.StreamFrameResult,
        streamID: UInt32,
        body: Data,
        wireEndStream: Bool,
        into output: inout Data
    ) {
        guard var streaming = streamingScripts[streamID] else {
            // Stream removed during the hop (shouldn't happen on the serial
            // lwIP queue, since the connection is parked); emit best-effort.
            if !(result.body.isEmpty && !wireEndStream) {
                output.append(emitDataFrames(streamID: streamID, payload: result.body, endStream: wireEndStream))
            }
            return
        }
        // Track cumulative wire-byte growth across the stream's frames. The
        // receiver's flow-control window was budgeted for the original
        // sender's bytes; any growth we add eats unaccounted into that
        // window. Once the projected total would exceed the cap, this frame
        // and every subsequent one fall back to the original payload. Clamp
        // at zero rather than banking headroom from an earlier shrink — see
        // the constant's note for the FLOW_CONTROL_ERROR rationale.
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

    /// URL for the streaming script's ctx. On response phase the
    /// originating request's URL (from the request log) wins; on
    /// request phase we synthesize the URL using the connection's
    /// destination host so the script sees what the client requested,
    /// not the rewritten ``:authority`` an authority-rewrite rule may
    /// have substituted. Matches HTTP/1's behaviour (which uses the
    /// connection's ``host`` rather than the rewritten ``Host`` header)
    /// so a script written against ``ctx.url`` behaves the same on
    /// both protocols.
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
              let code = Int(raw.trimmingCharacters(in: .whitespaces))
        else { return nil }
        return code
    }

    /// Emits the deferred HEADERS and the buffered body prefix without
    /// running scripts, then flips the pending message to ``abandoned``
    /// so subsequent DATA frames forward verbatim. Used when the body
    /// overflows the buffer cap mid-stream.
    private func abandonPending(streamID: UInt32, pending: inout PendingMessage) -> Data {
        let prefix = pending.data
        pending.data = Data()
        pending.abandoned = true
        // Early-open stream: HEADERS already opened it in order, so emit only
        // the buffered body prefix; subsequent DATA forwards verbatim.
        if pending.headersAlreadyEmitted {
            pendingMessages[streamID] = pending
            return emitBufferedDataFrames(streamID: streamID, payload: prefix, endStream: false)
        }
        // Inbound HEADERS need to be logged for the response side to
        // populate ctx.method/url even though scripts won't run.
        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: pending.headers)
        }
        let reencoded = HPACKEncoder.encodeHeaderBlock(pending.headers)
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

    /// Emits the deferred HEADERS + buffered raw body without running
    /// scripts. Used by ``runScriptsAndFlush`` when decompression fails
    /// — the original ``content-encoding`` is still present on
    /// ``pending.headers`` so the receiver can decode the original
    /// payload itself. Inbound request HEADERS still need to land in
    /// the request log so the response-side ctx is populated.
    private func emitPassthroughDeferred(
        streamID: UInt32,
        pending: PendingMessage,
        endStream: Bool
    ) -> Data {
        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: pending.headers)
        }
        let reencoded = HPACKEncoder.encodeHeaderBlock(pending.headers)
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

    /// Runs the script chain on the buffered message and emits the
    /// final HEADERS (with script mutations) plus the rewritten body
    /// as DATA frame(s). Removes the entry from ``pendingMessages`` so
    /// the stream is settled.
    ///
    /// Dispatches the script off-queue and parks, returning true;
    /// ``continuation`` then runs from the resume once the flush is emitted.
    /// The no-pending and already-abandoned cases have nothing to script,
    /// and a decompression failure emits the deferred bytes verbatim — all
    /// three run ``continuation`` inline and return its value instead of
    /// parking.
    private func runScriptsAndFlush(
        streamID: UInt32,
        endStream: Bool,
        into output: inout Data,
        then continuation: @escaping (inout Data) -> Bool
    ) -> Bool {
        guard let pending = pendingMessages.removeValue(forKey: streamID) else {
            return continuation(&output)
        }
        if pending.abandoned {
            return continuation(&output)
        }
        let plaintext: Data
        if pending.codec.requiresDecompression {
            // Decompression failure: skip scripts and emit the
            // deferred HEADERS + raw bytes verbatim so the receiver
            // can still decode the original payload. ``pending.headers``
            // still carries `content-encoding` — it's stripped only
            // after a successful decompression — so it correctly labels
            // these still-encoded bytes. HTTP/1 takes the same approach
            // in ``applyScriptsAndEmit``.
            guard let decoded = MITMBodyCodec.decompress(pending.data, plan: pending.codec, host: rewriter.host) else {
                if pending.headersAlreadyEmitted {
                    // Early-open stream: its HEADERS (announced identity) are
                    // already on the wire, so we can't fall back to the
                    // encoded-passthrough HEADERS. Emit the buffered body to
                    // close the stream — a rare decode failure degrades to one
                    // unparseable request, not a connection-wide reset.
                    output.append(emitBufferedDataFrames(streamID: streamID, payload: pending.data, endStream: endStream))
                } else {
                    output.append(emitPassthroughDeferred(streamID: streamID, pending: pending, endStream: endStream))
                }
                return continuation(&output)
            }
            plaintext = decoded
        } else {
            plaintext = pending.data
        }
        // On a successful decompression we're emitting identity, so
        // hide ``content-encoding`` from the script and from the
        // re-encoded header block. When the body wasn't compressed
        // there's nothing to hide.
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
            guard let self else { return }
            guard !self.torn else { return }
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
            // Drain any frames that followed the parked one in rxBuffer.
            // Without this the pump stops at the parked frame, so frames the
            // peer already sent after it (WINDOW_UPDATE, SETTINGS ACK, the
            // next stream's HEADERS/DATA) are stranded until the next
            // receive — which may never come if the peer is now waiting on
            // us, deadlocking the connection. Mirrors HTTP/1's resume, which
            // continues its drive loop. Skipped when the continuation itself
            // parked (its own resume will drain).
            if !parkedAgain {
                parkedAgain = self.pump(into: &resumed)
            }
            self.finishPumpPass(resumed, parkedAgain: parkedAgain)
        }
        return true
    }

    /// Emits a buffered-message script flush's result: a synthesized response
    /// short-circuit (queued to the client), the flow-control passthrough
    /// fallback on excessive growth, or the rewritten HEADERS + body.
    /// Extracted so it can run from the off-queue resume.
    private func emitFlushResult(
        outcome: MITMScriptTransform.Outcome,
        streamID: UInt32,
        endStream: Bool,
        pending: PendingMessage,
        plaintext: Data,
        into output: inout Data
    ) {
        // Early-open path: this stream's HEADERS already went on the wire in
        // stream-ID order, so only the body can still change. Emit just the
        // script-rewritten body; the script's method/url/header mutations and
        // ``Anywhere.respond`` can't apply once the stream is open.
        if pending.headersAlreadyEmitted {
            let body: Data
            switch outcome {
            case .message(let updated):
                // Same flow-control guard as the deferred path below: if the
                // script grew the body past the cap, forward the original to
                // avoid a FLOW_CONTROL_ERROR.
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
            output.append(emitBufferedDataFrames(streamID: streamID, payload: body, endStream: endStream))
            return
        }

        let result: MITMScriptEngine.Message
        switch outcome {
        case .message(let updated):
            result = updated
        case .synthesizedResponse(let response):
            // Request-phase short-circuit. Suppress upstream emission
            // for this stream entirely and queue the synthesized
            // HEADERS + DATA on the inbound leg's client-bound buffer.
            // The outer leg never saw a HEADERS for this stream so
            // there's nothing to RST.
            queueSynthesizedResponse(streamID: streamID, response: response)
            return
        }

        // Flow-control safeguard. The wire-level body bytes the
        // original sender put on this stream were already budgeted by
        // its flow-control accounting; we can pass those through
        // safely. Any script-introduced *growth* is unaccounted: the
        // receiver decrements its window by what we send, not by what
        // the original sender intended, so a script that grows the
        // body past the default initial window risks a
        // FLOW_CONTROL_ERROR + connection-wide GOAWAY.
        //
        // The comparison baseline is the *decompressed* plaintext, not
        // the compressed wire bytes — decompression itself is not
        // "growth" from the script's perspective, and using
        // ``pending.data.count`` (compressed) as the baseline would
        // make every script with a non-trivial compression ratio
        // (typical gzip JSON is ~5×) trip the cap as a no-op and fall
        // back to passthrough. ``plaintext.count`` is what the script
        // saw on input; ``result.body.count`` is what it produced.
        // Their delta is the user-introduced wire-level growth, which
        // is the value the receiver's flow-control window cares about.
        let originalIdentityBytes = plaintext.count
        let rewrittenWireBytes = result.body.count
        if rewrittenWireBytes > originalIdentityBytes,
           rewrittenWireBytes - originalIdentityBytes > Self.maxBufferedRewriteGrowthBytes {
            logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): script grew body by \(rewrittenWireBytes - originalIdentityBytes) B (cap \(Self.maxBufferedRewriteGrowthBytes) B); emitting original payload")
            output.append(emitPassthroughDeferred(streamID: streamID, pending: pending, endStream: endStream))
            return
        }

        // Re-build the HTTP/2 header block: pseudo-headers from the
        // (possibly script-mutated) method/url/status, regular headers
        // from result.headers (with any stale pseudo-headers stripped
        // in case the script touched them directly).
        let finalHeaders = rebuildHeaders(from: result, fallback: pending.headers)

        if direction == .inbound {
            logHTTP2Request(streamID: streamID, headers: finalHeaders)
        }

        let reencoded = HPACKEncoder.encodeHeaderBlock(finalHeaders)
        // RFC 9110 §15.2: a response to HEAD never carries a body even
        // when the same resource fetched with GET would. A script that
        // wrote into ctx.body would otherwise have us emit DATA frames
        // the client didn't expect — strict h2 clients ignore them, but
        // emitting them is still spec-violating and can confuse stream
        // accounting on the receiver. Drop the bytes here, matching
        // HTTP/1's emitScriptedHead carve-out.
        let isHeadResponse = phase == .httpResponse
        && pending.originatingRequest?.method?.uppercased() == "HEAD"
        let body = isHeadResponse ? Data() : result.body
        // END_STREAM lands on either HEADERS (no body case) or the last
        // DATA frame (body case). HTTP/2 requires DATA to follow HEADERS
        // when there's a body; an empty body is fine on HEADERS alone.
        let headersHaveEndStream = endStream && body.isEmpty
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

    /// Decides whether a stream's HEADERS (and DATA, if any) should be
    /// deferred so the buffered transform can mutate the full message. The
    /// codec and content-length gates make the decision once at HEADERS
    /// time rather than rediscovered per-frame. Rule matching happens
    /// earlier, on the rewriter side via
    /// ``MITMHTTP2Rewriter/hasBufferedBodyRule(phase:requestURL:)``.
    ///
    /// An END_STREAM-on-HEADERS message has no DATA to buffer, so the
    /// content-length / codec gates don't apply — defer unconditionally
    /// so a script can still mutate head fields.
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
        // No content-length. We can recover from a mid-stream cap
        // overflow only when the body is identity (just flush + pass
        // through). Compressed bodies whose size we cannot bound up
        // front are not safe to buffer optimistically — skip them.
        return !codec.requiresDecompression
    }

    /// Returns the first header value matching ``name`` (case-insensitive),
    /// or nil when absent.
    private func firstHeaderValue(_ headers: [(name: String, value: String)], name: String) -> String? {
        for (n, v) in headers where n.equalsIgnoringASCIICase(name) {
            return v
        }
        return nil
    }

    /// HTTP/2 analogue of the HTTP/1 advisory: warns when a buffered
    /// ``.script`` rule will hold a streaming response (SSE and friends;
    /// see ``MITMScriptTransform/isStreamingMediaType(_:)``) until
    /// END_STREAM before the client sees any of it. The rule still runs,
    /// as requested; ``streamScript`` is the per-frame alternative.
    /// Response phase only.
    private func warnIfBufferedScriptDeStreams(streamID: UInt32, headers: [(name: String, value: String)]) {
        let contentType = firstHeaderValue(headers, name: "content-type")
        guard phase == .httpResponse,
              MITMScriptTransform.isStreamingMediaType(contentType) else { return }
        logger.warning("[MITM] HTTP/2 \(rewriter.host) stream \(streamID): buffered Script on a streaming response. Switch to Stream Script to rewrite frames as they arrive.")
    }

    /// Per-stream cap on how many bytes a buffered ``.script`` rewrite
    /// may add to the original body before the rewrite is abandoned in
    /// favour of emitting the unmodified payload. Original bytes are
    /// already budgeted by the original sender's flow-control accounting
    /// — those can't trip ``FLOW_CONTROL_ERROR``. Extra bytes can, since
    /// the receiver's window decrements by what *we* send, not by what
    /// the original sender intended. With no per-stream window tracking for
    /// forwarded streams, the safest cap is the spec-default initial window
    /// (RFC 9113 §6.9.2 = 65,535 B), so a single rewrite emission stays
    /// within one worst-case window's worth of unaccounted growth. A
    /// script that grows further falls back to the original payload via
    /// ``emitPassthroughDeferred`` rather than risking a GOAWAY that
    /// would tear down every other stream on the connection.
    private static let maxBufferedRewriteGrowthBytes: Int = 65_535

    /// Cumulative per-stream cap on the wire-byte growth a
    /// ``.streamScript`` may introduce before subsequent frames are
    /// bypassed. Same rationale as ``maxBufferedRewriteGrowthBytes``:
    /// the receiver's flow-control window only budgeted the original
    /// sender's wire bytes, so introduced growth eats into the window
    /// without any matching WINDOW_UPDATE we can observe. The cap is
    /// cumulative across frames on the same stream — a script that
    /// grows each of a hundred frames by 1 KB exhausts the budget just
    /// as surely as one that grows a single frame by 100 KB. When the
    /// cap trips, we flip ``FrameCursor.bypass`` so the rest of the
    /// stream forwards verbatim instead of risking a connection-level
    /// GOAWAY.
    private static let maxStreamingRewriteGrowthBytes: Int = 65_535

    /// Serializes a request-phase `Anywhere.respond(...)` payload as an
    /// HTTP/2 HEADERS frame followed by DATA frames **paced to the client's
    /// flow-control windows**, appending the bytes to ``pendingClientBytes``
    /// for the session pump to inject onto the inner TLS record. Inbound leg
    /// only — the outbound leg never reaches this path.
    ///
    /// HEADERS go out immediately (headers are not flow-controlled, RFC 9113
    /// §6.9.1). The body is emitted as far as the connection and per-stream
    /// windows currently allow; any remainder is buffered in
    /// ``pendingSynthBodies`` and drained by ``flushPendingSynth`` as the
    /// client grants window via WINDOW_UPDATE. END_STREAM lands only on the
    /// final byte, so a body spanning several WINDOW_UPDATE rounds still
    /// terminates the stream exactly once.
    ///
    /// ``:status`` is taken from ``response.status``; pseudo-headers the
    /// script populated under ``headers`` are dropped so the HPACK encoder
    /// never emits duplicates. ``content-length``/``transfer-encoding`` are
    /// dropped since END_STREAM is the source of truth in HTTP/2.
    ///
    /// Header names are checked against RFC 9110 §5.6.2 (token chars only) and
    /// values against RFC 9113 §8.2.1 (no CR/LF/NUL); violators are dropped.
    private func queueSynthesizedResponse(
        streamID: UInt32,
        response: MITMScriptEngine.SynthesizedResponse
    ) {
        var headers: [(name: String, value: String)] = [
            (name: ":status", value: String(response.status))
        ]
        for entry in response.headers {
            let n = entry.name.lowercased()
            if n.hasPrefix(":") { continue }
            if n == "content-length" || n == "transfer-encoding" { continue }
            guard Self.isValidHeaderName(n),
                  Self.isValidHTTP2HeaderValue(entry.value)
            else {
                logger.warning("[MITM][JS] HTTP/2 \(rewriter.host): Anywhere.respond dropping invalid header: \(entry.name)")
                continue
            }
            // HTTP/2 forbids uppercase header names (RFC 9113 §8.2.1);
            // normalize defensively so a careless script can't blow up
            // the client's decoder.
            headers.append((name: n, value: entry.value))
        }
        let block = HPACKEncoder.encodeHeaderBlock(headers)

        // Cap the buffered body to the per-message body budget
        // (``MITMBodyCodec/maxBufferedBodyBytes``, 4 MiB), matching the HTTP/1
        // synth path. This bounds only the extension's memory; the wire stays
        // within the client's flow-control window via the pacing below, not
        // this cap.
        var body = response.body
        if body.count > MITMBodyCodec.maxBufferedBodyBytes {
            logger.warning("[MITM][JS] HTTP/2 \(rewriter.host): Anywhere.respond body \(body.count) B exceeds memory cap \(MITMBodyCodec.maxBufferedBodyBytes) B; truncating")
            let end = body.startIndex + MITMBodyCodec.maxBufferedBodyBytes
            body = body.subdata(in: body.startIndex..<end)
        }

        // HEADERS first (END_STREAM only when there is no body to follow).
        let out = emitHeaderBlock(
            streamID: streamID,
            block: block,
            endStream: body.isEmpty,
            kind: .headers
        )
        let isPreEstablishment = !upstreamSetupForwarded
        if isPreEstablishment, !serverPrefaceSentToClient {
            // Pre-establishment synth (302 / reject / respond before any
            // upstream leg): the client never received a server preface and
            // none will be relayed (this connection won't dial), so open with a
            // self-contained server SETTINGS + a SETTINGS ACK for the client's.
            pendingClientBytes.append(serverConnectionPreface())
            serverPrefaceSentToClient = true
        }
        pendingClientBytes.append(out)

        // Record before any DATA so the client's follow-up frames (trailers,
        // DATA, WINDOW_UPDATE, or the RST some clients send after consuming an
        // unsolicited response) aren't forwarded upstream on an idle stream.
        // See ``handleFrame`` / ``handleRSTStream``.
        markSynthResponded(streamID)

        guard !body.isEmpty else {
            // Done at HEADERS. A pre-establishment one-shot still needs its
            // terminating GOAWAY now — there is no body to pace. last-stream-id
            // reports 0 when a proxy stream was co-batched ahead of this synth
            // (it gets dropped by the close, so the client must retry it);
            // otherwise this synth stream is the highest processed.
            if isPreEstablishment {
                pendingClientBytes.append(goAwayFrame(lastStreamID: forwardedRequestUpstream ? 0 : streamID))
                inboundClosed = true
            }
            return
        }

        // Buffer the whole body, then emit the first window's worth now. Any
        // remainder — and, for the one-shot path, the deferred GOAWAY — is left
        // to ``flushPendingSynth``, driven by the client's WINDOW_UPDATEs.
        pendingSynthBodies[streamID] = PendingSynthBody(
            remaining: body,
            streamWindow: flowController.clientInitialStreamWindow,
            isPreEstablishment: isPreEstablishment,
            goAwayLastStreamID: forwardedRequestUpstream ? 0 : streamID
        )
        flushPendingSynth(streamID: streamID)
    }

    /// Emits as much of stream `streamID`'s buffered synth body as the
    /// connection and per-stream windows currently allow, appending DATA to
    /// ``pendingClientBytes`` and doing the window accounting. When the body
    /// finishes, END_STREAM lands on the last frame, the buffer is dropped, and
    /// a pre-establishment one-shot sends its deferred GOAWAY. A flush that can
    /// emit nothing (windows exhausted) leaves the entry for the next
    /// WINDOW_UPDATE to retry.
    private func flushPendingSynth(streamID: UInt32) {
        guard var entry = pendingSynthBodies[streamID] else { return }
        let available = max(0, min(flowController.connectionWindow, entry.streamWindow, entry.remaining.count))
        if available > 0 {
            let chunkEnd = entry.remaining.startIndex + available
            let chunk = entry.remaining.subdata(in: entry.remaining.startIndex..<chunkEnd)
            let didFinish = available == entry.remaining.count
            // ``emitDataFrames`` only auto-debits the connection window on the
            // outbound leg; this is the inbound (synth) leg, so account here.
            pendingClientBytes.append(emitDataFrames(streamID: streamID, payload: chunk, endStream: didFinish))
            flowController.debitConnection(available)
            entry.streamWindow -= available
            // Post-establishment synth shares the connection window with real
            // upstream traffic, so its bytes are withheld from the connection
            // WINDOW_UPDATEs we forward upstream (see ``handleWindowUpdate``). A
            // one-shot pre-establishment synth never dials, so there is no
            // upstream credit to compensate and nothing to record.
            if !entry.isPreEstablishment {
                flowController.addSynthDebt(available)
            }
            entry.remaining.removeFirst(available)
            if didFinish {
                completeSynthStream(streamID: streamID, entry: entry)
                return
            }
        }
        // Still owes the client bytes (window exhausted, or none was
        // available). Keep the entry for the next WINDOW_UPDATE. A
        // pre-establishment one-shot is now mid-pacing: flag it so connection
        // WINDOW_UPDATEs are consumed-and-dropped rather than buffered toward
        // an upstream that will never dial (see ``oneShotSynthPacing``).
        pendingSynthBodies[streamID] = entry
        if entry.isPreEstablishment {
            oneShotSynthPacing = true
        }
    }

    /// Flushes every buffered synth body in ``synthRespondedOrder`` (FIFO)
    /// order until the shared connection window is exhausted — used when a
    /// connection-level WINDOW_UPDATE grows the window shared across streams.
    /// FIFO keeps a stream that missed one grant at the front of the next, so
    /// no synth stream starves across rounds.
    private func flushAllPendingSynth() {
        guard !pendingSynthBodies.isEmpty else { return }
        for streamID in synthRespondedOrder {
            if flowController.connectionWindow <= 0 { break }
            if pendingSynthBodies[streamID] != nil {
                flushPendingSynth(streamID: streamID)
            }
        }
    }

    /// Finalizes a synth stream whose body has fully reached the client: drops
    /// the buffer and, for a pre-establishment one-shot, emits the deferred
    /// GOAWAY and closes the connection (the client reconnects for anything
    /// else). See ``queueSynthesizedResponse`` for why the GOAWAY is deferred.
    private func completeSynthStream(streamID: UInt32, entry: PendingSynthBody) {
        pendingSynthBodies.removeValue(forKey: streamID)
        if entry.isPreEstablishment {
            pendingClientBytes.append(goAwayFrame(lastStreamID: entry.goAwayLastStreamID))
            inboundClosed = true
            oneShotSynthPacing = false
        }
    }

    /// Parses a WINDOW_UPDATE (RFC 9113 §6.9), updates the client flow-control
    /// window we track for it, drives any synth pacing the new window unblocks
    /// (appending DATA to ``pendingClientBytes``), and returns the bytes to emit
    /// toward upstream — empty when the frame is consumed/swallowed.
    ///
    /// The windows tracked here govern data flowing *to the client*, which only
    /// the client's own WINDOW_UPDATEs replenish — and those arrive on the
    /// inbound leg. The outbound leg's WINDOW_UPDATEs are the server's, governing
    /// the upstream's receive window, so they are forwarded to the client
    /// verbatim and never touch the synth accounting.
    ///
    /// Connection-level (stream 0) WINDOW_UPDATEs credit the shared window and
    /// are forwarded upstream minus the synth connection-debt (so the upstream
    /// is credited only for bytes it actually sent); a frame whose increment is
    /// fully withheld is dropped, since a zero-increment WINDOW_UPDATE is a
    /// PROTOCOL_ERROR (§6.9.1). A pre-establishment one-shot has no upstream, so
    /// its connection WINDOW_UPDATEs are swallowed. Per-stream WINDOW_UPDATEs on
    /// a synth (MITM-owned) stream drive that stream's pacing and are swallowed
    /// (the upstream never saw the stream); on a real stream they forward
    /// verbatim (upstream's flow control is its own concern).
    private func handleWindowUpdate(_ frame: RawFrame) -> Data {
        if direction == .outbound {
            // The outbound leg relays the server's WINDOW_UPDATEs to the client.
            // A connection-level (stream 0) one credits the client's connection
            // window; if the inbound leg credited the client directly for request
            // DATA it buffered (``creditBufferedDataToSender``), withhold that
            // here so the client isn't credited twice — the request-direction
            // mirror of the inbound leg's synth-debt withholding below. A
            // per-stream, malformed, or zero-increment frame forwards verbatim
            // for the real peer to handle.
            guard frame.streamID == 0,
                  let increment = Self.windowUpdateIncrement(frame.payload),
                  increment > 0 else {
                return serializeFrame(frame)
            }
            let forwarded = flowController.withholdClientRequestDebt(from: increment)
            if forwarded == increment { return serializeFrame(frame) }
            if forwarded == 0 { return Data() }  // fully withheld → drop (zero WU is a PROTOCOL_ERROR)
            return windowUpdateFrame(streamID: 0, increment: forwarded)
        }
        let increment = Self.windowUpdateIncrement(frame.payload)

        if frame.streamID == 0 {
            // Capture before flushing: completing a one-shot synth in
            // ``flushAllPendingSynth`` clears ``oneShotSynthPacing``, but this
            // very frame still belongs to the never-dialing connection and must
            // not be forwarded.
            let wasOneShotPacing = oneShotSynthPacing
            if let increment, increment > 0 {
                flowController.creditConnection(increment)
            }
            flushAllPendingSynth()
            // A pre-establishment one-shot never dials — there is nothing to
            // forward the frame to, and buffering it would pressure
            // ``maxPendingUpstreamSetupBytes``. Swallow it.
            if wasOneShotPacing { return Data() }
            // Malformed (nil) or zero increment: don't compensate; forward
            // verbatim and let the real peer enforce the §6.9.1 error.
            guard let increment, increment > 0 else { return serializeFrame(frame) }
            let forwarded = flowController.withholdSynthDebt(from: increment)
            if forwarded == increment { return serializeFrame(frame) }
            if forwarded == 0 { return Data() }
            return windowUpdateFrame(streamID: 0, increment: forwarded)
        }

        // Per-stream. A synth stream is MITM-owned; its WINDOW_UPDATE paces the
        // buffered body and is never forwarded (matching the synth-swallow).
        let isSynthStream = pendingSynthBodies[frame.streamID] != nil
            || synthRespondedStreams.contains(frame.streamID)
        if isSynthStream {
            if let increment, increment > 0, pendingSynthBodies[frame.streamID] != nil {
                pendingSynthBodies[frame.streamID]?.streamWindow += increment
                flushPendingSynth(streamID: frame.streamID)
            }
            return Data()
        }
        return serializeFrame(frame)
    }

    /// Decodes a WINDOW_UPDATE payload's 31-bit increment (RFC 9113 §6.9.1,
    /// reserved high bit masked). Returns nil for a malformed (non-4-byte)
    /// payload so the caller forwards it verbatim for the real peer to reject.
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

    /// Builds a connection- or stream-level WINDOW_UPDATE frame carrying
    /// `increment` — for forwarding a connection WINDOW_UPDATE whose increment
    /// was reduced by the withheld synth debt.
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

    /// The server half of the h2 connection preface used for a
    /// pre-establishment synth reply (when no upstream relays one): an empty
    /// SETTINGS frame followed by a SETTINGS ACK for the client's SETTINGS.
    private func serverConnectionPreface() -> Data {
        var d = Data()
        appendFrameHeader(typeCode: FrameTypeCode.settings, flags: 0, streamID: 0, payloadLength: 0, into: &d)
        appendFrameHeader(typeCode: FrameTypeCode.settings, flags: 0x1, streamID: 0, payloadLength: 0, into: &d)
        return d
    }

    /// A GOAWAY (NO_ERROR) naming ``lastStreamID`` as the highest processed
    /// stream, ending a one-shot synth connection cleanly so the client retries
    /// any higher streams on a fresh connection.
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

    /// Inserts ``streamID`` into ``synthRespondedStreams`` and the
    /// matching FIFO. Evicts the oldest entry when the FIFO is at the
    /// cap so a long-lived connection that repeatedly synthesizes
    /// responses can't grow the set without bound. The eviction is
    /// best-effort — if a client happens to send a late RST_STREAM for
    /// the evicted ID it'll be forwarded to upstream as if from an
    /// idle stream and may trigger GOAWAY, but that risk is bounded by
    /// the cap and unlikely in practice (clients RST promptly or not
    /// at all).
    private func markSynthResponded(_ streamID: UInt32) {
        guard synthRespondedStreams.insert(streamID).inserted else { return }
        synthRespondedOrder.append(streamID)
        if synthRespondedOrder.count > Self.synthRespondedMaxStreams {
            let evicted = synthRespondedOrder.removeFirst()
            synthRespondedStreams.remove(evicted)
            // Keep the paced-body map consistent with the FIFO: an evicted
            // stream is no longer swallow-protected, so a stale buffered body
            // (and any further WINDOW_UPDATEs for it) could not be drained.
            pendingSynthBodies.removeValue(forKey: evicted)
        }
    }

    /// Removes ``streamID`` from both ``synthRespondedStreams`` and the
    /// FIFO. Returns true iff the streamID was present — callers use
    /// the return value to gate frame swallowing (the set membership
    /// and the swallow decision are the same predicate).
    @discardableResult
    private func clearSynthResponded(_ streamID: UInt32) -> Bool {
        guard synthRespondedStreams.remove(streamID) != nil else { return false }
        if let idx = synthRespondedOrder.firstIndex(of: streamID) {
            synthRespondedOrder.remove(at: idx)
        }
        return true
    }

    /// RFC 9110 §5.6.2: header field-name is a `token` — one or more of
    /// `tchar` (alphanumerics plus a fixed punctuation set). Empty
    /// names are rejected. Used to gate user-supplied headers from
    /// ``Anywhere.respond`` before they reach the HPACK encoder.
    private static func isValidHeaderName(_ name: String) -> Bool {
        guard !name.isEmpty else { return false }
        for byte in name.utf8 {
            switch byte {
            case 0x21, 0x23, 0x24, 0x25, 0x26, 0x27,
                 0x2A, 0x2B, 0x2D, 0x2E,
                 0x5E, 0x5F, 0x60, 0x7C, 0x7E:
                continue
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A:
                continue
            default:
                return false
            }
        }
        return true
    }

    /// HTTP/2 disallows CR, LF, and NUL in header field values (RFC
    /// 9113 §8.2.1). A scriptable inject path would otherwise let a
    /// careless or malicious script slip extra header lines into the
    /// re-encoded block via the decoder's string handling.
    private static func isValidHTTP2HeaderValue(_ value: String) -> Bool {
        for byte in value.utf8 {
            if byte == 0x0D || byte == 0x0A || byte == 0x00 {
                return false
            }
        }
        return true
    }

    // MARK: - Message build / header rebuild

    /// Builds the ``MITMScriptEngine/Message`` the script chain
    /// receives. HTTP/2 pseudo-headers (`:method`, `:authority`,
    /// `:path`, `:scheme`, `:status`) are stripped here and projected
    /// into the scalar `method` / `url` / `status` fields so the script
    /// sees only regular headers in `ctx.headers`. On response phase
    /// the originating request's method/url are looked up via
    /// ``MITMRequestLog``.
    private func buildMessage(
        headers: [(name: String, value: String)],
        body: Data,
        originatingRequest: MITMRequestLog.Record?
    ) -> MITMScriptEngine.Message {
        var method: String?
        var url: String?
        var status: Int?
        switch phase {
        case .httpRequest:
            method = firstHeaderValue(headers, name: ":method")
            if let path = firstHeaderValue(headers, name: ":path") {
                // Use the connection's destination host (the SNI/host
                // the client opened the leg with) rather than the
                // possibly-rewritten ``:authority``, so ``ctx.url``
                // mirrors what the client requested. HTTP/1 does the
                // same with its session-level ``host`` field, keeping
                // the two protocols' script semantics aligned.
                url = "https://\(rewriter.host)\(path)"
            }
        case .httpResponse:
            if let raw = firstHeaderValue(headers, name: ":status"),
               let code = Int(raw.trimmingCharacters(in: .whitespaces)) {
                status = code
            }
            method = originatingRequest?.method
            url = originatingRequest?.url
        }
        let regularHeaders = headers.filter { !$0.name.hasPrefix(":") }
        return MITMScriptEngine.Message(
            phase: phase,
            method: method,
            url: url,
            status: status,
            headers: regularHeaders,
            body: body,
            ruleSetID: rewriter.ruleSetID
        )
    }

    /// Re-assembles the wire header block from a (possibly mutated)
    /// message. Pseudo-headers are rebuilt from ``message`` fields; any
    /// pseudo-headers the script accidentally added to
    /// ``message.headers`` are dropped here so the HPACK encoder never
    /// emits duplicates. ``fallback`` supplies pseudo-header values
    /// the message lacks (e.g. ``:scheme`` on requests, original
    /// authority when the script cleared the URL).
    private func rebuildHeaders(
        from message: MITMScriptEngine.Message,
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
                // RFC 9113 §8.3.1: ``:path`` MUST start with ``/`` for
                // non-CONNECT, non-OPTIONS-asterisk requests. A script
                // that wrote a relative URL like ``api/foo`` would
                // otherwise produce ``:path: api/foo``, which strict
                // h2 stacks reject with PROTOCOL_ERROR + GOAWAY.
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

    /// Records the in-flight request's method and absolute URL onto the
    /// shared request log so the outbound (response) leg can populate
    /// ctx.method / ctx.url. Inbound HEADERS only.
    private func logHTTP2Request(streamID: UInt32, headers: [(name: String, value: String)]) {
        guard direction == .inbound else { return }
        // A request has been committed upstream — recorded so a later
        // pre-establishment synth sets its GOAWAY last-stream-id correctly.
        forwardedRequestUpstream = true
        let method = firstHeaderValue(headers, name: ":method")
        var url: String?
        if let path = firstHeaderValue(headers, name: ":path") {
            // Use the connection's destination host so the recorded
            // URL — surfaced as ``ctx.url`` on response-phase scripts —
            // matches what request-phase scripts saw and what HTTP/1
            // records. Authority-rewrite rules change ``:authority``
            // on the wire, but the script-facing URL should remain the
            // client's original target for consistency across protocols.
            url = "https://\(rewriter.host)\(path)"
        }
        rewriter.requestLog.recordHTTP2(streamID: streamID, method: method, url: url)
    }

    // MARK: - Padding helpers

    /// Strips PADDED + PRIORITY prefixes from a HEADERS payload,
    /// returning just the HPACK header block. Returns nil when the
    /// padding length is invalid.
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

    /// Strips PADDED + extracts the Promised Stream ID from a
    /// PUSH_PROMISE payload.
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

    /// Strips PADDED from a DATA payload.
    private func stripDataPadding(frame: RawFrame) -> Data? {
        var payload = frame.payload
        if frame.flags & 0x8 != 0 {
            guard let stripped = stripPadding(&payload) else { return nil }
            payload = stripped
        }
        return payload
    }

    /// Removes the leading pad-length byte and the trailing padding
    /// bytes; returns the inner content.
    private func stripPadding(_ payload: inout Data) -> Data? {
        guard !payload.isEmpty else { return nil }
        let padLen = Int(payload[payload.startIndex])
        guard payload.count >= 1 + padLen else { return nil }
        return payload.subdata(in: (payload.startIndex + 1)..<(payload.endIndex - padLen))
    }

    // MARK: - Frame parser / serializer

    /// Reads one complete frame from `buffer`, removing the consumed
    /// bytes. Returns nil if more bytes are needed.
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

    /// Issues the DATA **sender** its own flow-control credit for a frame the
    /// MITM is buffering (a `script` / `body-json` / `body-replace` rule holds
    /// the whole message before re-emitting it). A relaying proxy lets the
    /// receiver's WINDOW_UPDATEs flow back to the sender, but a buffered stream
    /// emits nothing to the receiver until the body is complete — so the
    /// receiver never credits, and the sender stalls at its initial window,
    /// wedging the stream (and, via the shared connection window, others) until
    /// timeout. While it buffers, the MITM **is** the receiver, so it credits
    /// the sender itself: a per-stream WINDOW_UPDATE keeps this stream's window
    /// open and a connection-level one keeps the shared window open.
    /// ``emitBufferedDataFrames`` records the matching debt so the receiver's
    /// eventual credit for the emitted body is withheld from the relay and the
    /// sender is not credited twice — leaving its window netting to the same
    /// value a pure relay would. The credit goes to the sender's own leg: the
    /// client on the inbound (request) leg, the server on the outbound
    /// (response) leg. `flowControlledLength` is the DATA frame's full on-wire
    /// payload length (including any padding), which is what the sender debited.
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

    /// ``emitDataFrames`` for DATA that originates from the MITM's **buffer**
    /// for a body-rewrite stream (a rewrite result, the abandon prefix, or a
    /// decompression-fail passthrough) rather than being relayed frame-for-frame
    /// from the sender. While the stream was buffered,
    /// ``creditBufferedDataToSender`` gave the sender its own WINDOW_UPDATEs; the
    /// receiver now credits what it receives here and those credits are relayed
    /// back to the sender on the opposite leg, so without compensation the
    /// sender would be credited twice. Recording the emitted byte count as debt
    /// makes the opposite leg withhold exactly that much from the relay (mirror
    /// of the synth path's ``addSynthDebt``). Direction selects the relay that
    /// withholds it: a response body (outbound) is credited by the client and
    /// relayed to the server on the inbound leg (``withholdSynthDebt``); a
    /// request body (inbound) is credited by the server and relayed to the
    /// client on the outbound leg (``withholdClientRequestDebt``).
    private func emitBufferedDataFrames(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        if !payload.isEmpty {
            switch direction {
            case .outbound: flowController.addSynthDebt(payload.count)
            case .inbound:  flowController.addClientRequestDebt(payload.count)
            }
        }
        return emitDataFrames(streamID: streamID, payload: payload, endStream: endStream)
    }

    /// Emits one or more DATA frames whose payloads each fit within
    /// ``maxFramePayloadSize``. END_STREAM lands on the last frame only.
    /// An empty input still emits a single empty DATA frame so any
    /// END_STREAM signal survives. Writes frame headers directly into
    /// ``output`` and appends payload slices in place, avoiding the
    /// per-frame intermediate ``Data`` and ``subdata`` copy a
    /// ``serializeFrame`` round-trip would incur — 256 throwaway
    /// allocations for a 4 MiB body split into 256 frames.
    private func emitDataFrames(streamID: UInt32, payload: Data, endStream: Bool) -> Data {
        // Debit the client's shared connection-level flow-control window for
        // real server→client DATA the outbound leg forwards or rewrites — this
        // is the single chokepoint every such DATA byte routes through, so the
        // window stays in step with what the client has actually received. The
        // synth (`Anywhere.respond`) path debits the window itself as it paces,
        // and the inbound leg's other ``emitDataFrames`` calls produce
        // upstream-bound *request* DATA that the client window must not see, so
        // gate on direction.
        if direction == .outbound {
            flowController.debitConnection(payload.count)
        }
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

    /// Emits a HEADERS or PUSH_PROMISE frame, followed by CONTINUATION
    /// frames when the encoded block does not fit in a single frame
    /// (RFC 9113 §6.2 / §6.10). PUSH_PROMISE's 4-byte Promised Stream ID
    /// prefix counts towards the first frame's payload, so the initial
    /// chunk is sized accordingly. END_HEADERS lands on the final emitted
    /// frame; END_STREAM stays on the initial frame.
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

    /// Writes the 9-byte HTTP/2 frame header in place. Used by the
    /// emit paths instead of ``serializeFrame`` so a length-prefixed
    /// payload can be appended directly to the running output buffer
    /// without the intermediate ``Data`` copy.
    private func appendFrameHeader(
        typeCode: UInt8,
        flags: UInt8,
        streamID: UInt32,
        payloadLength: Int,
        into out: inout Data
    ) {
        // The 24-bit length field can only represent 0…2^24-1. A
        // negative or oversized value would sign-extend through the
        // shifts and emit a corrupt frame header that desyncs the
        // receiver's framing. No caller passes such a value today,
        // but assert the invariant rather than silently emit garbage.
        precondition(payloadLength >= 0 && payloadLength <= 0xFFFFFF,
                     "HTTP/2 frame payload length \(payloadLength) out of 24-bit range")
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

    /// Whole-frame serializer for the pass-through path, where we
    /// receive a ``RawFrame`` from ``parseFrame`` and emit it verbatim
    /// (unknown frame types: SETTINGS, WINDOW_UPDATE, PING, GOAWAY,
    /// RST_STREAM, PRIORITY, future types). The emit-side hot paths
    /// (DATA / HEADERS / CONTINUATION) use ``appendFrameHeader`` so
    /// they can write into the running output buffer without going
    /// through this intermediate ``Data``.
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
