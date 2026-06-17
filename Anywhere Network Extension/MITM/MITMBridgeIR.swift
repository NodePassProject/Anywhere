//
//  MITMBridgeIR.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

/// How a request body is framed toward an HTTP/1.1 upstream. HTTP/2 carries no
/// on-wire length, so the framing is chosen explicitly; an HTTP/2 upstream ignores
/// this and frames with DATA/END_STREAM.
enum MITMBridgeBodyFraming: Equatable {
    case none
    case contentLength(Int)
    case chunked
}

/// The protocol-agnostic request head the HTTP/2 client leg emits, consumed by
/// whichever upstream leg the session binds after the dial (HTTP/1.1 or HTTP/2). It is
/// neutral; each upstream leg applies its own protocol translation (the HTTP/1.1
/// serializer, or HTTP/2 HEADERS encoding).
struct MITMRequestHead {
    let clientStreamID: UInt32
    let method: String
    let scheme: String
    /// `:authority` (post-rewrite). The HTTP/1.1 leg turns this into a `Host` header.
    let authority: String
    /// `:path` (origin-form request target).
    let path: String
    /// Regular headers, post request-phase rewrite, with pseudo-, hop-by-hop, and
    /// framing headers removed. `Cookie` is left split (HTTP/2 form); the HTTP/1.1
    /// serializer coalesces it.
    let headers: [(name: String, value: String)]
    /// Framing for an HTTP/1.1 upstream; ignored by an HTTP/2 upstream.
    let framing: MITMBridgeBodyFraming
    /// Lowercased names the client sent with the HPACK never-indexed representation
    /// (RFC 7541 §6.2.3); an h2 upstream must re-emit them never-indexed (§7.1.3). Empty
    /// toward an h1 upstream, which has no such marker.
    let neverIndexed: Set<String>
    /// The upstream this request's transparent rewrite resolved to, **captured synchronously at
    /// rewrite time** (nil → dial the original destination). Carrying it on the head — rather than
    /// reading the rewriter's shared last-write-wins field at dial time — keeps the dial target
    /// consistent with the `:authority` baked into this same head, even when the request is buffered
    /// for a body rewrite and a concurrent stream rewrites to a different host in the meantime.
    let resolvedUpstream: (host: String, port: UInt16?)?
}

/// The upstream side of the bridge (HTTP/1.1 per-stream, or one multiplexed HTTP/2).
/// The client leg drives it with neutral request events; the leg serializes them to
/// its wire protocol and delivers responses back through a `MITMResponseSink`.
protocol MITMUpstreamLeg: AnyObject {
    func sendRequestHead(_ head: MITMRequestHead, endStream: Bool)
    func sendRequestData(streamID: UInt32, _ data: Data, endStream: Bool)
    /// Terminal request trailers (e.g. gRPC), emitted after the request body. An h2 upstream sends
    /// them as a trailing HEADERS block with END_STREAM; a leg that can't carry request trailers
    /// (HTTP/1.1) just ends the body via the default below.
    func sendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    func abortRequest(streamID: UInt32)
    func markTorn()
}

extension MITMUpstreamLeg {
    /// Default: a leg with no request-trailer support simply ends the request body without them.
    func sendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        sendRequestData(streamID: streamID, Data(), endStream: true)
    }
}

/// The client-bound side of the bridge: an upstream leg delivers protocol-agnostic
/// response events, and the implementor (the h2 client leg) encodes them to the
/// client with flow-control pacing. Headers are post response-phase rewrite; the
/// sink normalizes them to HTTP/2 (lowercase, hop-by-hop stripped).
protocol MITMResponseSink: AnyObject {
    /// `neverIndexed` carries the lowercased names the upstream marked never-indexed (RFC 7541
    /// §6.2.3), which the sink must re-emit never-indexed toward the client (§7.1.3).
    func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>)
    /// An interim 1xx informational response (e.g. 103 Early Hints). It precedes the final response
    /// on the same stream and carries no body or END_STREAM (RFC 9113 §8.1); the sink emits it as a
    /// HEADERS block and keeps the stream open for the final response that follows.
    func deliverResponseInterim(streamID: UInt32, status: Int, headers: [(name: String, value: String)])
    func deliverResponseData(streamID: UInt32, _ data: Data, endStream: Bool)
    /// Terminal trailer fields (e.g. gRPC `grpc-status`). The sink emits them as a trailing
    /// HEADERS block with END_STREAM, after the response body has drained to the client.
    func deliverResponseTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    /// The upstream reset/aborted before the response completed. `errorCode` is the HTTP/2
    /// error to surface to the client (RFC 9113 §7): a real upstream RST relays its own code so
    /// a retriable REFUSED_STREAM stays distinguishable from a fatal reset; locally-detected
    /// failures (malformed/truncated upstream, an internal limit) use INTERNAL_ERROR.
    func deliverResponseReset(streamID: UInt32, errorCode: UInt32)
}

extension MITMResponseSink {
    /// For responses with no HPACK provenance (an h1 upstream re-parsed to h2, or a
    /// synthesized response): nothing was marked never-indexed.
    func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool) {
        deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: endStream, neverIndexed: [])
    }

    /// Locally-detected reset (no upstream code to relay): INTERNAL_ERROR.
    func deliverResponseReset(streamID: UInt32) {
        deliverResponseReset(streamID: streamID, errorCode: MITMHTTP2FrameCodec.ErrorCode.internalError)
    }
}

/// HTTP/2 ⇄ HTTP/1.1 header translation: strips connection-specific and framing fields,
/// and normalizes field-name case for the target protocol.
enum MITMBridgeHeaders {

    /// Connection-specific / hop-by-hop fields, illegal in HTTP/2 (RFC 9113 §8.2.2) or meaningless
    /// once the bridge owns framing — including the classic hop-by-hop set (RFC 9110 §7.6.1):
    /// proxy-auth and Trailer must not be forwarded across this leg. Lowercased for matching.
    static let hopByHop: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
        "proxy-authenticate", "proxy-authorization", "trailer",
    ]

    /// RFC 9113 §8.3: validates a decoded h2 header block's pseudo-header section — every
    /// pseudo-header field MUST precede the regular fields, none may be duplicated, and only the
    /// known request (`:method` / `:scheme` / `:authority` / `:path`) or response (`:status`)
    /// pseudo-headers are permitted. A violation makes the message malformed — and a request-
    /// smuggling vector once re-serialized to HTTP/1.1 — so the caller rejects it. Names match
    /// case-insensitively, mirroring the rest of the bridge (an uppercase `:Path` is normalized,
    /// not silently bypassed).
    static func pseudoHeadersValid(
        _ decoded: [(name: String, value: String)],
        isRequest: Bool
    ) -> Bool {
        let allowed: Set<String> = isRequest
            ? [":method", ":scheme", ":authority", ":path"]
            : [":status"]
        var seen: Set<String> = []
        var sawRegular = false
        for (name, _) in decoded {
            if name.hasPrefix(":") {
                if sawRegular { return false }                    // pseudo-header after a regular field
                let lower = name.lowercased()
                if !allowed.contains(lower) { return false }      // unknown pseudo-header
                if !seen.insert(lower).inserted { return false }  // duplicate pseudo-header
            } else {
                sawRegular = true
            }
        }
        return true
    }

    /// Regular request headers for an upstream: pseudo-, hop-by-hop-, and framing
    /// headers removed. `Cookie` is left split (the HTTP/1.1 serializer coalesces it,
    /// HTTP/2 keeps it split).
    static func upstreamRequestHeaders(
        decoded: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        let drop = hopByHop.union(connectionTokens(decoded))
        var out: [(name: String, value: String)] = []
        out.reserveCapacity(decoded.count)
        for (name, value) in decoded {
            if name.hasPrefix(":") { continue }
            let lower = name.lowercased()
            if drop.contains(lower) { continue }
            if lower == "content-length" { continue }
            // RFC 9113 §8.2.2: `te` is connection-specific and illegal in HTTP/2 unless its sole
            // value is `trailers`; an HTTP/1.1 upstream treats it as hop-by-hop either way.
            if lower == "te", value.trimmingCharacters(in: .whitespaces).lowercased() != "trailers" { continue }
            out.append((name: name, value: value))
        }
        // Clamp Accept-Encoding to the codings we can decode (mitmproxy `constrain_encoding`) so a
        // buffered body rule isn't silently defeated by an undecodable Content-Encoding (e.g. zstd).
        return out.map { entry in
            entry.name.lowercased() == "accept-encoding"
                ? (name: entry.name, value: MITMBodyCodec.constrainedAcceptEncoding(entry.value))
                : entry
        }
    }

    /// Normalizes a (rewritten) response header list to HTTP/2 form: lowercases every
    /// field-name (RFC 9113 §8.2.1) and drops connection-specific fields. The caller
    /// prepends `:status`. `content-length` is **kept**: it's a content field, not framing
    /// (an h2 body is framed by DATA/END_STREAM), and it's informational the client may need
    /// — a HEAD / 204 / 304 carries it as its sole semantic payload. Paths that re-materialize
    /// the body (buffered rewrite, streaming script) correct or drop it via the helpers below
    /// before delivering, so the emitted length always matches the DATA (RFC 9113 §8.1.2.6).
    static func responseHeadersToH2(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        let drop = hopByHop.union(connectionTokens(headers))
        var out: [(name: String, value: String)] = []
        out.reserveCapacity(headers.count)
        for (name, value) in headers {
            if name.hasPrefix(":") { continue }
            let lower = name.lowercased()
            if drop.contains(lower) { continue }
            if lower == "te", value.trimmingCharacters(in: .whitespaces).lowercased() != "trailers" { continue }
            out.append((name: lower, value: value))
        }
        return out
    }

    /// Tokens listed in a `Connection` header are themselves hop-by-hop (RFC 9110 §7.6.1): an
    /// intermediary MUST drop both `Connection` and every field it names before forwarding, and
    /// none may survive into HTTP/2 (RFC 9113 §8.2.2). Returns the lowercased token set; the
    /// static `hopByHop` set already covers `Connection` itself plus the common fixed names.
    private static func connectionTokens(
        _ headers: [(name: String, value: String)]
    ) -> Set<String> {
        var tokens: Set<String> = []
        for (name, value) in headers where name.lowercased() == "connection" {
            for token in value.split(separator: ",") {
                let normalized = token.trimmingCharacters(in: .whitespaces).lowercased()
                if !normalized.isEmpty { tokens.insert(normalized) }
            }
        }
        return tokens
    }

    /// Replaces `content-length` with the exact re-materialized body length, for a buffered
    /// rewrite (script edit / decompression) whose body length no longer matches the upstream
    /// value — a stale length would make the h2 message malformed (RFC 9113 §8.1.2.6).
    static func settingContentLength(
        _ headers: [(name: String, value: String)],
        _ length: Int
    ) -> [(name: String, value: String)] {
        var out = headers.filter { $0.name.lowercased() != "content-length" }
        out.append((name: "content-length", value: String(length)))
        return out
    }

    /// Drops `content-length`: a streaming script rewrites frames as they pass, so the total
    /// length isn't known up front and the upstream value would mismatch the delivered DATA.
    static func droppingContentLength(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        headers.filter { $0.name.lowercased() != "content-length" }
    }
}
