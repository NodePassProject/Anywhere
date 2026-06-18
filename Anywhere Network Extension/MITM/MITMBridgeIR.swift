//
//  MITMBridgeIR.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

/// How a request body is framed toward an HTTP/1.1 upstream. An HTTP/2 upstream
/// ignores this and frames with DATA/END_STREAM.
enum MITMBridgeBodyFraming: Equatable {
    case none
    case contentLength(Int)
    case chunked
}

/// Protocol-agnostic request head; each upstream leg applies its own translation.
struct MITMRequestHead {
    let clientStreamID: UInt32
    let method: String
    let scheme: String
    /// `:authority` (post-rewrite). The HTTP/1.1 leg turns this into a `Host` header.
    let authority: String
    /// `:path` (origin-form request target).
    let path: String
    /// Regular headers (post request-phase rewrite) with pseudo-, hop-by-hop, and
    /// framing headers removed. `Cookie` left split; the HTTP/1.1 serializer coalesces it.
    let headers: [(name: String, value: String)]
    /// Framing for an HTTP/1.1 upstream; ignored by an HTTP/2 upstream.
    let framing: MITMBridgeBodyFraming
    /// Lowercased names the client marked HPACK never-indexed (RFC 7541 §6.2.3); an h2
    /// upstream must re-emit them never-indexed (§7.1.3). Empty toward an h1 upstream.
    let neverIndexed: Set<String>
    /// Upstream the transparent rewrite resolved to, captured at rewrite time (nil → dial
    /// the original). Kept on the head so a concurrent stream's rewrite can't change this
    /// request's dial target while it's buffered for a body rewrite.
    let resolvedUpstream: (host: String, port: UInt16?)?
}

/// Upstream side of the bridge; delivers responses back through a `MITMResponseSink`.
protocol MITMUpstreamLeg: AnyObject {
    func sendRequestHead(_ head: MITMRequestHead, endStream: Bool)
    func sendRequestData(streamID: UInt32, _ data: Data, endStream: Bool)
    /// Terminal request trailers (e.g. gRPC), after the body. An h2 upstream sends a trailing
    /// HEADERS block; a leg that can't carry them (HTTP/1.1) ends the body via the default below.
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

/// Client-bound side of the bridge. The sink normalizes headers to HTTP/2
/// (lowercase, hop-by-hop stripped).
protocol MITMResponseSink: AnyObject {
    /// `neverIndexed`: lowercased names the upstream marked never-indexed (RFC 7541 §6.2.3);
    /// the sink re-emits them never-indexed toward the client (§7.1.3).
    func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>)
    /// Interim 1xx response (e.g. 103 Early Hints): precedes the final response, no body or
    /// END_STREAM (RFC 9113 §8.1). The sink emits a HEADERS block and keeps the stream open.
    func deliverResponseInterim(streamID: UInt32, status: Int, headers: [(name: String, value: String)])
    func deliverResponseData(streamID: UInt32, _ data: Data, endStream: Bool)
    /// Terminal trailer fields (e.g. gRPC `grpc-status`): emitted as a trailing HEADERS block
    /// with END_STREAM after the body drains.
    func deliverResponseTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    /// Upstream reset/aborted before completion. `errorCode` is surfaced to the client (RFC 9113
    /// §7): a real upstream RST relays its own code (keeping REFUSED_STREAM distinguishable);
    /// locally-detected failures use INTERNAL_ERROR.
    func deliverResponseReset(streamID: UInt32, errorCode: UInt32)
}

extension MITMResponseSink {
    /// Responses with no HPACK provenance (h1 re-parsed to h2, or synthesized): nothing never-indexed.
    func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool) {
        deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: endStream, neverIndexed: [])
    }

    /// Locally-detected reset (no upstream code to relay): INTERNAL_ERROR.
    func deliverResponseReset(streamID: UInt32) {
        deliverResponseReset(streamID: streamID, errorCode: MITMHTTP2FrameCodec.ErrorCode.internalError)
    }
}

/// HTTP/2 ⇄ HTTP/1.1 header translation.
enum MITMBridgeHeaders {

    /// Hop-by-hop / connection-specific fields not forwarded across the bridge
    /// (RFC 9113 §8.2.2, RFC 9110 §7.6.1). Lowercased for matching.
    static let hopByHop: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
        "proxy-authenticate", "proxy-authorization", "trailer",
    ]

    /// Connection-specific fields HTTP/2 forbids (RFC 9113 §8.2.2): their presence is malformed.
    /// A subset of `hopByHop`. Lowercased for matching.
    static let h2ConnectionSpecific: Set<String> = [
        "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade",
    ]

    /// RFC 9113 §8.2.2: an HTTP/2 message MUST NOT carry a connection-specific field, and `te` may
    /// carry only `trailers`. Returns false when the block violates this; pseudo-headers checked elsewhere.
    static func h2ConnectionHeadersAbsent(_ decoded: [(name: String, value: String)]) -> Bool {
        for (name, value) in decoded {
            if name.hasPrefix(":") { continue }
            let lower = name.lowercased()
            if h2ConnectionSpecific.contains(lower) { return false }
            if lower == "te", value.trimmingCharacters(in: .whitespaces).lowercased() != "trailers" {
                return false
            }
        }
        return true
    }

    /// Validates a decoded h2 block's pseudo-header section (RFC 9113 §8.3): all pseudo-headers
    /// precede regular fields, none duplicated, only the known request/response pseudo-headers
    /// allowed. A violation is malformed (and a smuggling vector once re-serialized to HTTP/1.1),
    /// so the caller rejects it. Names match case-insensitively.
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

    /// Completeness of an inbound request HEADERS (RFC 9113 §8.3.1): mandatory request pseudo-headers
    /// present, `:path` non-empty, `:authority`/`Host` present (byte-equal if both). `:method`,
    /// pseudo-header structure, and CONNECT are handled by the caller.
    static func requestPseudoHeadersComplete(_ decoded: [(name: String, value: String)]) -> Bool {
        var hasScheme = false
        var hasPath = false
        var pathEmpty = false
        var authority: String?
        var host: String?
        for (name, value) in decoded {
            if name.hasPrefix(":") {
                switch name.lowercased() {
                case ":scheme": hasScheme = true
                case ":path": hasPath = true; pathEmpty = value.isEmpty
                case ":authority": authority = value
                default: break
                }
            } else if name.lowercased() == "host" {
                host = value
            }
        }
        // Mandatory request pseudo-headers (:method verified by the caller) + non-empty :path.
        guard hasScheme, hasPath, !pathEmpty else { return false }
        // :authority / Host: at least one present; if both, byte-equal.
        if let authority, let host { return authority == host }
        return authority != nil || host != nil
    }

    /// Regular request headers for an upstream: pseudo-, hop-by-hop, and framing headers
    /// removed. `Cookie` left split (the HTTP/1.1 serializer coalesces it).
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
            // RFC 9113 §8.2.2: `te` is illegal in HTTP/2 unless its sole value is `trailers`;
            // an h1 upstream treats it as hop-by-hop either way.
            if lower == "te", value.trimmingCharacters(in: .whitespaces).lowercased() != "trailers" { continue }
            out.append((name: name, value: value))
        }
        // Clamp Accept-Encoding to the codings we can decode so a buffered body rule isn't
        // defeated by an undecodable Content-Encoding (e.g. zstd).
        return out.map { entry in
            entry.name.lowercased() == "accept-encoding"
                ? (name: entry.name, value: MITMBodyCodec.constrainedAcceptEncoding(entry.value))
                : entry
        }
    }

    /// Normalizes a response header list to HTTP/2 form: lowercases field-names (RFC 9113 §8.2.1),
    /// drops connection-specific fields; the caller prepends `:status`. `content-length` is kept
    /// (it's content, not framing, and a HEAD/204/304 needs it); body-rematerializing paths correct
    /// or drop it via the helpers below so the length matches the DATA (RFC 9113 §8.1.2.6).
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

    /// Tokens named in a `Connection` header are themselves hop-by-hop (RFC 9110 §7.6.1) and must
    /// be dropped before forwarding. Returns the lowercased token set; `hopByHop` already covers
    /// `Connection` and the common fixed names.
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

    /// Replaces `content-length` with the re-materialized body length after a buffered rewrite;
    /// a stale length would make the h2 message malformed (RFC 9113 §8.1.2.6).
    static func settingContentLength(
        _ headers: [(name: String, value: String)],
        _ length: Int
    ) -> [(name: String, value: String)] {
        var out = headers.filter { $0.name.lowercased() != "content-length" }
        out.append((name: "content-length", value: String(length)))
        return out
    }

    /// Drops `content-length`: a streaming script rewrites frames as they pass, so the total
    /// length isn't known up front.
    static func droppingContentLength(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        headers.filter { $0.name.lowercased() != "content-length" }
    }
}
