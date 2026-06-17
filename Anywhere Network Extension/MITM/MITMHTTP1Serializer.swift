//
//  MITMHTTP1Serializer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

/// Serializes a neutral `MITMRequestHead` into an HTTP/1.1 request head plus body
/// chunk framing — the h2→h1 request translation: derive `Host` from the authority,
/// coalesce `Cookie`, and frame the body.
enum MITMHTTP1Serializer {

    /// Builds `METHOD path HTTP/1.1` + headers + framing header + the blank line.
    /// Derives `Host` from `head.authority` when absent, coalesces multiple `Cookie`
    /// headers with `"; "` (RFC 6265 §5.4 — HTTP/1.1 forbids split `Cookie`), and
    /// token-validates header names while dropping CR/LF/NUL values.
    static func requestHead(_ head: MITMRequestHead, host: String) -> Data {
        let startLine = "\(head.method) \(head.path) HTTP/1.1"

        let hasHost = head.headers.contains { $0.name.equalsIgnoringASCIICase("host") }
        var safe: [(name: String, value: String)] = []
        safe.reserveCapacity(head.headers.count + 2)

        // RFC 9113 §8.3.1: an h2 request carries the origin in :authority; h1 needs Host.
        if !hasHost, !head.authority.isEmpty {
            safe.append((name: "Host", value: head.authority))
        }

        var cookies: [String] = []
        for (name, value) in head.headers {
            if name.equalsIgnoringASCIICase("content-length")
                || name.equalsIgnoringASCIICase("transfer-encoding") {
                continue // the bridge owns framing
            }
            if name.equalsIgnoringASCIICase("cookie") {
                cookies.append(value)
                continue
            }
            guard isValidHTTPHeaderName(name), isValidHTTPHeaderValue(value) else {
                logger.warning("HTTP/1 bridge \(host): dropping invalid request header \(name)")
                continue
            }
            safe.append((name: name, value: value))
        }
        if !cookies.isEmpty {
            safe.append((name: "Cookie", value: cookies.joined(separator: "; ")))
        }
        switch head.framing {
        case .none:
            break
        case .contentLength(let n):
            safe.append((name: "Content-Length", value: String(n)))
        case .chunked:
            safe.append((name: "Transfer-Encoding", value: "chunked"))
        }

        var size = startLine.utf8.count + 4
        for (name, value) in safe {
            size += name.utf8.count + 2 + value.utf8.count + 2
        }
        var out = Data(capacity: size)
        // ISO-8859-1 bytes so a header octet the client sent (HPACK-decoded as latin-1) round-trips
        // to the upstream unchanged rather than being re-encoded as multi-byte UTF-8.
        out.appendHeaderFieldBytes(startLine)
        out.append(0x0D); out.append(0x0A)
        for (name, value) in safe {
            out.appendHeaderFieldBytes(name)
            out.append(0x3A); out.append(0x20)
            out.appendHeaderFieldBytes(value)
            out.append(0x0D); out.append(0x0A)
        }
        out.append(0x0D); out.append(0x0A)
        return out
    }

    /// Frames one chunk: `<hex-size>\r\n<data>\r\n` (caller avoids empty `data`).
    static func chunk(_ data: Data) -> Data {
        var out = Data(capacity: data.count + 16)
        out.append(contentsOf: String(data.count, radix: 16).utf8)
        out.append(0x0D); out.append(0x0A)
        out.append(data)
        out.append(0x0D); out.append(0x0A)
        return out
    }

    /// The final `0\r\n\r\n` chunk terminator (no trailers — the bridge drops them).
    static let chunkTerminator = Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A])
}

private let logger = AnywhereLogger(category: "MITMH1Serializer")
