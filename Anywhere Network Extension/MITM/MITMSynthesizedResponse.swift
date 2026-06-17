//
//  MITMSynthesizedResponse.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

extension MITMScriptEngine.SynthesizedResponse {

    /// Framing + connection-specific (hop-by-hop) header names a script must not set on a
    /// locally-generated response: content-length/transfer-encoding are owned by the serializer, and
    /// connection/keep-alive/upgrade/proxy-connection/te/trailer are hop-by-hop (RFC 9110 §7.6.1) —
    /// and outright illegal on the HTTP/2 synth path (RFC 9113 §8.2.2). Dropping them keeps the wire
    /// well-framed regardless of what the script supplies.
    private static let disallowedSynthHeaders: Set<String> = [
        "content-length", "transfer-encoding", "connection", "keep-alive",
        "upgrade", "proxy-connection", "te", "trailer",
    ]

    /// Sanitizes script/rule-supplied headers: drops framing and pseudo-headers, validates names/values
    /// (response-splitting defense). `lowercaseNames` enforces HTTP/2 lowercase (RFC 9113 §8.2.1).
    func sanitizedHeaders(
        lowercaseNames: Bool,
        onDrop: (String) -> Void
    ) -> [(name: String, value: String)] {
        var out: [(name: String, value: String)] = []
        out.reserveCapacity(headers.count)
        for entry in headers {
            let name = lowercaseNames ? entry.name.lowercased() : entry.name
            if name.hasPrefix(":") { continue }
            if Self.disallowedSynthHeaders.contains(name.lowercased()) {
                continue
            }
            guard isValidHTTPHeaderName(name), isValidHTTPHeaderValue(entry.value) else {
                onDrop(entry.name)
                continue
            }
            out.append((name: name, value: entry.value))
        }
        return out
    }

    /// RFC 9110 §5.6.7 IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`). Fixed POSIX locale + GMT so
    /// the device's locale/timezone can't corrupt the format.
    private static let imfFixdateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return f
    }()

    /// Appends a `Date` (RFC 9110 §6.6.1: an origin generates one on every response) to a
    /// locally-generated response unless the script already supplied one. `lowercaseName` matches
    /// HTTP/2's lowercase-header requirement (RFC 9113 §8.2.1).
    func withDateStamp(_ headers: [(name: String, value: String)], lowercaseName: Bool) -> [(name: String, value: String)] {
        guard !headers.contains(where: { $0.name.equalsIgnoringASCIICase("date") }) else { return headers }
        return headers + [(name: lowercaseName ? "date" : "Date", value: Self.imfFixdateFormatter.string(from: Date()))]
    }

    /// Truncates the body to `cap` bytes, invoking `onTruncate(originalSize)` when it exceeds the cap.
    func truncatedBody(cap: Int, onTruncate: (Int) -> Void) -> Data {
        guard body.count > cap else { return body }
        onTruncate(body.count)
        let end = body.startIndex + cap
        return body.subdata(in: body.startIndex..<end)
    }
}
