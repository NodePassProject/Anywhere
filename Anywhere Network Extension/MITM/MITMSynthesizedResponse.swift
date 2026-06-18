//
//  MITMSynthesizedResponse.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

extension MITMScriptEngine.SynthesizedResponse {

    /// Header names a script must not set on a synth response: content-length/transfer-encoding
    /// are serializer-owned; the rest are hop-by-hop (RFC 9110 §7.6.1) and illegal on the
    /// HTTP/2 synth path (RFC 9113 §8.2.2). Dropping them keeps the wire well-framed.
    private static let disallowedSynthHeaders: Set<String> = [
        "content-length", "transfer-encoding", "connection", "keep-alive",
        "upgrade", "proxy-connection", "te", "trailer",
    ]

    /// Sanitizes script/rule headers: drops framing/pseudo-headers, validates names/values
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

    /// Appends a `Date` (RFC 9110 §6.6.1: origins generate one per response) unless the script
    /// already supplied one. `lowercaseName` matches HTTP/2's requirement (RFC 9113 §8.2.1).
    func withDateStamp(_ headers: [(name: String, value: String)], lowercaseName: Bool) -> [(name: String, value: String)] {
        guard !headers.contains(where: { $0.name.equalsIgnoringASCIICase("date") }) else { return headers }
        return headers + [(name: lowercaseName ? "date" : "Date", value: Self.imfFixdateFormatter.string(from: Date()))]
    }

    func truncatedBody(cap: Int, onTruncate: (Int) -> Void) -> Data {
        guard body.count > cap else { return body }
        onTruncate(body.count)
        let end = body.startIndex + cap
        return body.subdata(in: body.startIndex..<end)
    }
}
