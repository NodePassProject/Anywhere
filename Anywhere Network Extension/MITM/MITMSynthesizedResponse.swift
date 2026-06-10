//
//  MITMSynthesizedResponse.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

extension MITMScriptEngine.SynthesizedResponse {

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
            if name.equalsIgnoringASCIICase("content-length")
                || name.equalsIgnoringASCIICase("transfer-encoding") {
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

    /// Truncates the body to `cap` bytes, invoking `onTruncate(originalSize)` when it exceeds the cap.
    func truncatedBody(cap: Int, onTruncate: (Int) -> Void) -> Data {
        guard body.count > cap else { return body }
        onTruncate(body.count)
        let end = body.startIndex + cap
        return body.subdata(in: body.startIndex..<end)
    }
}
