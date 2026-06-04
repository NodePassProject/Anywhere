//
//  MITMSynthesizedResponse.swift
//  Anywhere
//
//  Created by NodePassProject on 6/4/26.
//

import Foundation

extension MITMScriptEngine.SynthesizedResponse {

    /// Sanitizes the script/rule-supplied headers for emission on a synthesized
    /// response. Drops framing headers (`content-length` / `transfer-encoding` —
    /// the per-protocol serializer sets framing itself) and pseudo-headers
    /// (`:`-prefixed; HTTP/2 builds its own `:status`, HTTP/1 has none), then
    /// validates each name + value against the shared RFC 9110 / 9113 checks,
    /// reporting each drop via `onDrop(name)`.
    ///
    /// `lowercaseNames` lowercases field-names for HTTP/2 (RFC 9113 §8.2.1
    /// forbids uppercase); HTTP/1 keeps the original case. Shared by both
    /// transports' `queueSynthesizedResponse` so the response-splitting defense
    /// (no CR/LF/NUL, no re-injected framing header) lives in exactly one place.
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

    /// Truncates ``body`` to `cap` bytes, invoking `onTruncate(originalSize)`
    /// when it exceeds the cap. Shared memory guard for the synth serializers —
    /// both bound the buffered synth body to the same per-message budget
    /// (``MITMBodyCodec/maxBufferedBodyBytes``).
    func truncatedBody(cap: Int, onTruncate: (Int) -> Void) -> Data {
        guard body.count > cap else { return body }
        onTruncate(body.count)
        let end = body.startIndex + cap
        return body.subdata(in: body.startIndex..<end)
    }
}
