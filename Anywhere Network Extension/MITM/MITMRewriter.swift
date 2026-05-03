//
//  MITMRewriter.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

final class MITMRewriter {

    /// Marker between the head and the body of an HTTP/1 message.
    private static let headerTerminator = Data([0x0D, 0x0A, 0x0D, 0x0A]) // CRLF CRLF

    func transformRequest(_ data: Data) -> Data {
        // Test rewrite: tag the first request whose start line falls
        // inside this chunk. Visible by hitting an echo endpoint
        // (e.g. httpbin.org/headers).
        guard looksLikeRequestStart(data) else { return data }
        return injectHeader(into: data, line: "X-Anywhere-MITM-Req: 1")
    }

    func transformResponse(_ data: Data) -> Data {
        // Test rewrite: tag the first response whose status line falls
        // inside this chunk. Visible in browser DevTools (Network → Headers).
        guard data.starts(with: Data("HTTP/".utf8)) else { return data }
        return injectHeader(into: data, line: "X-Anywhere-MITM-Resp: 1")
    }

    /// Returns true if `data` begins with what looks like an HTTP/1
    /// request line: `<METHOD> <path> HTTP/1.x\r\n`. This guards
    /// against injecting into a request body chunk that happens to
    /// contain CRLF CRLF.
    private func looksLikeRequestStart(_ data: Data) -> Bool {
        guard let crlf = data.range(of: Data([0x0D, 0x0A])) else { return false }
        let firstLine = data.subdata(in: data.startIndex..<crlf.lowerBound)
        guard let line = String(data: firstLine, encoding: .ascii) else { return false }
        return line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0")
    }

    /// Inserts `<line>\r\n` immediately before the first `CRLF CRLF` in
    /// `data`. No-op when the terminator is absent.
    private func injectHeader(into data: Data, line: String) -> Data {
        guard let range = data.range(of: Self.headerTerminator) else { return data }
        var out = Data(capacity: data.count + line.utf8.count + 2)
        out.append(data.subdata(in: data.startIndex..<range.lowerBound))
        out.append(0x0D); out.append(0x0A)              // CRLF
        out.append(contentsOf: line.utf8)
        out.append(data.subdata(in: range.lowerBound..<data.endIndex))
        return out
    }
}
