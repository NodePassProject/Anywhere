//
//  MITMHTTP1Serializer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

nonisolated private let logger = AnywhereLogger(category: "MITMHTTP1Serializer")

nonisolated enum MITMHTTP1Serializer {
    static func requestHead(_ head: MITMRequestHead, host: String) -> Data {
        let startLine = "\(head.method) \(head.path) HTTP/1.1"

        let hasHost = head.headers.contains { ASCII.equalsIgnoringCase($0.name, "host") }
        var safe: [(name: String, value: String)] = []
        safe.reserveCapacity(head.headers.count + 2)

        if !hasHost, !head.authority.isEmpty {
            safe.append((name: "Host", value: head.authority))
        }

        var cookies: [String] = []
        for (name, value) in head.headers {
            if ASCII.equalsIgnoringCase(name, "content-length")
                || ASCII.equalsIgnoringCase(name, "transfer-encoding") {
                continue
            }
            if ASCII.equalsIgnoringCase(name, "cookie") {
                cookies.append(value)
                continue
            }
            guard HTTPHeader.isValidName(name), HTTPHeader.isValidValue(value) else {
                logger.warning("[MITM] \(host): Invalid request header: \(HTTPHeader.escapedForLog(name))")
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
        HTTPHeader.appendFieldBytes(startLine, to: &out)
        out.append(contentsOf: [0x0D, 0x0A])
        for (name, value) in safe {
            HTTPHeader.appendFieldBytes(name, to: &out)
            out.append(contentsOf: [0x3A, 0x20])
            HTTPHeader.appendFieldBytes(value, to: &out)
            out.append(contentsOf: [0x0D, 0x0A])
        }
        out.append(contentsOf: [0x0D, 0x0A])
        return out
    }

    static func chunk(_ data: Data) -> Data {
        var out = Data(capacity: data.count + 16)
        out.append(contentsOf: String(data.count, radix: 16).utf8)
        out.append(contentsOf: [0x0D, 0x0A])
        out.append(data)
        out.append(contentsOf: [0x0D, 0x0A])
        return out
    }

    static let chunkTerminator = Data([0x30, 0x0D, 0x0A, 0x0D, 0x0A])
}
