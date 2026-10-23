//
//  MITMBridgeIR.swift
//  Anywhere
//
//  Created by NodePassProject on 6/15/26.
//

import Foundation

nonisolated enum MITMBridgeBodyFraming: Equatable {
    case none
    case contentLength(Int)
    case chunked
}

nonisolated struct MITMRequestHead {
    let clientStreamID: UInt32
    let method: String
    let scheme: String
    let authority: String
    let path: String
    let headers: [(name: String, value: String)]
    let framing: MITMBridgeBodyFraming
    let indexing: HPACKIndexingHints
    let resolvedUpstream: (host: String, port: UInt16?)?
    let originalURL: String?
}

nonisolated protocol MITMUpstreamLeg: AnyObject {
    func sendRequestHead(_ head: MITMRequestHead, endStream: Bool)
    func sendRequestData(streamID: UInt32, _ data: Data, endStream: Bool)
    func sendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    func abortRequest(streamID: UInt32)
    func markTorn()
}

extension MITMUpstreamLeg {
    func sendRequestTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)]) {
        sendRequestData(streamID: streamID, Data(), endStream: true)
    }
}

nonisolated protocol MITMResponseSink: AnyObject {
    func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool, neverIndexed: Set<String>)
    func deliverResponseInterim(streamID: UInt32, status: Int, headers: [(name: String, value: String)])
    func deliverResponseData(streamID: UInt32, _ data: Data, endStream: Bool)
    func deliverResponseTrailers(streamID: UInt32, _ trailers: [(name: String, value: String)])
    func deliverResponseReset(streamID: UInt32, errorCode: UInt32)
}

extension MITMResponseSink {
    func deliverResponseHead(streamID: UInt32, status: Int, headers: [(name: String, value: String)], endStream: Bool) {
        deliverResponseHead(streamID: streamID, status: status, headers: headers, endStream: endStream, neverIndexed: [])
    }

    func deliverResponseReset(streamID: UInt32) {
        deliverResponseReset(streamID: streamID, errorCode: MITMHTTP2FrameCodec.ErrorCode.internalError)
    }
}

nonisolated enum MITMBridgeHeaders {
    static let hopByHop: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade",
        "proxy-authenticate", "proxy-authorization", "trailer",
    ]

    static let h2ConnectionSpecific: Set<String> = [
        "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade",
    ]

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
                if sawRegular { return false }
                let lower = name.lowercased()
                if !allowed.contains(lower) { return false }
                if !seen.insert(lower).inserted { return false }
            } else {
                sawRegular = true
            }
        }
        return true
    }

    static func requestPseudoHeadersComplete(_ decoded: [(name: String, value: String)]) -> Bool {
        var hasScheme = false
        var hasPath = false
        var isPathEmpty = false
        var authority: String?
        var host: String?
        for (name, value) in decoded {
            if name.hasPrefix(":") {
                switch name.lowercased() {
                case ":scheme": hasScheme = true
                                case ":path":
                    hasPath = true
                    isPathEmpty = value.isEmpty
                case ":authority": authority = value
                default: break
                }
            } else if name.lowercased() == "host" {
                host = value
            }
        }
        guard hasScheme, hasPath, !isPathEmpty else { return false }
        if let authority, let host { return authority == host }
        return authority != nil || host != nil
    }

    static func upstreamRequestHeaders(decoded: [(name: String, value: String)]) -> [(name: String, value: String)] {
        let drop = hopByHop.union(connectionTokens(decoded))
        var out: [(name: String, value: String)] = []
        out.reserveCapacity(decoded.count)
        for (name, value) in decoded {
            if name.hasPrefix(":") { continue }
            let lower = name.lowercased()
            if drop.contains(lower) { continue }
            if lower == "content-length" { continue }
            if lower == "te", value.trimmingCharacters(in: .whitespaces).lowercased() != "trailers" { continue }
            out.append((name: name, value: value))
        }
        return out
    }

    static func clampingAcceptEncoding(_ headers: [(name: String, value: String)]) -> [(name: String, value: String)] {
        headers.map { entry in
            entry.name.lowercased() == "accept-encoding"
                ? (name: entry.name, value: MITMBodyCodec.constrainedAcceptEncoding(entry.value))
                : entry
        }
    }

    static func responseHeadersToH2(_ headers: [(name: String, value: String)]) -> [(name: String, value: String)] {
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

    private static func connectionTokens(_ headers: [(name: String, value: String)]) -> Set<String> {
        var tokens: Set<String> = []
        for (name, value) in headers where name.lowercased() == "connection" {
            for token in value.split(separator: ",") {
                let normalized = token.trimmingCharacters(in: .whitespaces).lowercased()
                if !normalized.isEmpty { tokens.insert(normalized) }
            }
        }
        return tokens
    }

    static func settingContentLength(_ headers: [(name: String, value: String)], _ length: Int) -> [(name: String, value: String)] {
        var out = headers.filter { $0.name.lowercased() != "content-length" }
        out.append((name: "content-length", value: String(length)))
        return out
    }

    static func droppingContentLength(
        _ headers: [(name: String, value: String)]
    ) -> [(name: String, value: String)] {
        headers.filter { $0.name.lowercased() != "content-length" }
    }
}
