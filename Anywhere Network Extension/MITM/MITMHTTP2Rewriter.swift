//
//  MITMHTTP2Rewriter.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/3/26.
//

import Foundation

/// HTTP/2 analog of ``MITMRewriter``. Where ``MITMRewriter`` operates on
/// the raw plaintext byte stream that the HTTP/1.1 pipeline produces,
/// this rewriter operates at HTTP/2 frame granularity — the unit at
/// which h2 traffic is naturally split.
///
/// All hooks are passthrough today. Wiring matches the HTTP/1.1 stub
/// (`transformRequest` / `transformResponse`): rewriting rules will be
/// applied here once the rule engine lands.
final class MITMHTTP2Rewriter {

    /// Called once per request HEADERS block (after CONTINUATION is
    /// reassembled) flowing client → server.
    func transformRequestHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32
    ) -> [(name: String, value: String)] {
        // Test rewrite: tag every outgoing request so we can verify the
        // pipeline by visiting an echo endpoint (e.g. httpbin.org/headers
        // or postman-echo.com/headers).
        var modified = headers
        modified.append((name: "x-anywhere-mitm-req", value: "1"))
        return modified
    }

    /// Called once per response HEADERS block flowing server → client.
    func transformResponseHeaders(
        _ headers: [(name: String, value: String)],
        streamID: UInt32
    ) -> [(name: String, value: String)] {
        // Test rewrite: tag every response so we can verify the pipeline
        // by inspecting headers in browser DevTools (Network tab).
        var modified = headers
        modified.append((name: "x-anywhere-mitm-resp", value: "1"))
        return modified
    }

    /// Called per DATA frame flowing client → server.
    func transformRequestData(
        _ data: Data,
        streamID: UInt32,
        endStream: Bool
    ) -> Data {
        // TODO: Apply request body rewrite rules.
        data
    }

    /// Called per DATA frame flowing server → client.
    func transformResponseData(
        _ data: Data,
        streamID: UInt32,
        endStream: Bool
    ) -> Data {
        // TODO: Apply response body rewrite rules.
        data
    }
}
