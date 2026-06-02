//
//  MITMRespondBuilder.swift
//  Anywhere
//
//  Created by NodePassProject on 6/1/26.
//

import Foundation

/// Builds the synthesized inner-leg response for the non-transparent
/// "Rewrite" sub-modes (302 redirect / 200 reject). Returns a
/// ``MITMScriptEngine/SynthesizedResponse`` — the same shape produced by
/// `Anywhere.respond` — so the HTTP/1 and HTTP/2 rewriters can reuse their
/// existing `queueSynthesizedResponse` serializers. Those serializers add the
/// status line and a body-matching `Content-Length`, so this only supplies the
/// status, the one distinguishing header, and the body.
///
/// 302 / reject sub-modes are gated per-rule by `urlPattern` and synthesized
/// inline in the rewriter pipeline, so a synthesized reply needs no upstream
/// connection.
enum MITMRespondBuilder {

    /// The synthesized response for a synthesize sub-mode, or nil for
    /// ``CompiledRewriteAction/transparent`` (which is proxied upstream, not
    /// synthesized).
    static func response(for action: CompiledRewriteAction) -> MITMScriptEngine.SynthesizedResponse? {
        switch action {
        case .transparent:
            return nil
        case .redirect302(let location):
            return MITMScriptEngine.SynthesizedResponse(
                status: 302,
                headers: [(name: "Location", value: location)],
                body: Data()
            )
        case .reject200Text(let content):
            let text = content.isEmpty ? defaultText : content
            return MITMScriptEngine.SynthesizedResponse(
                status: 200,
                headers: [(name: "Content-Type", value: "text/plain; charset=utf-8")],
                body: Data(text.utf8)
            )
        case .reject200Gif:
            return MITMScriptEngine.SynthesizedResponse(
                status: 200,
                headers: [(name: "Content-Type", value: "image/gif")],
                body: tinyGIF
            )
        case .reject200Data(let base64):
            let source = base64.isEmpty ? defaultDataBase64 : base64
            let body = Data(base64Encoded: source) ?? Data()
            return MITMScriptEngine.SynthesizedResponse(
                status: 200,
                headers: [(name: "Content-Type", value: "application/octet-stream")],
                body: body
            )
        }
    }

    /// Default body for ``CompiledRewriteAction/reject200Text`` when the user
    /// left it blank — kept non-empty so a client never treats a zero-length
    /// 200 as an error.
    private static let defaultText = "Success from Anywhere"

    /// Default body for ``CompiledRewriteAction/reject200Data`` when blank:
    /// base64 for the literal "Anywhere".
    private static let defaultDataBase64 = "QW55d2hlcmU="

    /// 43-byte 1×1 transparent GIF89a — the canonical "tracking pixel"
    /// payload used to satisfy image requests with no visible content.
    static let tinyGIF = Data([
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x01,
        0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02,
        0x4C, 0x01, 0x00, 0x3B
    ])
}
