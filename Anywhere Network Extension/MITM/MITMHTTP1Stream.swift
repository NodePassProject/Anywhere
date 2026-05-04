//
//  MITMHTTP1Stream.swift
//  Anywhere
//
//  Created by Argsment Limited on 5/4/26.
//

import Foundation

private let logger = AnywhereLogger(category: "MITM")

/// One direction of an HTTP/1.x byte stream traversing the MITM. Owns
/// the message-framing state machine (parse head -> forward or rewrite
/// body -> next message) and the chunked-encoding decoder. The caller
/// passes raw plaintext bytes via ``transform(_:)`` and receives the
/// rewritten plaintext for the opposite TLS leg.
///
/// One instance per direction. ``MITMSession`` constructs two of them
/// (request, response). They share ``policy`` but never share state.
///
/// If the stream cannot be parsed safely, it permanently downgrades to
/// passthrough so the underlying connection stays usable even when MITM
/// rewrites cannot apply.
final class MITMHTTP1Stream {

    private let host: String
    private let phase: MITMPhase
    private let policy: MITMRewritePolicy
    /// When set, every request's `Host:` header is rewritten to this value
    /// so the upstream sees a consistent authority. Driven by the rule set's
    /// ``rewriteTarget``; nil means "leave Host alone". Used only on request
    /// streams; response streams pass nil.
    private let effectiveAuthority: String?

    init(
        host: String,
        phase: MITMPhase,
        policy: MITMRewritePolicy,
        effectiveAuthority: String?
    ) {
        self.host = host
        self.phase = phase
        self.policy = policy
        self.effectiveAuthority = effectiveAuthority
    }

    // MARK: - State

    private enum Mode {
        /// Buffering the next message's head. The accumulator lives in
        /// ``rxBuffer`` until CRLF CRLF is seen.
        case awaitingHead

        /// Header rewrite already emitted; pass body bytes through
        /// unchanged. Used when no bodyReplace rule applies, or when the
        /// body is opaque-encoded.
        case forwardingLength(remaining: Int)
        case forwardingChunked(reader: ChunkedReader)

        /// Buffering the body to rewrite it. The head is emitted only once
        /// the body completes, so Content-Length or chunk framing can be
        /// updated before sending.
        case rewritingLength(headBytes: Data, expected: Int, accumulator: Data)
        case rewritingChunked(headBytes: Data, accumulator: Data, reader: ChunkedReader)

        /// Permanent: forward bytes verbatim. Reached on protocol
        /// upgrades (101), CONNECT-style tunnels, or any framing error.
        case passthrough
    }

    private var mode: Mode = .awaitingHead
    private var rxBuffer = Data()

    // MARK: - Public API

    func transform(_ data: Data) -> Data {
        if case .passthrough = mode {
            return data
        }
        rxBuffer.append(data)
        var output = Data()
        // Each iteration consumes from rxBuffer or returns when more
        // bytes are needed.
        while drive(into: &output) { }
        return output
    }

    // MARK: - Driver

    /// Returns true when state advanced and the loop should run again.
    private func drive(into output: inout Data) -> Bool {
        // Modes with mutable associated state are written back before inout
        // calls to avoid overlapping access to ``mode``.
        switch mode {
        case .passthrough:
            output.append(rxBuffer)
            rxBuffer.removeAll(keepingCapacity: false)
            return false

        case .awaitingHead:
            return consumeHead(into: &output)

        case .forwardingLength(let remaining):
            return forwardLength(remaining: remaining, into: &output)

        case .forwardingChunked(var reader):
            mode = .forwardingChunked(reader: reader)
            return forwardChunked(reader: &reader, into: &output)

        case .rewritingLength(let headBytes, let expected, var accumulator):
            mode = .rewritingLength(headBytes: headBytes, expected: expected, accumulator: accumulator)
            return rewriteLength(headBytes: headBytes, expected: expected, accumulator: &accumulator, into: &output)

        case .rewritingChunked(let headBytes, var accumulator, var reader):
            mode = .rewritingChunked(headBytes: headBytes, accumulator: accumulator, reader: reader)
            return rewriteChunked(headBytes: headBytes, accumulator: &accumulator, reader: &reader, into: &output)
        }
    }

    // MARK: - Head consumption

    /// Finds CRLF CRLF in ``rxBuffer``. When found, parses the head,
    /// applies header rewrites, decides on body framing, and either:
    ///   - emits the rewritten head and switches to forwarding mode, or
    ///   - withholds the head (saved in mode) and switches to rewrite
    ///     mode so Content-Length can be fixed after the body is rewritten.
    private func consumeHead(into output: inout Data) -> Bool {
        guard let terminator = rxBuffer.range(of: Data([0x0D, 0x0A, 0x0D, 0x0A])) else {
            return false
        }
        let headEnd = terminator.upperBound
        let headData = rxBuffer.subdata(in: rxBuffer.startIndex..<headEnd)
        rxBuffer.removeSubrange(rxBuffer.startIndex..<headEnd)

        guard let parsed = parseHead(headData) else {
            // If the head is not HTTP/1.x, stop rewriting and forward the
            // remaining bytes verbatim.
            mode = .passthrough
            output.append(headData)
            return true
        }

        // Apply rewrite rules. URL rules touch the request-target on the
        // start line (request phase only); header rules touch the
        // header block. Content-Length is recomputed below when a body
        // rewrite is also in play.
        //
        // Auto Host rewrite runs first so configured headerReplace rules see
        // the canonical post-redirect Host and can still override it.
        let rewrittenStartLine = applyURLRules(parsed.startLine)
        let withAuthority = applyAuthorityRewrite(parsed.headers)
        let rewrittenHeaders = applyHeaderRules(withAuthority)
        let framing = bodyFraming(startLine: rewrittenStartLine, headers: rewrittenHeaders)

        // Special case: response with status 101 Switching Protocols, or
        // any "read until close" body. These cannot be re-framed reliably,
        // so emit the rewritten head and switch to permanent passthrough.
        switch framing {
        case .switchingProtocols, .readUntilClose:
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            mode = .passthrough
            return true
        case .none:
            output.append(serializeHead(startLine: rewrittenStartLine, headers: rewrittenHeaders))
            mode = .awaitingHead
            return true
        case .contentLength(let length):
            return enterContentLength(
                originalHeaders: parsed.headers,
                rewrittenHeaders: rewrittenHeaders,
                startLine: rewrittenStartLine,
                length: length,
                into: &output
            )
        case .chunked:
            return enterChunked(
                originalHeaders: parsed.headers,
                rewrittenHeaders: rewrittenHeaders,
                startLine: rewrittenStartLine,
                into: &output
            )
        }
    }

    private func enterContentLength(
        originalHeaders: [Header],
        rewrittenHeaders: [Header],
        startLine: String,
        length: Int,
        into output: inout Data
    ) -> Bool {
        if shouldRewriteBody(headers: originalHeaders) {
            // Withhold the head until the rewritten body length is known,
            // then patch Content-Length before emitting head + body.
            let headBytes = serializeHead(startLine: startLine, headers: rewrittenHeaders)
            mode = .rewritingLength(headBytes: headBytes, expected: length, accumulator: Data())
            return true
        }
        output.append(serializeHead(startLine: startLine, headers: rewrittenHeaders))
        mode = .forwardingLength(remaining: length)
        return true
    }

    private func enterChunked(
        originalHeaders: [Header],
        rewrittenHeaders: [Header],
        startLine: String,
        into output: inout Data
    ) -> Bool {
        if shouldRewriteBody(headers: originalHeaders) {
            let headBytes = serializeHead(startLine: startLine, headers: rewrittenHeaders)
            mode = .rewritingChunked(headBytes: headBytes, accumulator: Data(), reader: ChunkedReader())
            return true
        }
        output.append(serializeHead(startLine: startLine, headers: rewrittenHeaders))
        mode = .forwardingChunked(reader: ChunkedReader())
        return true
    }

    // MARK: - Body forwarding (no rewrite)

    private func forwardLength(remaining: Int, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let take = min(remaining, rxBuffer.count)
        let slice = rxBuffer.prefix(take)
        output.append(slice)
        rxBuffer.removeFirst(take)
        let left = remaining - take
        if left == 0 {
            mode = .awaitingHead
        } else {
            mode = .forwardingLength(remaining: left)
        }
        return true
    }

    private func forwardChunked(reader: inout ChunkedReader, into output: inout Data) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let result = reader.consumeForward(&rxBuffer, into: &output)
        switch result {
        case .needMore:
            mode = .forwardingChunked(reader: reader)
            return false
        case .complete:
            mode = .awaitingHead
            return true
        case .malformed:
            // Forward remaining bytes verbatim; the peer will detect the
            // framing error.
            mode = .passthrough
            return true
        }
    }

    // MARK: - Body rewriting

    private func rewriteLength(
        headBytes: Data,
        expected: Int,
        accumulator: inout Data,
        into output: inout Data
    ) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let needed = expected - accumulator.count
        let take = min(needed, rxBuffer.count)
        accumulator.append(rxBuffer.prefix(take))
        rxBuffer.removeFirst(take)
        if accumulator.count == expected {
            let rewrittenBody = applyBodyRules(accumulator)
            let patchedHead = patchContentLength(in: headBytes, to: rewrittenBody.count)
            output.append(patchedHead)
            output.append(rewrittenBody)
            mode = .awaitingHead
            return true
        }
        mode = .rewritingLength(headBytes: headBytes, expected: expected, accumulator: accumulator)
        return false
    }

    private func rewriteChunked(
        headBytes: Data,
        accumulator: inout Data,
        reader: inout ChunkedReader,
        into output: inout Data
    ) -> Bool {
        guard !rxBuffer.isEmpty else { return false }
        let result = reader.consumeBuffered(&rxBuffer, into: &accumulator)
        switch result {
        case .needMore:
            mode = .rewritingChunked(headBytes: headBytes, accumulator: accumulator, reader: reader)
            return false
        case .complete(let originalSizes):
            let rewrittenBody = applyBodyRules(accumulator)
            output.append(headBytes)
            output.append(rechunk(body: rewrittenBody, originalSizes: originalSizes))
            mode = .awaitingHead
            return true
        case .malformed:
            mode = .passthrough
            return true
        }
    }

    // MARK: - Re-chunking

    /// Re-emits ``body`` as chunked-transfer-encoding using
    /// ``originalSizes`` as chunk-size targets. All but the last emitted
    /// chunk keep their original sizes; the last chunk absorbs any size
    /// delta. If the rewritten body is shorter than the prefix, emit fewer
    /// chunks. Always terminates with a zero-size chunk and empty trailers.
    private func rechunk(body: Data, originalSizes: [Int]) -> Data {
        var out = Data()
        var emitted = 0
        let total = body.count

        if originalSizes.count > 1 {
            for size in originalSizes.dropLast() {
                guard emitted < total else { break }
                let take = min(size, total - emitted)
                appendChunk(body.subdata(in: (body.startIndex + emitted)..<(body.startIndex + emitted + take)), into: &out)
                emitted += take
            }
        }
        if emitted < total || originalSizes.count == 1 {
            let remaining = total - emitted
            if remaining > 0 {
                appendChunk(body.subdata(in: (body.startIndex + emitted)..<body.endIndex), into: &out)
            }
        }
        // Final zero-size chunk and empty trailers.
        out.append(contentsOf: "0\r\n\r\n".utf8)
        return out
    }

    private func appendChunk(_ data: Data, into out: inout Data) {
        out.append(contentsOf: String(data.count, radix: 16).utf8)
        out.append(0x0D); out.append(0x0A)
        out.append(data)
        out.append(0x0D); out.append(0x0A)
    }

    // MARK: - Head parsing

    private typealias Header = (name: String, value: String)

    private struct ParsedHead {
        let startLine: String
        let headers: [Header]
    }

    private func parseHead(_ data: Data) -> ParsedHead? {
        guard let raw = String(data: data, encoding: .ascii) else { return nil }
        let lines = raw.components(separatedBy: "\r\n")
        guard let startLine = lines.first, !startLine.isEmpty else { return nil }
        guard isHTTPStartLine(startLine) else { return nil }
        var headers: [Header] = []
        for line in lines.dropFirst() {
            if line.isEmpty { continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon])
            let value = String(line[line.index(after: colon)...])
                .trimmingCharacters(in: CharacterSet.whitespaces)
            headers.append((name: name, value: value))
        }
        return ParsedHead(startLine: startLine, headers: headers)
    }

    private func isHTTPStartLine(_ line: String) -> Bool {
        // Request: METHOD SP path SP HTTP/1.x
        // Response: HTTP/1.x SP status SP reason
        if line.hasPrefix("HTTP/1.") { return true }
        return line.hasSuffix(" HTTP/1.1") || line.hasSuffix(" HTTP/1.0")
    }

    private func serializeHead(startLine: String, headers: [Header]) -> Data {
        var out = Data()
        out.append(contentsOf: startLine.utf8)
        out.append(0x0D); out.append(0x0A)
        for (name, value) in headers {
            out.append(contentsOf: name.utf8)
            out.append(0x3A); out.append(0x20) // ": "
            out.append(contentsOf: value.utf8)
            out.append(0x0D); out.append(0x0A)
        }
        out.append(0x0D); out.append(0x0A)
        return out
    }

    private func patchContentLength(in head: Data, to newLength: Int) -> Data {
        // Re-walk the head, swapping any existing Content-Length values
        // for the rewritten size. If absent, append before the trailing
        // CRLF CRLF.
        guard let raw = String(data: head, encoding: .ascii) else {
            return head
        }
        var lines = raw.components(separatedBy: "\r\n")
        var found = false
        for i in lines.indices {
            let line = lines[i]
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].lowercased()
            if name == "content-length" {
                lines[i] = "Content-Length: \(newLength)"
                found = true
            }
        }
        if !found {
            // Insert before the empty terminator line.
            if let emptyIdx = lines.firstIndex(where: { $0.isEmpty }) {
                lines.insert("Content-Length: \(newLength)", at: emptyIdx)
            } else {
                lines.append("Content-Length: \(newLength)")
                lines.append("")
            }
        }
        return Data(lines.joined(separator: "\r\n").utf8)
    }

    // MARK: - Framing decision

    private enum Framing {
        case none
        case contentLength(Int)
        case chunked
        case readUntilClose
        case switchingProtocols
    }

    private func bodyFraming(startLine: String, headers: [Header]) -> Framing {
        if phase == .httpResponse {
            // Status line: "HTTP/1.x SSS Reason"
            let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
            if parts.count >= 2, let status = Int(parts[1]) {
                if status == 101 { return .switchingProtocols }
                if status == 204 || status == 304 { return .none }
                if status >= 100 && status < 200 { return .none }
            }
        }
        for (name, value) in headers where name.lowercased() == "transfer-encoding" {
            if value.lowercased().contains("chunked") {
                return .chunked
            }
        }
        for (name, value) in headers where name.lowercased() == "content-length" {
            let trimmed = value.trimmingCharacters(in: CharacterSet.whitespaces)
            if let length = Int(trimmed), length >= 0 {
                return length == 0 ? .none : .contentLength(length)
            }
        }
        return phase == .httpRequest ? .none : .readUntilClose
    }

    // MARK: - Body rewrite gate

    private func shouldRewriteBody(headers: [Header]) -> Bool {
        let rules = policy.rules(for: host, phase: phase)
        let hasBodyRule = rules.contains {
            if case .bodyReplace = $0.operation { return true }
            return false
        }
        guard hasBodyRule else { return false }
        for (name, value) in headers where name.lowercased() == "content-encoding" {
            let trimmed = value.trimmingCharacters(in: CharacterSet.whitespaces).lowercased()
            if trimmed.isEmpty || trimmed == "identity" { continue }
            return false
        }
        return true
    }

    // MARK: - Rule application

    /// When the rule set declares a ``rewriteTarget``, the request's Host
    /// header is forced to the target authority so redirected requests use
    /// an authority the upstream can route.
    private func applyAuthorityRewrite(_ headers: [Header]) -> [Header] {
        guard phase == .httpRequest, let authority = effectiveAuthority else {
            return headers
        }
        var result = headers.filter { $0.name.lowercased() != "host" }
        result.append((name: "Host", value: authority))
        return result
    }

    /// Rewrites the request-target on the start line via any
    /// ``urlReplace`` rules. Request phase only; no-op on responses,
    /// asterisk-form (`OPTIONS *`), or unparseable lines. The regex applies
    /// to the path-and-query, not the method or HTTP-version.
    private func applyURLRules(_ startLine: String) -> String {
        guard phase == .httpRequest else { return startLine }
        let rules = policy.rules(for: host, phase: phase)
        guard rules.contains(where: {
            if case .urlReplace = $0.operation { return true }
            return false
        }) else { return startLine }

        // Request-line shape: METHOD SP request-target SP HTTP-version.
        let parts = startLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count == 3 else { return startLine }
        let method = String(parts[0])
        var target = String(parts[1])
        let version = String(parts[2])

        // Asterisk-form (RFC 9112 section 3.2.4) is reserved for
        // OPTIONS * and is not a meaningful target for URL rewrites.
        if target == "*" { return startLine }

        var changed = false
        for rule in rules {
            guard case .urlReplace(let regex, let replacement) = rule.operation else {
                continue
            }
            let range = NSRange(target.startIndex..., in: target)
            let mutated = regex.stringByReplacingMatches(
                in: target,
                options: [],
                range: range,
                withTemplate: replacement
            )
            if mutated != target {
                target = mutated
                changed = true
            }
        }
        return changed ? "\(method) \(target) \(version)" : startLine
    }

    private func applyHeaderRules(_ headers: [Header]) -> [Header] {
        let rules = policy.rules(for: host, phase: phase)
        guard !rules.isEmpty else { return headers }
        var current = headers
        for rule in rules {
            switch rule.operation {
            case .headerAdd(let name, let value):
                current.append((name: name, value: value))
            case .headerDelete(let nameLower):
                current.removeAll { $0.name.lowercased() == nameLower }
            case .headerReplace(let regex, let name, let value):
                current = current.map { entry in
                    let literal = "\(entry.name): \(entry.value)"
                    let range = NSRange(literal.startIndex..., in: literal)
                    guard regex.firstMatch(in: literal, options: [], range: range) != nil else {
                        return entry
                    }
                    let rewritten = regex.stringByReplacingMatches(
                        in: literal,
                        options: [],
                        range: range,
                        withTemplate: "\(name): \(value)"
                    )
                    return (name: name, value: value)
                }
            case .urlReplace, .bodyReplace:
                continue
            }
        }
        return current
    }

    private func applyBodyRules(_ data: Data) -> Data {
        let rules = policy.rules(for: host, phase: phase)
        var bodyString = String(decoding: data, as: UTF8.self)
        var changed = false
        for rule in rules {
            guard case .bodyReplace(let regex, let replacement) = rule.operation else {
                continue
            }
            let range = NSRange(bodyString.startIndex..., in: bodyString)
            let mutated = regex.stringByReplacingMatches(
                in: bodyString,
                options: [],
                range: range,
                withTemplate: replacement
            )
            if mutated != bodyString {
                bodyString = mutated
                changed = true
            }
        }
        return changed ? Data(bodyString.utf8) : data
    }
}

// MARK: - ChunkedReader

/// Streaming chunked-transfer decoder. Used in two modes:
///
///   - ``consumeForward(_:into:)``: pass-through. Bytes consumed from
///     ``buffer`` are appended verbatim to ``output``; framing is tracked
///     to know when the message ends.
///   - ``consumeBuffered(_:into:)``: rewrite. Decoded chunk data is
///     appended to ``output`` (the body accumulator); on
///     completion the original chunk sizes are returned for re-chunking.
///
/// Either method drains ``buffer`` from the front. They do not mix on
/// the same instance; ``MITMHTTP1Stream`` chooses one mode per body.
private final class ChunkedReader {
    private enum State {
        case sizeLine
        case chunkData(remaining: Int, originalSize: Int)
        case dataCRLF(originalSize: Int)
        case trailerOrEnd
    }

    private var state: State = .sizeLine
    private var sizes: [Int] = []

    enum ForwardResult {
        case needMore
        case complete
        case malformed
    }

    enum BufferedResult {
        case needMore
        case complete(sizes: [Int])
        case malformed
    }

    func consumeForward(_ buffer: inout Data, into output: inout Data) -> ForwardResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                guard let size = parseHexSize(line) else { return .malformed }
                if size == 0 {
                    state = .trailerOrEnd
                } else {
                    state = .chunkData(remaining: size, originalSize: size)
                }
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                output.append(buffer.prefix(take))
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF(let originalSize):
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[buffer.startIndex] == 0x0D, buffer[buffer.startIndex + 1] == 0x0A else {
                    return .malformed
                }
                output.append(0x0D); output.append(0x0A)
                buffer.removeFirst(2)
                sizes.append(originalSize)
                state = .sizeLine
            case .trailerOrEnd:
                // Forward the trailer block (zero or more lines + CRLF)
                // verbatim until the empty-line terminator.
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                output.append(line)
                output.append(0x0D); output.append(0x0A)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                if line.isEmpty {
                    return .complete
                }
            }
        }
        return .needMore
    }

    func consumeBuffered(_ buffer: inout Data, into output: inout Data) -> BufferedResult {
        while !buffer.isEmpty {
            switch state {
            case .sizeLine:
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                guard let size = parseHexSize(line) else { return .malformed }
                if size == 0 {
                    state = .trailerOrEnd
                } else {
                    state = .chunkData(remaining: size, originalSize: size)
                }
            case .chunkData(let remaining, let originalSize):
                let take = min(remaining, buffer.count)
                output.append(buffer.prefix(take))
                buffer.removeFirst(take)
                let left = remaining - take
                if left == 0 {
                    state = .dataCRLF(originalSize: originalSize)
                } else {
                    state = .chunkData(remaining: left, originalSize: originalSize)
                    return .needMore
                }
            case .dataCRLF(let originalSize):
                guard buffer.count >= 2 else { return .needMore }
                guard buffer[buffer.startIndex] == 0x0D, buffer[buffer.startIndex + 1] == 0x0A else {
                    return .malformed
                }
                buffer.removeFirst(2)
                sizes.append(originalSize)
                state = .sizeLine
            case .trailerOrEnd:
                // Rewritten bodies are re-chunked with empty trailers, so
                // consume and discard any original trailers here.
                guard let lineEnd = findCRLF(in: buffer) else { return .needMore }
                let line = buffer.subdata(in: buffer.startIndex..<lineEnd)
                buffer.removeSubrange(buffer.startIndex..<(lineEnd + 2))
                if line.isEmpty {
                    return .complete(sizes: sizes)
                }
            }
        }
        return .needMore
    }

    private func findCRLF(in buffer: Data) -> Int? {
        guard buffer.count >= 2 else { return nil }
        var i = buffer.startIndex
        while i < buffer.endIndex - 1 {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A {
                return i
            }
            i += 1
        }
        return nil
    }

    private func parseHexSize(_ data: Data) -> Int? {
        guard let raw = String(data: data, encoding: .ascii) else { return nil }
        // "size" or "size;ext..."; only the leading hex is needed.
        let head = raw.split(separator: ";", maxSplits: 1).first.map(String.init) ?? raw
        let trimmed = head.trimmingCharacters(in: CharacterSet.whitespaces)
        return Int(trimmed, radix: 16)
    }
}
