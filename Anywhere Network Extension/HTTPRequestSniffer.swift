//
//  HTTPRequestSniffer.swift
//  Anywhere
//
//  Created by NodePassProject on 6/21/26.
//

import Foundation

struct HTTPRequestSniffer {

    enum State: Equatable {
        case needMore
        /// Not a well-formed HTTP/1.x request (or the head exceeded the cap).
        case notHTTP
        /// Parsed head. `authority` is the lowercased host (no port/userinfo) from the
        /// request-target or `Host` header; nil if neither is present.
        case found(authority: String?)
    }

    private let bufferLimit: Int
    private var buffer = [UInt8]()
    private(set) var state: State = .needMore

    init(bufferLimit: Int = TunnelConstants.httpSnifferBufferLimit) {
        self.bufferLimit = bufferLimit
    }
    
    mutating func feed(_ data: Data) -> State {
        guard state == .needMore, !data.isEmpty else { return state }
        
        if buffer.isEmpty, !Self.isMethodStartByte(data[data.startIndex]) {
            state = .notHTTP
            return state
        }

        buffer.append(contentsOf: data)
        if buffer.count > bufferLimit {
            state = .notHTTP
            return state
        }

        state = parse()
        return state
    }

    // MARK: - Parsing

    private func parse() -> State {
        guard let lineEnd = indexOfCRLF(from: 0) else { return .needMore }
        guard let request = Self.parseRequestLine(Self.decodeLine(buffer[0..<lineEnd])) else {
            return .notHTTP
        }

        switch request.target {
        case .authorityForm:
            // CONNECT sets up a tunnel with no rewritable body — leave it to plain proxying.
            return .notHTTP
        case .absolute(let authority):
            return .found(authority: Self.normalizeAuthorityHost(authority))
        case .originOrAsterisk:
            // No authority in the request line — the host is in the `Host` header, so we need the full head.
            guard let headEnd = indexOfDoubleCRLF() else { return .needMore }
            let host = hostHeader(from: lineEnd + 2, to: headEnd)
            return .found(authority: host.flatMap(Self.normalizeAuthorityHost))
        }
    }

    // MARK: - Request line

    private enum TargetForm: Equatable {
        case originOrAsterisk
        case absolute(authority: String)
        case authorityForm
    }

    private struct ParsedRequestLine {
        let method: String
        let target: TargetForm
    }

    /// Validates `METHOD SP request-target SP HTTP/1.(0|1)` and classifies the request-target form.
    private static func parseRequestLine(_ line: String) -> ParsedRequestLine? {
        let version: String
        if line.hasSuffix(" HTTP/1.1") {
            version = " HTTP/1.1"
        } else if line.hasSuffix(" HTTP/1.0") {
            version = " HTTP/1.0"
        } else {
            return nil
        }
        let head = line.dropLast(version.count)
        guard let firstSpace = head.firstIndex(of: " ") else { return nil }
        let method = String(head[head.startIndex..<firstSpace])
        let target = String(head[head.index(after: firstSpace)...])
        guard HTTPHeader.isValidName(method), !target.isEmpty, !target.contains(" ") else {
            return nil
        }

        if method == "CONNECT" {
            return ParsedRequestLine(method: method, target: .authorityForm)
        }
        if target == "*" || target.hasPrefix("/") {
            return ParsedRequestLine(method: method, target: .originOrAsterisk)
        }
        // absolute-form: take the authority between "://" and the first "/".
        if let schemeRange = target.range(of: "://") {
            let afterScheme = target[schemeRange.upperBound...]
            let authority = afterScheme.prefix { $0 != "/" }
            guard !authority.isEmpty else { return nil }
            return ParsedRequestLine(method: method, target: .absolute(authority: String(authority)))
        }
        return nil
    }

    /// Reduces an `authority` (`[userinfo@]host[:port]`) to a bare lowercased host suitable for
    /// policy matching. IPv6 literals keep their bracket-stripped form.
    private static func normalizeAuthorityHost(_ authority: String) -> String? {
        var value = Substring(authority)
        if let at = value.lastIndex(of: "@") {
            value = value[value.index(after: at)...]
        }
        guard !value.isEmpty else { return nil }
        // IPv6 literal: [::1]:port — host is inside the brackets (handled before the ":port" strip).
        if value.first == "[" {
            guard let close = value.firstIndex(of: "]") else { return nil }
            let host = value[value.index(after: value.startIndex)..<close]
            return host.isEmpty ? nil : host.lowercased()
        }
        if let colon = value.firstIndex(of: ":") {
            value = value[value.startIndex..<colon]
        }
        return value.isEmpty ? nil : value.lowercased()
    }

    // MARK: - Headers

    /// Returns the first `Host` header value in the head region `[start, end)`.
    private func hostHeader(from start: Int, to end: Int) -> String? {
        var cursor = start
        while cursor < end {
            guard let lineEnd = indexOfCRLF(from: cursor), lineEnd <= end else { break }
            defer { cursor = lineEnd + 2 }
            if lineEnd == cursor { break } // blank line: end of head
            let line = Self.decodeLine(buffer[cursor..<lineEnd])
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colon]
            guard ASCII.equalsIgnoringCase(String(name), "host") else { continue }
            let value = line[line.index(after: colon)...]
                .trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
        return nil
    }

    // MARK: - Byte helpers

    /// RFC 9110 §9.1 method tokens are `tchar`; in practice every method begins with an ASCII letter.
    private static func isMethodStartByte(_ byte: UInt8) -> Bool {
        (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }

    /// Index of the first byte of the next CRLF at or after `from`, or nil.
    private func indexOfCRLF(from: Int) -> Int? {
        guard from >= 0, buffer.count >= 2 else { return nil }
        var i = from
        while i + 1 < buffer.count {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A { return i }
            i += 1
        }
        return nil
    }

    /// Index of the first byte of the CRLF that terminates the head (the empty line).
    private func indexOfDoubleCRLF() -> Int? {
        guard buffer.count >= 4 else { return nil }
        var i = 0
        while i + 3 < buffer.count {
            if buffer[i] == 0x0D, buffer[i + 1] == 0x0A,
               buffer[i + 2] == 0x0D, buffer[i + 3] == 0x0A {
                return i + 2
            }
            i += 1
        }
        return nil
    }
    
    private static func decodeLine(_ bytes: ArraySlice<UInt8>) -> String {
        String(bytes.map { Character(UnicodeScalar($0)) })
    }
}
