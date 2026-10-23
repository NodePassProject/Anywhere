//
//  Scanner+NodeProperties.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

// MARK: - Anchors and aliases

extension Scanner {
    mutating func scanAnchor(isAlias: Bool) throws(YAMLError) -> Token {
        let startMark = mark
        skip()

        var name: [UInt8] = []
        while isWordCharacter() {
            read(into: &name)
        }
        let endMark = mark

        let terminators: [Unicode.Scalar] = ["?", ":", ",", "]", "}", "%", "@", "`"]
        guard !name.isEmpty, isWhitespaceOrEnd() || terminators.contains(where: { matches($0) }) else {
            throw error(
                "did not find expected alphabetic or numeric character",
                context: isAlias ? "while scanning an alias" : "while scanning an anchor",
                contextMark: startMark
            )
        }

        let value = String(decoding: name, as: UTF8.self)
        return Token(kind: isAlias ? .alias(value) : .anchor(value), startMark: startMark, endMark: endMark)
    }
}

// MARK: - Tags

extension Scanner {
    mutating func scanTag() throws(YAMLError) -> Token {
        let startMark = mark
        var handle: [UInt8]
        var suffix: [UInt8]

        if matches("<", at: 1) {
            handle = []
            skip()
            skip()
            suffix = try scanTagURI(isVerbatim: true, isDirective: false, startMark: startMark)
            guard matches(">") else {
                throw error("did not find the expected '>'", context: "while scanning a tag", contextMark: startMark)
            }
            skip()
        } else {
            let scannedHandle = try scanTagHandle(isDirective: false, startMark: startMark)
            if scannedHandle.count > 1 && scannedHandle.last == UInt8(ascii: "!") {
                handle = scannedHandle
                suffix = try scanTagURI(isVerbatim: false, isDirective: false, startMark: startMark)
            } else {
                suffix = try scanTagURI(isVerbatim: false, isDirective: false, head: scannedHandle, startMark: startMark)
                handle = [UInt8(ascii: "!")]
                if suffix.isEmpty {
                    swap(&handle, &suffix)
                }
            }
        }

        guard isWhitespaceOrEnd() || (flowLevel > 0 && matches(",")) else {
            throw error("did not find expected whitespace or line break", context: "while scanning a tag", contextMark: startMark)
        }

        let kind = Token.Kind.tag(
            handle: String(decoding: handle, as: UTF8.self),
            suffix: String(decoding: suffix, as: UTF8.self)
        )
        return Token(kind: kind, startMark: startMark, endMark: mark)
    }

    mutating func scanTagHandle(isDirective: Bool, startMark: Mark) throws(YAMLError) -> [UInt8] {
        guard matches("!") else {
            throw error(
                "did not find expected '!'",
                context: isDirective ? "while scanning a tag directive" : "while scanning a tag",
                contextMark: startMark
            )
        }

        var handle: [UInt8] = []
        read(into: &handle)
        while isWordCharacter() {
            read(into: &handle)
        }
        if matches("!") {
            read(into: &handle)
        } else if isDirective && handle != [UInt8(ascii: "!")] {
            throw error("did not find expected '!'", context: "while parsing a tag directive", contextMark: startMark)
        }
        return handle
    }

    mutating func scanTagURI(
        isVerbatim: Bool,
        isDirective: Bool,
        head: [UInt8] = [],
        startMark: Mark
    ) throws(YAMLError) -> [UInt8] {
        var uri = Array(head.dropFirst())
        var length = head.count

        while isTagURICharacter(isVerbatim: isVerbatim) {
            if matches("%") {
                try scanURIEscapes(isDirective: isDirective, startMark: startMark, into: &uri)
            } else {
                read(into: &uri)
            }
            length += 1
        }

        guard length > 0 else {
            throw error(
                "did not find expected tag URI",
                context: isDirective ? "while parsing a %TAG directive" : "while parsing a tag",
                contextMark: startMark
            )
        }
        return uri
    }

    private func isTagURICharacter(isVerbatim: Bool) -> Bool {
        if isWordCharacter() {
            return true
        }
        let punctuation: [Unicode.Scalar] = [";", "/", "?", ":", "@", "&", "=", "+", "$", ".", "%", "!", "~", "*", "'", "(", ")"]
        if punctuation.contains(where: { matches($0) }) {
            return true
        }
        return isVerbatim && (matches(",") || matches("[") || matches("]"))
    }

    private mutating func scanURIEscapes(isDirective: Bool, startMark: Mark, into uri: inout [UInt8]) throws(YAMLError) {
        let context = isDirective ? "while parsing a %TAG directive" : "while parsing a tag"
        var remainingLength = 0

        repeat {
            guard matches("%"), let high = hexDigitValue(at: 1), let low = hexDigitValue(at: 2) else {
                throw error("did not find URI escaped octet", context: context, contextMark: startMark)
            }
            let octet = UInt8(high << 4 | low)

            if remainingLength == 0 {
                remainingLength = Self.sequenceLength(leadingByte: octet)
                guard remainingLength > 0 else {
                    throw error("found an incorrect leading UTF-8 octet", context: context, contextMark: startMark)
                }
            } else if octet & 0xC0 != 0x80 {
                throw error("found an incorrect trailing UTF-8 octet", context: context, contextMark: startMark)
            }

            uri.append(octet)
            skip()
            skip()
            skip()
            remainingLength -= 1
        } while remainingLength > 0
    }
}
