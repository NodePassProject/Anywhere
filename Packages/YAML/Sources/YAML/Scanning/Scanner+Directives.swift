//
//  Scanner+Directives.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

extension Scanner {
    mutating func scanDirective() throws(YAMLError) -> Token {
        let startMark = mark
        skip()

        let kind: Token.Kind
        switch try scanDirectiveName(startMark: startMark) {
        case "YAML":
            let version = try scanVersionDirectiveValue(startMark: startMark)
            kind = .versionDirective(major: version.major, minor: version.minor)
        case "TAG":
            let directive = try scanTagDirectiveValue(startMark: startMark)
            kind = .tagDirective(handle: directive.handle, prefix: directive.prefix)
        default:
            throw error("found unknown directive name", context: "while scanning a directive", contextMark: startMark)
        }
        let endMark = mark

        while isBlank() {
            skip()
        }
        if matches("#") {
            while !isBreakOrEnd() {
                skip()
            }
        }
        guard isBreakOrEnd() else {
            throw error(
                "did not find expected comment or line break",
                context: "while scanning a directive",
                contextMark: startMark
            )
        }
        skipLineBreak()

        return Token(kind: kind, startMark: startMark, endMark: endMark)
    }

    private mutating func scanDirectiveName(startMark: Mark) throws(YAMLError) -> String {
        var name: [UInt8] = []
        while isWordCharacter() {
            read(into: &name)
        }
        guard !name.isEmpty else {
            throw error("could not find expected directive name", context: "while scanning a directive", contextMark: startMark)
        }
        guard isWhitespaceOrEnd() else {
            throw error(
                "found unexpected non-alphabetical character",
                context: "while scanning a directive",
                contextMark: startMark
            )
        }
        return String(decoding: name, as: UTF8.self)
    }

    private mutating func scanVersionDirectiveValue(startMark: Mark) throws(YAMLError) -> (major: Int, minor: Int) {
        while isBlank() {
            skip()
        }
        let major = try scanVersionDirectiveNumber(startMark: startMark)
        guard matches(".") else {
            throw error(
                "did not find expected digit or '.' character",
                context: "while scanning a %YAML directive",
                contextMark: startMark
            )
        }
        skip()
        let minor = try scanVersionDirectiveNumber(startMark: startMark)
        return (major, minor)
    }

    private mutating func scanVersionDirectiveNumber(startMark: Mark) throws(YAMLError) -> Int {
        let maximumLength = 9
        var value = 0
        var length = 0
        while isDigit() {
            length += 1
            guard length <= maximumLength else {
                throw error("found extremely long version number", context: "while scanning a %YAML directive", contextMark: startMark)
            }
            value = value * 10 + Int(byte() - UInt8(ascii: "0"))
            skip()
        }
        guard length > 0 else {
            throw error("did not find expected version number", context: "while scanning a %YAML directive", contextMark: startMark)
        }
        return value
    }

    private mutating func scanTagDirectiveValue(startMark: Mark) throws(YAMLError) -> (handle: String, prefix: String) {
        while isBlank() {
            skip()
        }
        let handle = try scanTagHandle(isDirective: true, startMark: startMark)
        guard isBlank() else {
            throw error("did not find expected whitespace", context: "while scanning a %TAG directive", contextMark: startMark)
        }
        while isBlank() {
            skip()
        }
        let prefix = try scanTagURI(isVerbatim: true, isDirective: true, startMark: startMark)
        guard isWhitespaceOrEnd() else {
            throw error(
                "did not find expected whitespace or line break",
                context: "while scanning a %TAG directive",
                contextMark: startMark
            )
        }
        return (String(decoding: handle, as: UTF8.self), String(decoding: prefix, as: UTF8.self))
    }
}
