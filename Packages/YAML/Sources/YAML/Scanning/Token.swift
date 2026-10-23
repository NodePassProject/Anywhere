//
//  Token.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

enum ScalarStyle {
    case plain
    case singleQuoted
    case doubleQuoted
    case literal
    case folded
}

struct Token {
    enum Kind {
        case streamStart
        case streamEnd
        case versionDirective(major: Int, minor: Int)
        case tagDirective(handle: String, prefix: String)
        case documentStart
        case documentEnd
        case blockSequenceStart
        case blockMappingStart
        case blockEnd
        case flowSequenceStart
        case flowSequenceEnd
        case flowMappingStart
        case flowMappingEnd
        case blockEntry
        case flowEntry
        case key
        case value
        case alias(String)
        case anchor(String)
        case tag(handle: String, suffix: String)
        case scalar(String, style: ScalarStyle)
    }

    let kind: Kind
    let startMark: Mark
    let endMark: Mark
}
