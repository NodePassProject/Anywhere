//
//  Event.swift
//  YAML
//
//  Created by NodePassProject on 10/23/26.
//

enum CollectionStyle {
    case block
    case flow
}

struct VersionDirective: Equatable {
    let major: Int
    let minor: Int
}

struct TagDirective: Equatable {
    let handle: String
    let prefix: String
}

struct Event: Equatable {
    enum Kind: Equatable {
        case streamStart
        case streamEnd
        case documentStart(version: VersionDirective?, tagDirectives: [TagDirective], isImplicit: Bool)
        case documentEnd(isImplicit: Bool)
        case alias(anchor: String)
        case scalar(Scalar)
        case sequenceStart(CollectionStart)
        case sequenceEnd
        case mappingStart(CollectionStart)
        case mappingEnd
    }

    struct Scalar: Equatable {
        let value: String
        let anchor: String?
        let tag: String?
        let style: ScalarStyle
        let isPlainImplicit: Bool
        let isQuotedImplicit: Bool
    }

    struct CollectionStart: Equatable {
        let anchor: String?
        let tag: String?
        let isImplicit: Bool
        let style: CollectionStyle
    }

    let kind: Kind
    let startMark: Mark
    let endMark: Mark
}
