//
//  BLAKE3+Flags.swift
//  BLAKE
//
//  Created by NodePassProject on 10/23/26.
//

extension BLAKE3 {
    struct Flags: OptionSet, Sendable {
        let rawValue: UInt32

        static let chunkStart = Flags(rawValue: 1 << 0)
        static let chunkEnd = Flags(rawValue: 1 << 1)
        static let parent = Flags(rawValue: 1 << 2)
        static let root = Flags(rawValue: 1 << 3)
        static let keyedHash = Flags(rawValue: 1 << 4)
        static let deriveKeyContext = Flags(rawValue: 1 << 5)
        static let deriveKeyMaterial = Flags(rawValue: 1 << 6)
    }
}
