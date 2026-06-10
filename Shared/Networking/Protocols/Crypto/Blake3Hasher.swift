//
//  Blake3Hasher.swift
//  Network Extension
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation
import BLAKE3

struct Blake3Hasher {
    private var hasher: BLAKE3Hasher

    init() {
        hasher = BLAKE3Hasher()
    }

    /// Initialize for keyed hashing with a 32-byte key.
    init(key: [UInt8]) {
        hasher = BLAKE3Hasher(key: key)
    }

    init(deriveKeyContext context: String) {
        hasher = BLAKE3Hasher(derivingKeyFromContext: context)
    }

    /// Use when the context contains binary data that isn't valid UTF-8 — the String overload would mangle it.
    init(deriveKeyContextBytes context: Data) {
        hasher = BLAKE3Hasher(derivingKeyFromContextBytes: Array(context))
    }

    mutating func update(_ data: Data) {
        hasher.update(Array(data))
    }

    mutating func update(_ bytes: [UInt8]) {
        hasher.update(bytes)
    }

    mutating func finalizeData(count: Int = 32) -> Data {
        Data(hasher.finalize(outputLength: count))
    }

    // MARK: - Convenience

    static func hash(_ data: Data, count: Int = 32) -> Data {
        var h = Blake3Hasher()
        h.update(data)
        return h.finalizeData(count: count)
    }

    static func deriveKey(context: String, input: Data, count: Int = 32) -> Data {
        var h = Blake3Hasher(deriveKeyContext: context)
        h.update(input)
        return h.finalizeData(count: count)
    }

    static func deriveKey(contextBytes: Data, input: Data, count: Int = 32) -> Data {
        var h = Blake3Hasher(deriveKeyContextBytes: contextBytes)
        h.update(input)
        return h.finalizeData(count: count)
    }
}
