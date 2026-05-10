//
//  Blake3Hasher.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation
import BLAKE3

/// Swift wrapper around the BLAKE3 hash library.
struct Blake3Hasher {
    private var hasher: BLAKE3Hasher

    /// Initialize for plain hashing.
    init() {
        hasher = BLAKE3Hasher()
    }

    /// Initialize for keyed hashing with a 32-byte key.
    init(key: [UInt8]) {
        precondition(key.count == 32)
        hasher = BLAKE3Hasher(key: key)
    }

    /// Initialize for key derivation with a context string.
    init(deriveKeyContext context: String) {
        hasher = BLAKE3Hasher(derivingKeyFromContext: context)
    }

    /// Initialize for key derivation with raw context bytes.
    /// Use this when the context contains binary data (random IVs, public keys,
    /// etc.) that isn't valid UTF-8 — the String overload would mangle it.
    init(deriveKeyContextBytes context: Data) {
        hasher = BLAKE3Hasher(derivingKeyFromContextBytes: Array(context))
    }

    /// Feed input data into the hasher.
    mutating func update(_ data: Data) {
        hasher.update(Array(data))
    }

    /// Feed input bytes into the hasher.
    mutating func update(_ bytes: [UInt8]) {
        hasher.update(bytes)
    }

    /// Finalize and return the hash output as Data.
    mutating func finalizeData(count: Int = 32) -> Data {
        Data(hasher.finalize(outputLength: count))
    }

    // MARK: - Convenience

    /// Compute a plain BLAKE3 hash of the given data.
    static func hash(_ data: Data, count: Int = 32) -> Data {
        var h = Blake3Hasher()
        h.update(data)
        return h.finalizeData(count: count)
    }

    /// Derive a key using BLAKE3 key derivation mode.
    static func deriveKey(context: String, input: Data, count: Int = 32) -> Data {
        var h = Blake3Hasher(deriveKeyContext: context)
        h.update(input)
        return h.finalizeData(count: count)
    }

    /// Derive a key using BLAKE3 key derivation mode with binary context bytes.
    static func deriveKey(contextBytes: Data, input: Data, count: Int = 32) -> Data {
        var h = Blake3Hasher(deriveKeyContextBytes: contextBytes)
        h.update(input)
        return h.finalizeData(count: count)
    }
}
