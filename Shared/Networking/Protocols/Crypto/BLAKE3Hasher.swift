//
//  BLAKE3Hasher.swift
//  Anywhere
//
//  Created by NodePassProject on 3/8/26.
//

import Foundation

struct BLAKE3Hasher {
    private var state = blake3_hasher()

    init() {
        blake3_hasher_init(&state)
    }

    /// Initialize for keyed hashing with a 32-byte key.
    init(key: [UInt8]) {
        precondition(key.count == 32, "BLAKE3 keyed hashing requires a 32-byte key")
        blake3_hasher_init_keyed(&state, key)
    }

    init(deriveKeyContext context: String) {
        blake3_hasher_init_derive_key(&state, context)
    }

    /// Use when the context contains binary data that isn't valid UTF-8 — the String overload would mangle it.
    init(deriveKeyContextBytes context: Data) {
        context.withUnsafeBytes { raw in
            blake3_hasher_init_derive_key_raw(&state, raw.baseAddress, raw.count)
        }
    }

    mutating func update(_ data: Data) {
        guard !data.isEmpty else { return }
        data.withUnsafeBytes { raw in
            blake3_hasher_update(&state, raw.baseAddress, raw.count)
        }
    }

    mutating func update(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        bytes.withUnsafeBytes { raw in
            blake3_hasher_update(&state, raw.baseAddress, raw.count)
        }
    }

    func finalizeData(count: Int = 32) -> Data {
        var out = [UInt8](repeating: 0, count: count)
        withUnsafePointer(to: state) { statePtr in
            out.withUnsafeMutableBufferPointer { buffer in
                blake3_hasher_finalize(statePtr, buffer.baseAddress, count)
            }
        }
        return Data(out)
    }

    // MARK: - Convenience

    static func hash(_ data: Data, count: Int = 32) -> Data {
        var h = BLAKE3Hasher()
        h.update(data)
        return h.finalizeData(count: count)
    }

    static func deriveKey(context: String, input: Data, count: Int = 32) -> Data {
        var h = BLAKE3Hasher(deriveKeyContext: context)
        h.update(input)
        return h.finalizeData(count: count)
    }

    static func deriveKey(contextBytes: Data, input: Data, count: Int = 32) -> Data {
        var h = BLAKE3Hasher(deriveKeyContextBytes: contextBytes)
        h.update(input)
        return h.finalizeData(count: count)
    }
}
