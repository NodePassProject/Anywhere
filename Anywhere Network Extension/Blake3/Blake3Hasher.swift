//
//  Blake3Hasher.swift
//  Network Extension
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation

/// Swift wrapper around the C BLAKE3 hash library.
struct Blake3Hasher {
    private var hasher = blake3_hasher()

    /// Initialize for plain hashing.
    init() {
        blake3_hasher_init(&hasher)
    }

    /// Initialize for keyed hashing with a 32-byte key.
    init(key: [UInt8]) {
        precondition(key.count == Int(BLAKE3_KEY_LEN))
        key.withUnsafeBufferPointer { keyPtr in
            blake3_hasher_init_keyed(&hasher, keyPtr.baseAddress!)
        }
    }

    /// Initialize for key derivation with a context string.
    init(deriveKeyContext context: String) {
        context.withCString { cStr in
            blake3_hasher_init_derive_key(&hasher, cStr)
        }
    }

    /// Feed input data into the hasher.
    mutating func update(_ data: Data) {
        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress else { return }
            blake3_hasher_update(&hasher, base, data.count)
        }
    }

    /// Feed input bytes into the hasher.
    mutating func update(_ bytes: [UInt8]) {
        bytes.withUnsafeBufferPointer { ptr in
            blake3_hasher_update(&hasher, ptr.baseAddress!, bytes.count)
        }
    }

    /// Finalize and return the hash output as Data.
    mutating func finalizeData(count: Int = Int(BLAKE3_OUT_LEN)) -> Data {
        var data = Data(count: count)
        data.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            blake3_hasher_finalize(&hasher, base, count)
        }
        return data
    }

    // MARK: - Convenience

    /// Compute a plain BLAKE3 hash of the given data.
    static func hash(_ data: Data, count: Int = Int(BLAKE3_OUT_LEN)) -> Data {
        var h = Blake3Hasher()
        h.update(data)
        return h.finalizeData(count: count)
    }

    /// Derive a key using BLAKE3 key derivation mode.
    static func deriveKey(context: String, input: Data, count: Int = Int(BLAKE3_OUT_LEN)) -> Data {
        var h = Blake3Hasher(deriveKeyContext: context)
        h.update(input)
        return h.finalizeData(count: count)
    }
}
