//
//  BLAKE2bHasher.swift
//  Anywhere
//
//  Created by NodePassProject on 6/23/26.
//

import Foundation

struct BLAKE2bHasher {
    private var state = blake2b_state()
    private let outputLength: Int

    /// - Parameter outputLength: digest length in bytes (1...64).
    init(outputLength: Int = 32) {
        precondition((1...64).contains(outputLength), "BLAKE2b output length must be 1...64 bytes")
        self.outputLength = outputLength
        _ = blake2b_init(&state, outputLength)
    }

    mutating func update(_ bytes: [UInt8]) {
        guard !bytes.isEmpty else { return }
        bytes.withUnsafeBytes { raw in
            _ = blake2b_update(&state, raw.baseAddress, raw.count)
        }
    }

    mutating func update(_ data: Data) {
        guard !data.isEmpty else { return }
        data.withUnsafeBytes { raw in
            _ = blake2b_update(&state, raw.baseAddress, raw.count)
        }
    }
    
    func finalize() -> [UInt8] {
        var finalState = state
        var out = [UInt8](repeating: 0, count: outputLength)
        out.withUnsafeMutableBufferPointer { buffer in
            _ = blake2b_final(&finalState, buffer.baseAddress, outputLength)
        }
        return out
    }

    // MARK: - Convenience
    
    static func hash256(_ prefix: [UInt8], _ suffix: [UInt8]) -> [UInt8] {
        var hasher = BLAKE2bHasher(outputLength: 32)
        hasher.update(prefix)
        hasher.update(suffix)
        return hasher.finalize()
    }
}
