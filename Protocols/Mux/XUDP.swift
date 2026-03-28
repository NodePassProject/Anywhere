//
//  XUDP.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import Security

enum XUDP {
    /// Random 32-byte key, generated once per process lifetime.
    private static let baseKey: [UInt8] = {
        var key = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &key)
        return key
    }()

    /// Generate 8-byte GlobalID from source address using blake3 keyed hash.
    /// The source string format is "udp:host:port"
    static func generateGlobalID(sourceAddress: String) -> Data {
        var hasher = Blake3Hasher(key: baseKey)
        hasher.update(Array(sourceAddress.utf8))
        return hasher.finalizeData(count: 8)
    }
}
