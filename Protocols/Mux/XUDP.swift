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
    /// Matching Xray-core xudp.go:38: rand.Read(BaseKey)
    private static let baseKey: [UInt8] = {
        var key = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &key)
        return key
    }()

    /// Generate 8-byte GlobalID from source address using blake3 keyed hash.
    /// Matching Xray-core xudp.go:55-57:
    ///   h := blake3.New(8, BaseKey)
    ///   h.Write([]byte(inbound.Source.String()))
    /// The source string format is "udp:host:port" matching Xray-core's
    /// net.Destination.String() for UDP sources.
    static func generateGlobalID(sourceAddress: String) -> Data {
        #if NETWORK_EXTENSION
        var hasher = blake3_hasher()
        baseKey.withUnsafeBufferPointer { keyPtr in
            blake3_hasher_init_keyed(&hasher, keyPtr.baseAddress!)
        }
        let sourceBytes = Array(sourceAddress.utf8)
        sourceBytes.withUnsafeBufferPointer { srcPtr in
            blake3_hasher_update(&hasher, srcPtr.baseAddress!, sourceBytes.count)
        }
        var output = [UInt8](repeating: 0, count: 8)
        blake3_hasher_finalize(&hasher, &output, 8)
        return Data(output)
        #else
        // Fallback: SHA256-based GlobalID for main app (not used in practice)
        let sourceBytes = Array(sourceAddress.utf8)
        var output = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, 8, &output)
        return Data(output)
        #endif
    }
}
