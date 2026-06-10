//
//  XUDP.swift
//  Anywhere
//
//  Created by NodePassProject on 3/1/26.
//

import Foundation
import Security

enum XUDP {
    private static let baseKey: [UInt8] = {
        var key = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &key)
        return key
    }()

    /// Source address format: "udp:host:port"
    static func generateGlobalID(sourceAddress: String) -> Data {
        var hasher = Blake3Hasher(key: baseKey)
        hasher.update(Array(sourceAddress.utf8))
        return hasher.finalizeData(count: 8)
    }
}
