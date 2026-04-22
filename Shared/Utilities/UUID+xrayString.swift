//
//  UUID+xrayString.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/22/26.
//

import CryptoKit
import Foundation

extension UUID {
    /// Parses a UUID the way Xray-core does (common/uuid/uuid.go ParseString):
    /// length 32–36 is hex-decoded; length 1–30 is derived as
    /// `SHA1(zero_uuid || input)[0..<16]` with RFC 4122 v5 + variant bits stamped.
    init?(xrayString str: String) {
        let len = str.utf8.count

        if len >= 32, len <= 36 {
            if let u = UUID(uuidString: str) {
                self = u
                return
            }
            if len == 32, let data = Data(hexString: str), data.count == 16 {
                self = UUID.from(bytes: data)
                return
            }
            return nil
        }

        guard len >= 1, len <= 30 else { return nil }

        var hasher = Insecure.SHA1()
        hasher.update(data: Data(count: 16))
        hasher.update(data: Data(str.utf8))
        var bytes = Array(hasher.finalize().prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | (5 << 4)
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        self = UUID.from(bytes: Data(bytes))
    }

    private static func from(bytes: Data) -> UUID {
        bytes.withUnsafeBytes { raw in
            let p = raw.bindMemory(to: UInt8.self).baseAddress!
            return UUID(uuid: (p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                               p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]))
        }
    }
}
