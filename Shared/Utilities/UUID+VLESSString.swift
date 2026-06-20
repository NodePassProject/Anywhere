//
//  UUID+VLESSString.swift
//  Anywhere
//
//  Created by NodePassProject on 4/22/26.
//

import CryptoKit
import Foundation

extension UUID {
    /// Parses a UUID using the VLESS user-ID convention:
    /// length 32–36 is hex-decoded; length 1–30 is derived as
    /// `SHA1(zero_uuid || input)[0..<16]` with RFC 4122 v5 + variant bits stamped.
    init?(vlessString: String) {
        let length = vlessString.utf8.count

        if length >= 32, length <= 36 {
            if let parsed = UUID(uuidString: vlessString) {
                self = parsed
                return
            }
            if length == 32, let data = Data(hexString: vlessString), data.count == 16 {
                self = UUID.from(bytes: data)
                return
            }
            return nil
        }

        guard length >= 1, length <= 30 else { return nil }

        var hasher = Insecure.SHA1()
        hasher.update(data: Data(count: 16))
        hasher.update(data: Data(vlessString.utf8))
        var bytes = Array(hasher.finalize().prefix(16))
        bytes[6] = (bytes[6] & 0x0f) | (5 << 4)
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        self = UUID.from(bytes: Data(bytes))
    }

    private static func from(bytes: Data) -> UUID {
        bytes.withUnsafeBytes { raw in
            let bytePointer = raw.bindMemory(to: UInt8.self).baseAddress!
            return UUID(uuid: (bytePointer[0], bytePointer[1], bytePointer[2], bytePointer[3], bytePointer[4], bytePointer[5], bytePointer[6], bytePointer[7],
                               bytePointer[8], bytePointer[9], bytePointer[10], bytePointer[11], bytePointer[12], bytePointer[13], bytePointer[14], bytePointer[15]))
        }
    }
}
