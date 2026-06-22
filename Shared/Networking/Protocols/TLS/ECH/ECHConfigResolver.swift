//
//  ECHConfigResolver.swift
//  Anywhere
//
//  Created by NodePassProject on 6/14/26.
//

import Foundation

enum ECHConfigResolver {

    /// ECHConfigList bytes the handshake seals against, or nil when no usable spec is configured.
    static func resolveImmediate(_ spec: String?) -> Data? {
        guard let spec = spec?.trimmingCharacters(in: .whitespacesAndNewlines), !spec.isEmpty else { return nil }
        return decodeBase64(spec)
    }

    /// Decode a base64 ECHConfigList, tolerating URL-safe alphabets and missing
    /// padding (configs are often pasted from URLs/QR codes).
    static func decodeBase64(_ string: String) -> Data? {
        var normalized = string.trimmingCharacters(in: .whitespacesAndNewlines)
        normalized = normalized.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder != 0 { normalized += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: normalized)
    }
}
