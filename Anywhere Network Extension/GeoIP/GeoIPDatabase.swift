//
//  GeoIPDatabase.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/1/26.
//

import Foundation
import os.log

private let logger = Logger(subsystem: "com.argsment.Anywhere.Network-Extension", category: "GeoIP")

struct GeoIPDatabase {
    private let data: Data
    private let entryCount: Int
    private static let headerSize = 8
    private static let entrySize = 10  // 4 + 4 + 2

    init?(bundleResource: String = "geoip") {
        guard let url = Bundle.main.url(forResource: bundleResource, withExtension: "dat"),
              let data = try? Data(contentsOf: url) else {
            logger.error("[GeoIP] Failed to load \(bundleResource).dat from bundle")
            return nil
        }
        guard data.count >= Self.headerSize else {
            logger.error("[GeoIP] File too small: \(data.count) bytes")
            return nil
        }
        // Verify magic "GEO1"
        guard data[0] == 0x47, data[1] == 0x45, data[2] == 0x4F, data[3] == 0x31 else {
            logger.error("[GeoIP] Invalid magic header")
            return nil
        }
        let count = Int(data[4]) << 24 | Int(data[5]) << 16 | Int(data[6]) << 8 | Int(data[7])
        guard data.count >= Self.headerSize + count * Self.entrySize else {
            logger.error("[GeoIP] File truncated: expected \(Self.headerSize + count * Self.entrySize) bytes, got \(data.count)")
            return nil
        }
        self.data = data
        self.entryCount = count
        logger.info("[GeoIP] Loaded \(count) entries")
    }

    /// Looks up the country for an IPv4 address string.
    /// Returns the packed UInt16 country code (e.g. 0x434E for "CN"), or 0 if not found.
    func lookup(_ ipString: String) -> UInt16 {
        return data.withUnsafeBytes { ptr -> UInt16 in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return ipString.withCString { cStr in
                geoip_lookup(base, data.count, cStr)
            }
        }
    }

    /// Packs a 2-letter country code string into UInt16: (c1 << 8) | c2.
    /// Returns 0 for invalid codes.
    static func packCountryCode(_ code: String) -> UInt16 {
        let utf8 = Array(code.utf8)
        guard utf8.count == 2 else { return 0 }
        return UInt16(utf8[0]) << 8 | UInt16(utf8[1])
    }
}
