import Foundation

private let logger = TunnelLogger(category: "GeoIP")

struct GeoIPDatabase {
    private let data: Data
    private let entryCount: Int
    private static let headerSize = 8
    private static let entrySize = 10  // 4 + 4 + 2

    init?(bundleResource: String = "geoip") {
        guard let url = Bundle.main.url(forResource: bundleResource, withExtension: "dat"),
              let data = try? Data(contentsOf: url) else {
            logger.error("[VPN] GeoIP database failed to load")
            return nil
        }
        guard data.count >= Self.headerSize else {
            logger.error("[VPN] GeoIP database corrupt")
            return nil
        }
        // Verify magic "GEO1"
        guard data[0] == 0x47, data[1] == 0x45, data[2] == 0x4F, data[3] == 0x31 else {
            logger.error("[VPN] GeoIP database corrupt")
            return nil
        }
        let count = Int(data[4]) << 24 | Int(data[5]) << 16 | Int(data[6]) << 8 | Int(data[7])
        guard data.count >= Self.headerSize + count * Self.entrySize else {
            logger.error("[VPN] GeoIP database corrupt")
            return nil
        }
        self.data = data
        self.entryCount = count
        logger.debug("[GeoIP] Loaded \(count) entries")
    }

    /// Looks up the country for an IPv4 address string.
    /// Returns the packed UInt16 country code (e.g. 0x434E for "CN"), or 0 if not found.
    func lookup(_ ipString: String) -> UInt16 {
        // Parse IPv4 string to host-order UInt32
        let parts = ipString.split(separator: ".", maxSplits: 4, omittingEmptySubsequences: false)
        guard parts.count == 4 else { return 0 }

        var ip: UInt32 = 0
        for part in parts {
            guard let byte = UInt8(part) else { return 0 }
            ip = ip << 8 | UInt32(byte)
        }

        // Binary search: find largest startIP <= ip
        return data.withUnsafeBytes { ptr -> UInt16 in
            guard let base = ptr.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            let entries = base + Self.headerSize

            var lo = 0, hi = entryCount - 1, best = -1
            while lo <= hi {
                let mid = lo + (hi - lo) / 2
                let e = entries + mid * Self.entrySize
                let startIP = UInt32(e[0]) << 24 | UInt32(e[1]) << 16 | UInt32(e[2]) << 8 | UInt32(e[3])
                if startIP <= ip {
                    best = mid
                    lo = mid + 1
                } else {
                    hi = mid - 1
                }
            }

            guard best >= 0 else { return 0 }

            let e = entries + best * Self.entrySize
            let endIP = UInt32(e[4]) << 24 | UInt32(e[5]) << 16 | UInt32(e[6]) << 8 | UInt32(e[7])
            guard ip <= endIP else { return 0 }

            return UInt16(e[8]) << 8 | UInt16(e[9])
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
