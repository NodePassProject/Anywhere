//
//  ProxyUserAgent.swift
//  Anywhere
//

import Foundation

/// Shared Chrome User-Agent string matching Xray-core's `utils.ChromeUA`.
/// Uses a fixed base version (Chrome 144, released 2026-01-13) and advances
/// by one version every ~35 days (midpoint of Xray-core's 25-45 day range).
enum ProxyUserAgent {
    static let chrome: String = {
        let baseVersion = 144
        let baseDate = DateComponents(calendar: Calendar(identifier: .gregorian),
                                      timeZone: TimeZone(identifier: "UTC"),
                                      year: 2026, month: 1, day: 13).date!
        let daysSinceBase = max(0, Int(Date().timeIntervalSince(baseDate) / 86400))
        let version = baseVersion + daysSinceBase / 35
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/\(version).0.0.0 Safari/537.36"
    }()
}
