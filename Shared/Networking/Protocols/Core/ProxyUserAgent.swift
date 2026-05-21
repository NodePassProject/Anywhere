//
//  ProxyUserAgent.swift
//  Anywhere
//

import Foundation

enum ProxyUserAgent {
    static let `default`: String = chrome
    
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
