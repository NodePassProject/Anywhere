//
//  AnywhereProxyLink.swift
//  Anywhere
//
//  Created by NodePassProject on 6/5/26.
//

import Foundation

struct AnywhereProxyLink {
    let link: String
    let host: String?

    static func parse(_ string: String) -> AnywhereProxyLink? {
        let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("anywhere://add-proxy") else { return nil }

        if let hostRange = trimmed.range(of: "?host="),
           let linkRange = trimmed.range(of: "&link=") {
            let rawHost = String(trimmed[hostRange.upperBound..<linkRange.lowerBound])
            let rawLink = String(trimmed[linkRange.upperBound...])
            guard !rawLink.isEmpty else { return nil }
            let decodedHost = rawHost.removingPercentEncoding ?? rawHost
            return AnywhereProxyLink(
                link: resolveLink(rawLink.removingPercentEncoding ?? rawLink),
                host: decodedHost.isEmpty ? nil : decodedHost
            )
        }

        guard let linkRange = trimmed.range(of: "?link=") else { return nil }
        let rawLink = String(trimmed[linkRange.upperBound...])
        guard !rawLink.isEmpty else { return nil }
        return AnywhereProxyLink(
            link: resolveLink(rawLink.removingPercentEncoding ?? rawLink),
            host: nil
        )
    }

    // MARK: - Base64 link resolution

    private static func resolveLink(_ link: String) -> String {
        guard let data = Data(base64Encoded: link, options: .ignoreUnknownCharacters),
              let decoded = String(data: data, encoding: .utf8) else {
            return link
        }
        let trimmed = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("http://") || ProxyConfiguration.parsableURLPrefixes.contains(where: { trimmed.hasPrefix($0) }) {
            return trimmed
        }
        return link
    }
}
