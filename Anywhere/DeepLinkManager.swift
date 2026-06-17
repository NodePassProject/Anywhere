//
//  DeepLinkManager.swift
//  Anywhere
//
//  Created by NodePassProject on 4/24/26.
//

import Foundation
import Observation

@MainActor
@Observable
final class DeepLinkManager {
    var url: String?
    var ruleSetLinks: [URL]?

    func handle(url: URL) {
        switch url.scheme?.lowercased() {
        case "anywhere":
            handleAnywhereScheme(url)
        case "vless", "hysteria2", "hy2", "nowhere", "trojan", "anytls", "ss", "quic", "sudoku":
            self.url = url.absoluteString
        default:
            break
        }
    }

    private func handleAnywhereScheme(_ url: URL) {
        switch url.host?.lowercased() {
        case "add-proxy":
            handleAddProxy(url)
        case "add-rule-set":
            handleAddRuleSet(url)
        default:
            break
        }
    }

    private func handleAddProxy(_ url: URL) {
        // Take everything after "?link=" verbatim so the inner proxy/subscription
        // URL — which may itself carry "?", "&", "=" — survives unescaped.
        let string = url.absoluteString
        guard let range = string.range(of: "?link=") else { return }
        let rawLink = String(string[range.upperBound...])
        guard !rawLink.isEmpty else { return }
        self.url = rawLink.removingPercentEncoding ?? rawLink
    }
    
    private func handleAddRuleSet(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else { return }
        let links: [URL] = queryItems
            .filter { $0.name.lowercased() == "link" }
            .compactMap { $0.value?.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
            .compactMap { URL(string: $0) }
        guard !links.isEmpty else { return }
        self.ruleSetLinks = links
    }
}
