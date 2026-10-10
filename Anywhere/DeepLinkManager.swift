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
    var ruleSetLink: URL?
    var moduleLink: URL?

    func handle(url: URL) {
        switch url.scheme?.lowercased() {
        case "anywhere":
            handleAnywhereScheme(url)
        case "nowhere", "vless", "hysteria2", "hy2", "sudoku", "trojan", "anytls", "ss", "rfc":
            self.url = url.absoluteString
        default:
            break
        }
    }

    private func handleAnywhereScheme(_ url: URL) {
        guard let link = Self.extractLink(from: url.absoluteString) else { return }
        switch url.host?.lowercased() {
        case "add-proxy":
            self.url = link
        case "add-rule-set":
            ruleSetLink = URL(string: link)
        case "add-module":
            moduleLink = URL(string: link)
        default:
            break
        }
    }

    nonisolated static func extractAddProxyLink(from string: String) -> String? {
        guard string.lowercased().hasPrefix("anywhere://add-proxy") else { return nil }
        return extractLink(from: string)
    }

    /// Every `anywhere://` deep link carries exactly one link: everything after
    /// `?link=`, taken verbatim, so the inner URL needs no percent-encoding.
    private nonisolated static func extractLink(from string: String) -> String? {
        guard let range = string.range(of: "?link=") else { return nil }
        let rawLink = String(string[range.upperBound...])
        guard !rawLink.isEmpty else { return nil }
        return rawLink.removingPercentEncoding ?? rawLink
    }
}
