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
        guard url.host == "add-proxy" else { return }
        // Take everything after "?link="
        let string = url.absoluteString
        guard let range = string.range(of: "?link=") else { return }
        let rawLink = String(string[range.upperBound...])
        guard !rawLink.isEmpty else { return }
        self.url = rawLink.removingPercentEncoding ?? rawLink
    }
}
