//
//  DeepLinkManager.swift
//  Anywhere
//
//  Created by NodePassProject on 4/24/26.
//

import Foundation
import Combine

final class DeepLinkManager: ObservableObject {
    @Published var url: String?
    var host: String?

    // Supported deep link schemes:
    // anywhere://add-proxy?link=<link>
    // anywhere://add-proxy?host=<host>&link=<link>
    // vless://<...>
    // ss://<...>
    // sudoku://<...>
    func handle(url: URL) {
        switch url.scheme?.lowercased() {
        case "anywhere":
            handleAnywhereScheme(url)
        case "vless", "hysteria2", "hy2", "nowhere", "trojan", "anytls", "ss", "quic", "sudoku":
            self.host = nil
            self.url = url.absoluteString
        default:
            break
        }
    }

    private func handleAnywhereScheme(_ url: URL) {
        guard url.host == "add-proxy", let parsed = AnywhereProxyLink.parse(url.absoluteString) else { return }
        self.host = parsed.host
        self.url = parsed.link
    }
}
