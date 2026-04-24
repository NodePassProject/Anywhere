//
//  DeepLinkManager.swift
//  Anywhere
//
//  Created by Argsment Limited on 4/24/26.
//

import Foundation
import Combine

final class DeepLinkManager: ObservableObject {
    @Published var url: String?

    // Supported deep link schemes:
    // anywhere://add-proxy?link=<link>
    // vless://<...>
    // ss://<...>
    func handle(url: URL) {
        switch url.scheme?.lowercased() {
        case "anywhere":
            handleAnywhereScheme(url)
        case "vless", "hysteria2", "hy2", "trojan", "ss", "quic":
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
        self.url = rawLink.removingPercentEncoding
    }
}
