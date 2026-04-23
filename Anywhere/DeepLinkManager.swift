//
//  DeepLinkManager.swift
//  Anywhere
//

import Foundation
import Combine

enum DeepLinkAction: Equatable {
    case addProxyWithLink(url: String)
    case addProxyManual(url: String)
}

final class DeepLinkManager: ObservableObject {
    @Published var pendingAction: DeepLinkAction?

    // Supported deep link schemes:
    // anywhere://add-proxy?link=<link>
    // vless://<...>
    // ss://<...>
    // sudoku://<...>
    func handle(url: URL) {
        switch url.scheme?.lowercased() {
        case "anywhere":
            handleAnywhereScheme(url)
        case "vless", "ss", "sudoku":
            pendingAction = .addProxyManual(url: url.absoluteString)
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
        pendingAction = .addProxyWithLink(url: rawLink.removingPercentEncoding ?? rawLink)
    }
}
