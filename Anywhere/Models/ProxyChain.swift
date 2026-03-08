//
//  ProxyChain.swift
//  Anywhere
//
//  Created by Argsment Limited on 3/8/26.
//

import Foundation

/// A named, ordered sequence of proxy configurations forming a chain.
///
/// When selected as the working configuration:
/// - The **last** proxy in `proxyIds` is the exit proxy (talks to the target).
/// - All preceding proxies form the intermediate chain (tunneled through in order).
struct ProxyChain: Identifiable, Codable, Hashable {
    let id: UUID
    var name: String
    /// Ordered proxy IDs. First is the entry (outermost TCP), last is the exit.
    var proxyIds: [UUID]

    init(id: UUID = UUID(), name: String, proxyIds: [UUID] = []) {
        self.id = id
        self.name = name
        self.proxyIds = proxyIds
    }
}
