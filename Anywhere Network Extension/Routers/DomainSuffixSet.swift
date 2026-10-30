//
//  DomainSuffixSet.swift
//  Anywhere
//
//  Created by NodePassProject on 10/30/26.
//

import Foundation

nonisolated struct DomainSuffixSet: Sendable {
    private let suffixes: Set<String>

    init(_ suffixes: [String]) {
        self.suffixes = Set(suffixes.compactMap(DNSName.normalizedDomainSuffix))
    }

    var isEmpty: Bool { suffixes.isEmpty }

    func contains(_ domain: String) -> Bool {
        guard !suffixes.isEmpty else { return false }
        var candidate = Substring(domain)
        while true {
            if suffixes.contains(String(candidate)) { return true }
            guard let dot = candidate.firstIndex(of: ".") else { return false }
            candidate = candidate[candidate.index(after: dot)...]
        }
    }
}
